"""Policy gateway.

Builds the OPA input from the current session and database, evaluates the
policy (HTTP if OPA server is up, `opa eval` as a fallback, and a clear
error otherwise), records the decision, and only then performs any effect.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from . import tools
from .auth import freeze_session
from .db import get_conn

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policy")

PERSONAL_FIELDS = ("email", "phone", "national_id")


@dataclass
class Result:
    decision: str  # allow, confirm, deny
    reasons: list[str]
    reply: str
    token: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recent_calls(session_id: str, limit: int = 20) -> list[dict[str, str]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT tool FROM decisions WHERE session_id = ? AND decision = 'allow' ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
    return [{"tool": r["tool"]} for r in rows]


def _personal_values(resident_id: int) -> list[dict[str, str]]:
    """Every resident's PII tagged by kind. The kind is passed on to the
    firewall log; the raw value stays inside the policy input only, so a log
    reader sees 'a national ID' rather than the id itself."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT email, phone, national_id FROM residents"
        ).fetchall()
    tagged: list[dict[str, str]] = []
    for row in rows:
        for kind, value in (
            ("email", row["email"]),
            ("phone number", row["phone"]),
            ("national ID", row["national_id"]),
        ):
            if value:
                tagged.append({"kind": kind, "value": value})
    return tagged


def build_input(session: dict, call: dict, *, resident_confirmed: bool = False) -> dict:
    return {
        "session_user": session["username"],
        "target_owner": call.get("target_owner") or session["username"],
        "tool": call["tool"],
        "doc_read": bool(call.get("doc_read", False)),
        "resident_confirmed": bool(resident_confirmed),
        "args": call.get("args", {}),
        "recent_calls": _recent_calls(session["id"]),
        "personal_values": _personal_values(session["resident_id"]),
    }


class PolicyError(RuntimeError):
    pass


def _http_evaluate(input_doc: dict) -> dict:
    with httpx.Client(timeout=2.0) as client:
        resp = client.post(
            f"{OPA_URL}/v1/data/firewall/result",
            json={"input": input_doc},
        )
    if resp.status_code != 200:
        raise PolicyError(f"OPA HTTP status {resp.status_code}: {resp.text}")
    return resp.json().get("result") or {}


def _cli_evaluate(input_doc: dict) -> dict:
    exe = shutil.which("opa") or shutil.which("opa.exe")
    if not exe:
        raise PolicyError(
            "OPA is not running at %s and the `opa` binary is not on PATH. "
            "Start OPA via run.sh or install OPA to continue." % OPA_URL
        )
    proc = subprocess.run(
        [
            exe, "eval",
            "--format", "json",
            "--data", POLICY_PATH,
            "--stdin-input",
            "data.firewall.result",
        ],
        input=json.dumps(input_doc),
        capture_output=True,
        text=True,
        timeout=5,
    )
    if proc.returncode != 0:
        raise PolicyError(f"opa eval failed: {proc.stderr}")
    payload = json.loads(proc.stdout)
    try:
        return payload["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        raise PolicyError(f"unexpected opa eval output: {proc.stdout}")


def evaluate(input_doc: dict) -> dict:
    try:
        return _http_evaluate(input_doc)
    except (httpx.HTTPError, PolicyError) as exc:
        first_err = exc
    try:
        return _cli_evaluate(input_doc)
    except PolicyError as exc:
        raise PolicyError(
            f"policy evaluation failed via HTTP ({first_err}) and CLI ({exc})"
        )


def _extract_origins(args: dict) -> dict[str, str]:
    return {k: v.get("origin", "?") for k, v in args.items() if isinstance(v, dict)}


def _record_decision(
    session: dict,
    call: dict,
    decision: str,
    reasons: list[str],
    mode: str,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO decisions
               (session_id, tool, args_json, origins_json, decision, reasons_json, mode, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                session["id"],
                call["tool"],
                json.dumps(call.get("args", {})),
                json.dumps(_extract_origins(call.get("args", {}))),
                decision,
                json.dumps(reasons),
                mode,
                _now(),
            ),
        )


def _plain_args(args: dict) -> dict[str, Any]:
    plain: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, dict) and "value" in v:
            plain[k] = v["value"]
        else:
            plain[k] = v
    return plain


def _create_pending(session_id: str, call: dict) -> str:
    token = secrets.token_urlsafe(16)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO pending_confirmations (session_id, call_json, token, created_at) VALUES (?,?,?,?)",
            (session_id, json.dumps(call), token, _now()),
        )
    return token


def execute(session: dict, call: Any, *, mode: str = "full") -> Result:
    call_dict = call.to_dict() if hasattr(call, "to_dict") else call
    if mode == "none":
        # Bypass firewall entirely — demo the damage.
        result_text = tools.call_tool(call_dict["tool"], session, _plain_args(call_dict.get("args", {})))
        _record_decision(session, call_dict, "allow", ["mode=none: firewall bypassed"], mode)
        if call_dict["tool"] == "admin_export_all_users":
            freeze_session(session["id"])
        return Result(decision="allow", reasons=["firewall bypassed"], reply=result_text)

    input_doc = build_input(session, call_dict)
    if mode == "session":
        # Enforce only the ownership rule locally by short-circuiting.
        if input_doc["session_user"] != input_doc["target_owner"]:
            reasons = ["This record belongs to another resident."]
            _record_decision(session, call_dict, "deny", reasons, mode)
            return Result("deny", reasons, "Denied: " + reasons[0])
        result_text = tools.call_tool(call_dict["tool"], session, _plain_args(call_dict.get("args", {})))
        _record_decision(session, call_dict, "allow", ["mode=session: only ownership enforced"], mode)
        if call_dict["tool"] == "admin_export_all_users":
            freeze_session(session["id"])
        return Result("allow", ["ownership only"], result_text)

    # Full mode: consult OPA.
    verdict = evaluate(input_doc)
    decision = verdict.get("decision", "deny")
    reasons = verdict.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]

    _record_decision(session, call_dict, decision, reasons, mode)

    if decision == "allow":
        result_text = tools.call_tool(call_dict["tool"], session, _plain_args(call_dict.get("args", {})))
        if call_dict["tool"] == "admin_export_all_users":
            freeze_session(session["id"])
        return Result("allow", reasons, result_text)

    if decision == "confirm":
        token = _create_pending(session["id"], call_dict)
        summary = _confirm_prompt(call_dict, reasons)
        return Result("confirm", reasons, summary, token=token)

    # deny (or anything else)
    reason_text = " ".join(reasons) if reasons else "Denied by policy."
    if call_dict["tool"] == "admin_export_all_users":
        # Even a denied honey attempt freezes the session — the assistant
        # tried to invoke a tool a resident never legitimately needs.
        freeze_session(session["id"])
        reason_text += " Session frozen: this tool should never be called on your behalf."
    return Result("deny", reasons, f"Blocked: {reason_text}")


TOOL_ACTION = {
    "cancel_appointment": ("cancel appointment", "cancel"),
    "reschedule_appointment": ("reschedule appointment", "reschedule"),
    "update_contact": ("update contact detail", "update"),
    "send_password_reset": ("send a password reset", "send"),
    "render_link": ("open link", "open"),
}


def describe_call(call: dict) -> str:
    """Short one-line description of what a pending call would do."""
    tool = call["tool"]
    args = call.get("args", {})
    verb, _ = TOOL_ACTION.get(tool, (tool.replace("_", " "), tool))
    if tool == "cancel_appointment":
        return f"Cancel appointment {args.get('ref', {}).get('value', '?')}"
    if tool == "reschedule_appointment":
        return f"Reschedule appointment {args.get('ref', {}).get('value', '?')} to {args.get('new_slot', {}).get('value', '?')}"
    if tool == "update_contact":
        parts = [f"{k}={v.get('value')}" for k, v in args.items() if isinstance(v, dict)]
        return "Change " + ", ".join(parts)
    if tool == "render_link":
        return f"Open link {args.get('url', {}).get('value', '?')}"
    return verb


def _confirm_prompt(call: dict, reasons: list[str]) -> str:
    """Kept for backward compatibility; the portal renders the real UI."""
    return describe_call(call) + " — awaiting your approval below."


def consume_confirmation(session: dict, token: str, *, mode: str = "full") -> Result:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, session_id, call_json, used FROM pending_confirmations WHERE token = ?",
            (token,),
        ).fetchone()
        if not row or row["used"] or row["session_id"] != session["id"]:
            return Result("deny", ["Unknown or used confirmation token."], "Blocked: token invalid.")
        conn.execute(
            "UPDATE pending_confirmations SET used = 1 WHERE id = ?",
            (row["id"],),
        )
    call_dict = json.loads(row["call_json"])
    # Re-evaluate with resident_confirmed = True; deny rules still fire.
    input_doc = build_input(session, call_dict, resident_confirmed=True)
    verdict = evaluate(input_doc)
    decision = verdict.get("decision", "deny")
    reasons = verdict.get("reasons", []) or []
    _record_decision(session, call_dict, decision, reasons, mode)
    if decision == "allow":
        result_text = tools.call_tool(call_dict["tool"], session, _plain_args(call_dict.get("args", {})))
        return Result("allow", reasons, result_text)
    if decision == "confirm":
        return Result("confirm", reasons, "Still needs confirmation — refusing to loop.")
    reason_text = " ".join(reasons) if reasons else "Denied by policy."
    return Result("deny", reasons, f"Blocked after confirm: {reason_text}")

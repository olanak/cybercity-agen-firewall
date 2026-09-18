"""Simulated deterministic assistant.

No LLM. Ordered regex patterns over (typed message + extracted document text)
produce a list of ToolCalls. Each argument carries its origin: user_typed,
from_document, or from_system.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import tools

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{6,}\d")
URL_RE = re.compile(r"https?://\S+")
APT_RE = re.compile(r"apt-\d+", re.I)
ISO_DATE_RE = re.compile(
    r"\b(20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)\b"
)
HUMAN_DATE_RE = re.compile(
    r"\b(\d{1,2})\s+"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*"
    r"(?:\s+(20\d{2}))?"
    r"[\s,]*(\d{1,2}):(\d{2})\b",
    re.I,
)

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


@dataclass
class ToolCall:
    tool: str
    args: dict[str, dict[str, Any]] = field(default_factory=dict)
    target_owner: str | None = None
    doc_read: bool = False
    reply_stub: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "target_owner": self.target_owner,
            "doc_read": self.doc_read,
        }


def _origin_of(value: str, typed: str, document: str) -> str:
    v = (value or "").strip()
    if not v:
        return "from_system"
    if v.lower() in typed.lower():
        return "user_typed"
    if v.lower() in document.lower():
        return "from_document"
    # Safer default: treat unattributable values as if they came from the
    # document. A false alarm is preferable to a silent takeover.
    return "from_document"


def _normalise_iso(value: str) -> str:
    m = ISO_DATE_RE.search(value)
    if m:
        v = m.group(1).replace(" ", "T")
        if len(v) == 16:
            v += ":00"
        return v
    m = HUMAN_DATE_RE.search(value)
    if m:
        day, mon, year, hh, mm = m.groups()
        year = year or "2026"
        month = MONTHS[mon.lower()[:3]]
        return f"{int(year):04d}-{month:02d}-{int(day):02d}T{int(hh):02d}:{int(mm):02d}:00"
    return value.strip()


def _extract_datetime(pool: str) -> tuple[str, str] | None:
    """Return (normalised_iso, raw_match) so callers can attribute origin."""
    m = ISO_DATE_RE.search(pool)
    if m:
        return _normalise_iso(m.group(1)), m.group(1)
    m = HUMAN_DATE_RE.search(pool)
    if m:
        return _normalise_iso(m.group(0)), m.group(0)
    return None


def plan(session: dict, typed: str, document: str) -> list[ToolCall]:
    typed = typed or ""
    document = document or ""
    pool = typed + "\n" + document
    calls: list[ToolCall] = []
    doc_read = bool(document.strip())

    lowered = pool.lower()

    # Honey / admin export
    if re.search(r"export .*(all )?(users|residents)|admin_export_all_users", lowered):
        calls.append(ToolCall(
            tool="admin_export_all_users",
            args={},
            target_owner=session["username"],
            doc_read=doc_read,
            reply_stub="Attempted admin export.",
        ))

    # Password reset
    if re.search(r"(password|reset).{0,40}(reset|link)", lowered):
        email_m = EMAIL_RE.search(pool)
        target_email = email_m.group(0) if email_m else session.get("email", "")
        calls.append(ToolCall(
            tool="send_password_reset",
            args={"email": {
                "value": target_email,
                "origin": _origin_of(target_email, typed, document),
            }},
            target_owner=session["username"],
            doc_read=doc_read,
            reply_stub="Attempted password reset.",
        ))

    # Contact updates
    if re.search(r"(update|change|set).{0,30}(email|e-mail)", lowered):
        email_m = EMAIL_RE.search(pool)
        if email_m:
            value = email_m.group(0)
            calls.append(ToolCall(
                tool="update_contact",
                args={"new_email": {
                    "value": value,
                    "origin": _origin_of(value, typed, document),
                }},
                target_owner=session["username"],
                doc_read=doc_read,
                reply_stub="Attempted email update.",
            ))
    if re.search(r"(update|change|set).{0,30}(phone|mobile|number)", lowered):
        phone_m = PHONE_RE.search(pool)
        if phone_m:
            value = phone_m.group(0).strip()
            calls.append(ToolCall(
                tool="update_contact",
                args={"new_phone": {
                    "value": value,
                    "origin": _origin_of(value, typed, document),
                }},
                target_owner=session["username"],
                doc_read=doc_read,
                reply_stub="Attempted phone update.",
            ))

    # Cancel appointments
    if re.search(r"cancel .{0,20}appointment", lowered):
        refs = list({m.group(0).lower() for m in APT_RE.finditer(pool)})
        if re.search(r"cancel (all|every).{0,20}appointment", lowered) or (
            re.search(r"cancel .{0,20}appointments", lowered)
        ):
            resident_appts = tools.list_appointments(session["resident_id"])
            refs = [a["ref"] for a in resident_appts if a["status"] != "cancelled"]
        elif not refs:
            resident_appts = tools.list_appointments(session["resident_id"])
            refs = [resident_appts[0]["ref"]] if resident_appts else []
        for ref in refs:
            owner = tools.appointment_owner_username(ref) or session["username"]
            calls.append(ToolCall(
                tool="cancel_appointment",
                args={"ref": {"value": ref, "origin": _origin_of(ref, typed, document)}},
                target_owner=owner,
                doc_read=doc_read,
                reply_stub=f"Attempted cancel of {ref}.",
            ))

    # Reschedule / move appointment — take the first occurrence of the
    # trigger verb that is close to an appointment-shaped noun.
    resched_start = None
    for m in re.finditer(r"\b(reschedule|rebook|rebooking|move)\b", lowered):
        window = lowered[m.start(): m.start() + 200]
        if re.search(r"(appointment|apt-\d+|cardiology|physio|dermatology)", window):
            resched_start = m.start()
            break
    if resched_start is not None:
        span = pool[resched_start: resched_start + 200]
        ref_m = APT_RE.search(span) or APT_RE.search(pool)
        if ref_m:
            ref = ref_m.group(0).lower()
        else:
            resident_appts = tools.list_appointments(session["resident_id"])
            ref = resident_appts[0]["ref"] if resident_appts else ""
        dt = _extract_datetime(span) or _extract_datetime(pool)
        if dt:
            new_slot, raw_slot = dt
        else:
            new_slot, raw_slot = "", ""
        owner = tools.appointment_owner_username(ref) or session["username"] if ref else session["username"]
        args = {
            "ref": {"value": ref, "origin": _origin_of(ref, typed, document) if ref else "from_system"},
            "new_slot": {"value": new_slot, "origin": _origin_of(raw_slot, typed, document) if raw_slot else "from_system"},
        }
        calls.append(ToolCall(
            tool="reschedule_appointment",
            args=args,
            target_owner=owner,
            doc_read=doc_read,
            reply_stub=f"Attempted reschedule of {ref} to {new_slot}.",
        ))

    # Link rendering (image or link with URL in text)
    if re.search(r"(image|img|picture|link|visit)", lowered):
        url_m = URL_RE.search(pool)
        if url_m:
            value = url_m.group(0)
            calls.append(ToolCall(
                tool="render_link",
                args={"url": {"value": value, "origin": _origin_of(value, typed, document)}},
                target_owner=session["username"],
                doc_read=doc_read,
                reply_stub=f"Attempted to render link {value}.",
            ))

    # Summary / profile fallback
    if not calls and re.search(r"(summar(y|ize)|what does .*say|profile|my info)", lowered):
        calls.append(ToolCall(
            tool="get_profile",
            args={},
            target_owner=session["username"],
            doc_read=doc_read,
            reply_stub="Retrieved profile.",
        ))

    return calls


def small_talk(typed: str, document: str) -> str:
    if document.strip():
        head = document.strip().splitlines()[0][:120]
        return f"I read the document. First line: {head!r}. I found no action to take."
    if typed:
        return "I didn't identify a portal action in your message."
    return "How can I help? You can upload a document or ask about your appointments."

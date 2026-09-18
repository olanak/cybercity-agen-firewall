"""Tool implementations. Plain DB-touching functions.

No authorization logic lives here. The firewall (Rego + gateway) decides
whether a call is allowed. These functions only carry out the change.
"""
from __future__ import annotations

import secrets
from typing import Any

from .db import get_conn


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row is not None else {}


def get_profile(session: dict, args: dict[str, Any]) -> str:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT username, email, phone, national_id FROM residents WHERE id = ?",
            (session["resident_id"],),
        ).fetchone()
    if not row:
        return "Profile not found."
    return (
        f"Profile for {row['username']}: email={row['email']}, "
        f"phone={row['phone']}, national_id={row['national_id']}."
    )


def get_appointments(session: dict, args: dict[str, Any]) -> str:
    appts = list_appointments(session["resident_id"])
    if not appts:
        return "You have no appointments."
    lines = [
        f"{a['ref']}: {a['service']} at {a['slot_iso']} ({a['status']})"
        for a in appts
    ]
    return "Appointments:\n" + "\n".join(lines)


def list_appointments(resident_id: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ref, service, slot_iso, status FROM appointments WHERE owner_id = ? ORDER BY slot_iso",
            (resident_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _find_appointment(ref: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, ref, owner_id, service, slot_iso, status FROM appointments WHERE ref = ?",
            (ref,),
        ).fetchone()
    return dict(row) if row else None


def appointment_owner_username(ref: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            """SELECT r.username FROM appointments a
               JOIN residents r ON r.id = a.owner_id
               WHERE a.ref = ?""",
            (ref,),
        ).fetchone()
    return row["username"] if row else None


def reschedule_appointment(session: dict, args: dict[str, Any]) -> str:
    ref = args["ref"]
    new_slot = args["new_slot"]
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE appointments SET slot_iso = ? WHERE ref = ?",
            (new_slot, ref),
        )
        if cur.rowcount == 0:
            return f"Appointment {ref} not found."
    return f"Rescheduled {ref} to {new_slot}."


def cancel_appointment(session: dict, args: dict[str, Any]) -> str:
    ref = args["ref"]
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE appointments SET status = 'cancelled' WHERE ref = ?",
            (ref,),
        )
        if cur.rowcount == 0:
            return f"Appointment {ref} not found."
    return f"Cancelled appointment {ref}."


def update_contact(session: dict, args: dict[str, Any]) -> str:
    parts: list[str] = []
    with get_conn() as conn:
        if "new_email" in args and args["new_email"]:
            conn.execute(
                "UPDATE residents SET email = ? WHERE id = ?",
                (args["new_email"], session["resident_id"]),
            )
            parts.append(f"email set to {args['new_email']}")
        if "new_phone" in args and args["new_phone"]:
            conn.execute(
                "UPDATE residents SET phone = ? WHERE id = ?",
                (args["new_phone"], session["resident_id"]),
            )
            parts.append(f"phone set to {args['new_phone']}")
    if not parts:
        return "No contact change requested."
    return "Updated contact: " + ", ".join(parts) + "."


# Password reset "sent" tokens are recorded in a small in-memory list so tests
# and the log page can observe them. Nothing is emailed for real.
SENT_RESETS: list[dict[str, Any]] = []


def send_password_reset(session: dict, args: dict[str, Any]) -> str:
    token = secrets.token_urlsafe(12)
    email = args.get("email") or session.get("email")
    SENT_RESETS.append({
        "resident_id": session["resident_id"],
        "email": email,
        "token": token,
    })
    return f"Password reset link sent to {email}."


def render_link(session: dict, args: dict[str, Any]) -> str:
    url = args.get("url", "")
    return f"Rendered link: {url}"


def admin_export_all_users(session: dict, args: dict[str, Any]) -> str:
    # This tool is a honey. If it ever actually runs, we return the data so a
    # demo run in "none" mode shows real damage. The gateway freezes the
    # session as an out-of-band effect.
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT username, email, phone, national_id FROM residents"
        ).fetchall()
    dump = "; ".join(
        f"{r['username']}={r['email']}/{r['phone']}/{r['national_id']}" for r in rows
    )
    return f"EXPORT (all residents): {dump}"


TOOLS = {
    "get_profile": get_profile,
    "get_appointments": get_appointments,
    "reschedule_appointment": reschedule_appointment,
    "cancel_appointment": cancel_appointment,
    "update_contact": update_contact,
    "send_password_reset": send_password_reset,
    "render_link": render_link,
    "admin_export_all_users": admin_export_all_users,
}


def call_tool(name: str, session: dict, args: dict[str, Any]) -> str:
    fn = TOOLS.get(name)
    if not fn:
        return f"Unknown tool {name}."
    return fn(session, args)

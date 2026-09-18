import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request

from .db import get_conn

SESSION_COOKIE = "cc_session"
SESSION_TTL_HOURS = 8
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, dk_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
    except ValueError:
        return False
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return hmac.compare_digest(dk, expected)


def create_session(resident_id: int) -> tuple[str, datetime]:
    sid = secrets.token_urlsafe(24)
    now = _now()
    expires = now + timedelta(hours=SESSION_TTL_HOURS)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (id, resident_id, created_at, expires_at, frozen) VALUES (?,?,?,?,0)",
            (sid, resident_id, now.isoformat(), expires.isoformat()),
        )
    return sid, expires


def delete_session(sid: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))


def load_session(sid: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            """SELECT s.id, s.resident_id, s.created_at, s.expires_at, s.frozen,
                      r.username, r.email, r.phone, r.national_id
               FROM sessions s JOIN residents r ON r.id = s.resident_id
               WHERE s.id = ?""",
            (sid,),
        ).fetchone()
    if not row:
        return None
    expires = datetime.fromisoformat(row["expires_at"])
    if expires < _now():
        delete_session(sid)
        return None
    return {
        "id": row["id"],
        "resident_id": row["resident_id"],
        "username": row["username"],
        "email": row["email"],
        "phone": row["phone"],
        "national_id": row["national_id"],
        "expires_at": expires,
        "frozen": bool(row["frozen"]),
    }


def get_current_session(request: Request) -> dict | None:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    return load_session(sid)


def freeze_session(sid: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE sessions SET frozen = 1 WHERE id = ?", (sid,))


def authenticate(username: str, password: str) -> int | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM residents WHERE username = ?",
            (username,),
        ).fetchone()
    if not row:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return row["id"]

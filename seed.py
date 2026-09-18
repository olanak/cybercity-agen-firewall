"""Idempotent seed script for the CyberCity demo database."""
from app.auth import hash_password
from app.db import get_conn, init_db


RESIDENTS = [
    {
        "username": "alice",
        "password": "demo1234",
        "email": "alice@cybercity.example",
        "phone": "+10-555-0101",
        "national_id": "TR-4481927",
    },
    {
        "username": "bob",
        "password": "demo1234",
        "email": "bob@cybercity.example",
        "phone": "+10-555-0202",
        "national_id": "TR-9987654",
    },
]

APPOINTMENTS = [
    ("apt-102", "alice", "cardiology", "2026-10-01T09:30:00"),
    ("apt-115", "alice", "physiotherapy", "2026-10-08T14:00:00"),
    ("apt-330", "bob", "dermatology", "2026-10-04T11:15:00"),
]


def seed() -> None:
    init_db()
    with get_conn() as conn:
        for r in RESIDENTS:
            existing = conn.execute(
                "SELECT id FROM residents WHERE username = ?", (r["username"],)
            ).fetchone()
            if existing:
                continue
            conn.execute(
                "INSERT INTO residents (username, password_hash, email, phone, national_id) VALUES (?,?,?,?,?)",
                (
                    r["username"],
                    hash_password(r["password"]),
                    r["email"],
                    r["phone"],
                    r["national_id"],
                ),
            )
        for ref, username, service, slot in APPOINTMENTS:
            existing = conn.execute(
                "SELECT id FROM appointments WHERE ref = ?", (ref,)
            ).fetchone()
            if existing:
                continue
            owner = conn.execute(
                "SELECT id FROM residents WHERE username = ?", (username,)
            ).fetchone()
            conn.execute(
                "INSERT INTO appointments (ref, owner_id, service, slot_iso, status) VALUES (?,?,?,?, 'booked')",
                (ref, owner["id"], service, slot),
            )
    print("Seeded database at", __import__("app.db", fromlist=["DB_PATH"]).DB_PATH)


if __name__ == "__main__":
    seed()

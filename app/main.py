import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import assistant, db, docparse, gateway, tools
from .auth import (
    SESSION_COOKIE,
    SESSION_TTL_HOURS,
    authenticate,
    create_session,
    delete_session,
    get_current_session,
)
from .db import get_conn

BASE_DIR = os.path.dirname(__file__)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="CyberCity Portal", lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@app.middleware("http")
async def _sticky_mode_cookie(request: Request, call_next):
    """When a request carries ?mode=X, persist it into a cookie so later
    POSTs (chat, upload, confirm) run in the same mode."""
    response = await call_next(request)
    q = request.query_params.get("mode")
    if q in ("none", "session", "full"):
        response.set_cookie("cc_mode", q, httponly=False, samesite="lax", path="/")
    return response


MODE_COOKIE = "cc_mode"


def _mode(request: Request) -> str:
    # Precedence: explicit ?mode= in the URL, then the sticky cookie set from
    # a prior mode switch, then the FIREWALL_MODE env default.
    q = request.query_params.get("mode")
    if q in ("none", "session", "full"):
        return q
    ck = request.cookies.get(MODE_COOKIE)
    if ck in ("none", "session", "full"):
        return ck
    env = os.environ.get("FIREWALL_MODE", "full")
    if env not in ("none", "session", "full"):
        env = "full"
    return env


def _base_ctx(request: Request, session: dict | None) -> dict:
    return {
        "request": request,
        "session": session,
        "mode": _mode(request),
        "now": datetime.now(timezone.utc),
    }


def require_session(request: Request) -> dict:
    s = get_current_session(request)
    if not s:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return s


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    s = get_current_session(request)
    if s:
        return RedirectResponse("/portal", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request, error: str | None = None):
    s = get_current_session(request)
    if s:
        return RedirectResponse("/portal", status_code=303)
    ctx = _base_ctx(request, None)
    ctx["error"] = error
    return templates.TemplateResponse("login.html", ctx)


@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    rid = authenticate(username.strip().lower(), password)
    if not rid:
        return RedirectResponse("/login?error=invalid", status_code=303)
    sid, expires = create_session(rid)
    resp = RedirectResponse("/portal", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE,
        sid,
        httponly=True,
        samesite="lax",
        expires=int(expires.timestamp()),
        path="/",
    )
    return resp


@app.post("/logout")
def logout(request: Request):
    sid = request.cookies.get(SESSION_COOKIE)
    if sid:
        delete_session(sid)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    appts = tools.list_appointments(s["resident_id"])
    import json as _json
    with get_conn() as conn:
        docs = conn.execute(
            "SELECT id, filename, body_text, hidden_segments, created_at FROM documents WHERE session_id = ? ORDER BY id DESC LIMIT 5",
            (s["id"],),
        ).fetchall()
        msgs = conn.execute(
            "SELECT role, text, created_at FROM messages WHERE session_id = ? ORDER BY id ASC",
            (s["id"],),
        ).fetchall()
        pending_rows = conn.execute(
            "SELECT token, call_json FROM pending_confirmations WHERE session_id = ? AND used = 0 ORDER BY id ASC",
            (s["id"],),
        ).fetchall()
    pending = []
    for row in pending_rows:
        call = _json.loads(row["call_json"])
        pending.append({
            "token": row["token"],
            "description": gateway.describe_call(call),
            "tool": call["tool"],
            "args": call.get("args", {}),
        })
    ctx = _base_ctx(request, s)
    ctx.update({
        "appointments": appts,
        "documents": docs,
        "messages": msgs,
        "pending": pending,
    })
    return templates.TemplateResponse("portal.html", ctx)


@app.get("/account", response_class=HTMLResponse)
def account_get(request: Request, ok: str | None = None):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    ctx = _base_ctx(request, s)
    ctx["ok"] = ok
    return templates.TemplateResponse("account.html", ctx)


@app.post("/account/email")
def account_email(request: Request, new_email: str = Form(...)):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    if s["frozen"]:
        raise HTTPException(status_code=403, detail="session frozen")
    tools.update_contact(s, {"new_email": new_email.strip()})
    return RedirectResponse("/account?ok=email", status_code=303)


@app.post("/upload")
def upload(request: Request, file: UploadFile = File(...)):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    if s["frozen"]:
        raise HTTPException(status_code=403, detail="session frozen")
    name = (file.filename or "upload").lower()
    if not (name.endswith(".txt") or name.endswith(".md") or name.endswith(".html")):
        raise HTTPException(status_code=400, detail="only .txt, .md, .html accepted")
    data = file.file.read(200 * 1024 + 1)
    if len(data) > 200 * 1024:
        raise HTTPException(status_code=400, detail="file exceeds 200 KB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")
    body, hidden = docparse.extract(text, name)
    import json
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO documents (session_id, filename, body_text, hidden_segments, created_at) VALUES (?,?,?,?,?)",
            (
                s["id"],
                file.filename or "upload",
                body,
                json.dumps(hidden),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return RedirectResponse("/portal", status_code=303)


@app.post("/chat")
def chat(request: Request, message: str = Form("")):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    if s["frozen"]:
        raise HTTPException(status_code=403, detail="session frozen")
    typed = message.strip()
    with get_conn() as conn:
        doc = conn.execute(
            "SELECT body_text FROM documents WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (s["id"],),
        ).fetchone()
    document_text = doc["body_text"] if doc else ""
    from datetime import datetime, timezone
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO messages (session_id, role, text, created_at) VALUES (?,?,?,?)",
            (s["id"], "resident", typed, datetime.now(timezone.utc).isoformat()),
        )
    calls = assistant.plan(s, typed, document_text)
    mode = _mode(request)
    allows: list[str] = []
    denies: list[str] = []
    pending: list[tuple[str, dict]] = []  # (token, call)
    for call in calls:
        result = gateway.execute(s, call, mode=mode)
        if result.decision == "allow":
            allows.append(result.reply)
        elif result.decision == "deny":
            denies.append(result.reply)
        elif result.decision == "confirm" and result.token:
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT call_json FROM pending_confirmations WHERE token = ?",
                    (result.token,),
                ).fetchone()
            import json as _json
            pending.append((result.token, _json.loads(row["call_json"])))
    if not calls:
        allows.append(assistant.small_talk(typed, document_text))
    parts: list[str] = []
    parts.extend(allows)
    parts.extend(denies)
    if pending:
        source = "uploaded document" if document_text.strip() else "your message"
        lines = [
            f"Instruction from the {source} needs your approval. "
            f"The following action{'s' if len(pending) > 1 else ''} will only run if you approve below:"
        ]
        for i, (_tok, call) in enumerate(pending, 1):
            lines.append(f"  {i}. {gateway.describe_call(call)}")
        lines.append("Approve or dismiss each one in the panel below.")
        parts.append("\n".join(lines))
    reply = "\n\n".join(p for p in parts if p)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO messages (session_id, role, text, created_at) VALUES (?,?,?,?)",
            (s["id"], "assistant", reply, datetime.now(timezone.utc).isoformat()),
        )
    return RedirectResponse("/portal", status_code=303)


@app.get("/confirm/{token}", response_class=HTMLResponse)
def confirm_get(request: Request, token: str):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, session_id, call_json, used FROM pending_confirmations WHERE token = ?",
            (token,),
        ).fetchone()
    if not row or row["used"] or row["session_id"] != s["id"]:
        raise HTTPException(status_code=404, detail="unknown or used confirmation")
    import json
    call = json.loads(row["call_json"])
    ctx = _base_ctx(request, s)
    ctx.update({"call": call, "token": token})
    return templates.TemplateResponse("confirm.html", ctx)


@app.post("/confirm/{token}")
def confirm_post(request: Request, token: str):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    if s["frozen"]:
        raise HTTPException(status_code=403, detail="session frozen")
    result = gateway.consume_confirmation(s, token, mode=_mode(request))
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO messages (session_id, role, text, created_at) VALUES (?,?,?,?)",
            (s["id"], "assistant", result.reply, datetime.now(timezone.utc).isoformat()),
        )
    return RedirectResponse("/portal", status_code=303)


@app.post("/decline/{token}")
def decline(request: Request, token: str):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    import json as _json
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, session_id, call_json, used FROM pending_confirmations WHERE token = ?",
            (token,),
        ).fetchone()
        if row and not row["used"] and row["session_id"] == s["id"]:
            conn.execute(
                "UPDATE pending_confirmations SET used = 1 WHERE id = ?",
                (row["id"],),
            )
            call = _json.loads(row["call_json"])
            reply = f"Dismissed: {gateway.describe_call(call)}. Nothing was changed."
            conn.execute(
                "INSERT INTO messages (session_id, role, text, created_at) VALUES (?,?,?,?)",
                (s["id"], "assistant", reply, datetime.now(timezone.utc).isoformat()),
            )
    return RedirectResponse("/portal", status_code=303)


@app.get("/log", response_class=HTMLResponse)
def log_view(request: Request):
    s = get_current_session(request)
    if not s:
        return RedirectResponse("/login", status_code=303)
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT d.id, d.tool, d.args_json, d.origins_json, d.decision,
                      d.reasons_json, d.mode, d.created_at,
                      r.username AS username
               FROM decisions d
               JOIN sessions s ON s.id = d.session_id
               JOIN residents r ON r.id = s.resident_id
               ORDER BY d.id DESC LIMIT 200"""
        ).fetchall()
    import json
    decisions = []
    for row in rows:
        decisions.append({
            "id": row["id"],
            "tool": row["tool"],
            "args": json.loads(row["args_json"]),
            "origins": json.loads(row["origins_json"]),
            "decision": row["decision"],
            "reasons": json.loads(row["reasons_json"]),
            "mode": row["mode"],
            "created_at": row["created_at"],
            "username": row["username"],
        })
    ctx = _base_ctx(request, s)
    ctx["decisions"] = decisions
    return templates.TemplateResponse("log.html", ctx)


@app.post("/reset-demo")
def reset_demo(request: Request):
    db.reset_db()
    import seed as seed_mod
    seed_mod.seed()
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

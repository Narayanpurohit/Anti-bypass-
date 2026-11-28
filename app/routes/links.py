"""Public token, CAPTCHA and short-link redirect routes."""
from datetime import datetime, timedelta
import secrets
import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from app.config import HCAPTCHA_SECRET
from app.database import urls_col, sess_col, block_col, redir_col
from app.core import TOKEN_LEN, PROXY_TOKEN_LEN, client_ip, detect_bot, log_visit, verify_html, _debug_page
router = APIRouter()

@router.get("/token", response_class=HTMLResponse)
async def entry(t: str, request: Request):
    if len(t) != TOKEN_LEN:
        raise HTTPException(404, "Invalid token")
    doc = await urls_col.find_one({"token": t})
    if not doc:
        raise HTTPException(404, "Not found")
    if not doc.get("active", True):
        raise HTTPException(403, "This link has been disabled")
    ua = request.headers.get("User-Agent", "")
    ip = client_ip(request)
    is_bot, reason = detect_bot(ua, request)
    if is_bot:
        await log_visit(t, request, "bot", reason)
        raise HTTPException(403, "Access denied")
    if await block_col.find_one({"ip": ip}):
        await log_visit(t, request, "blocked", "IP blocklist")
        raise HTTPException(403, "Access denied")
    await log_visit(t, request, "captcha_pending")
    if doc.get("captcha_enabled", True):
        return HTMLResponse(verify_html(t))
    sid = secrets.token_urlsafe(40)
    await sess_col.insert_one({
        "sid": sid, "token": t, "target": doc["target_url"],
        "expires": datetime.utcnow() + timedelta(hours=2), "ip": ip
    })
    return RedirectResponse(f"/p?s={sid}", status_code=302)


@router.post("/api/verify")
async def api_verify(request: Request):
    body      = await request.json()
    cap_token = body.get("cap", "")
    url_token = body.get("t", "")
    if not cap_token or not url_token or len(url_token) != TOKEN_LEN:
        raise HTTPException(400, detail="Missing fields")
    async with httpx.AsyncClient() as c:
        r = await c.post("https://hcaptcha.com/siteverify", data={
            "secret":   HCAPTCHA_SECRET,
            "response": cap_token,
            "remoteip": client_ip(request)
        })
        result = r.json()
    if not result.get("success"):
        await log_visit(url_token, request, "captcha_fail", str(result.get("error-codes", [])))
        return JSONResponse({"ok": False, "detail": "Captcha verification failed."}, status_code=403)
    doc = await urls_col.find_one({"token": url_token})
    if not doc:
        return JSONResponse({"ok": False, "detail": "Token not found."}, status_code=404)
    sid = secrets.token_urlsafe(40)
    await sess_col.insert_one({
        "sid": sid, "token": url_token, "target": doc["target_url"],
        "expires": datetime.utcnow() + timedelta(hours=2),
        "ip": client_ip(request)
    })
    await log_visit(url_token, request, "success")
    return {"ok": True, "sid": sid}



@router.get("/p")
async def proxy(s: str, request: Request):
    """Complete the session by redirecting; do not proxy or impersonate a browser."""
    session = await sess_col.find_one({"sid": s})
    if not session:
        return HTMLResponse(_debug_page("Session Not Found", "This access session does not exist or has expired."), status_code=403)
    if session["expires"] < datetime.utcnow():
        return HTMLResponse(_debug_page("Session Expired", "Please return to the original link and verify again."), status_code=403)
    await sess_col.update_one({"sid": s}, {"$set": {"used": True}})
    return RedirectResponse(url=session["target"], status_code=302)

@router.get("/go")
async def go_redirect(t: str, request: Request):
    ua = request.headers.get("User-Agent", "")
    ip = client_ip(request)
    is_bot, reason = detect_bot(ua, request)
    if is_bot:
        raise HTTPException(403, "Access denied")
    if await block_col.find_one({"ip": ip}):
        raise HTTPException(403, "Access denied")
    if len(t) != PROXY_TOKEN_LEN:
        raise HTTPException(404, "Invalid token")
    doc = await redir_col.find_one({"token": t})
    if not doc:
        raise HTTPException(404, "Link not found")
    if doc.get("expires") is not None and doc["expires"] < datetime.utcnow():
        raise HTTPException(410, "Link expired")
    return HTMLResponse(verify_html(t, verify_endpoint="/api/go-verify"))


@router.post("/api/go-verify")
async def go_verify(request: Request):
    body        = await request.json()
    cap_token   = body.get("cap", "")
    proxy_token = body.get("t", "")
    if not cap_token or len(proxy_token) != PROXY_TOKEN_LEN:
        raise HTTPException(400, "Missing fields")
    async with httpx.AsyncClient() as c:
        r = await c.post("https://hcaptcha.com/siteverify", data={
            "secret":   HCAPTCHA_SECRET,
            "response": cap_token,
            "remoteip": client_ip(request),
        })
        result = r.json()
    if not result.get("success"):
        return JSONResponse({"ok": False, "detail": "Captcha failed."}, status_code=403)
    doc = await redir_col.find_one({"token": proxy_token})
    if not doc:
        return JSONResponse({"ok": False, "detail": "Token not found."}, status_code=404)
    if doc.get("expires") is not None and doc["expires"] < datetime.utcnow():
        return JSONResponse({"ok": False, "detail": "Link expired."}, status_code=410)
    return {"ok": True, "redirect": doc["url"]}

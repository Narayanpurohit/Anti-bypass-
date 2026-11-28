"""API-based short-link creation and expiry handling."""
from datetime import datetime, timedelta
from typing import Optional
import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from app.config import BASE_URL
from app.database import apikey_col, config_col, redir_col
from app.core import PROXY_TOKEN_LEN, gen_proxy_token, detect_bot
router = APIRouter()

@router.get("/api")
async def protection_wrap(request: Request, url: str, api: str = "", format: str = "json", expiry: str = ""):
    ua = request.headers.get("User-Agent", "")
    is_bot, reason = detect_bot(ua, request)
    if is_bot:
        return JSONResponse({"status": "error", "message": ["Access denied — bot detected."], "shortenedUrl": ""}, status_code=403)
    if not url.startswith("http"):
        return JSONResponse({"status": "error", "message": ["URL is invalid. Must start with http/https."], "shortenedUrl": ""}, status_code=400)

    expiry_hours: Optional[int] = None
    expiry_label: str = "permanent"
    if expiry and expiry.strip() not in ("", "0", "∞", "permanent", "forever", "inf", "infinity"):
        try:
            h = int(expiry.strip())
            if h < 0:
                return JSONResponse({"status": "error", "message": ["expiry must be a positive integer (hours) or 0 for permanent."], "shortenedUrl": ""}, status_code=400)
            if h > 0:
                expiry_hours = h
                expiry_label = f"{h}h"
        except ValueError:
            return JSONResponse({"status": "error", "message": [f"Invalid expiry value '{expiry}'. Use a number of hours (e.g. 1, 24) or 0 for permanent."], "shortenedUrl": ""}, status_code=400)

    if api:
        key_doc = await apikey_col.find_one({"key": api, "active": True})
        if not key_doc:
            return JSONResponse({"status": "error", "message": ["Invalid or inactive API key."], "shortenedUrl": ""}, status_code=401)
        await apikey_col.update_one({"key": api}, {"$inc": {"usage": 1}, "$set": {"last_used": datetime.utcnow()}})

    shortener_cfg = await config_col.find_one({"_id": "shortener"})
    if shortener_cfg and shortener_cfg.get("enabled") and shortener_cfg.get("shortener_url") and shortener_cfg.get("shortener_api_key"):
        s_url     = shortener_cfg["shortener_url"].rstrip("/")
        s_api_key = shortener_cfg["shortener_api_key"]
        try:
            async with httpx.AsyncClient(, timeout=10) as c:
                resp = await c.get(s_url, params={"api": s_api_key, "url": url, "format": "json"})
                s_data = resp.json()
        except Exception as e:
            return JSONResponse({
                "status": "error",
                "message": [f"Shortener API call failed: {type(e).__name__}: {str(e)[:120]}"],
                "shortenedUrl": ""
            }, status_code=502)

        if s_data.get("status") != "success" or not s_data.get("shortenedUrl"):
            err_msg = s_data.get("message") or s_data.get("error") or "Shortener returned error."
            if isinstance(err_msg, str):
                err_msg = [err_msg]
            return JSONResponse({
                "status": "error",
                "message": err_msg,
                "shortenedUrl": "",
                "shortener_response": s_data
            }, status_code=400)

        url = s_data["shortenedUrl"]

    proxy_token = gen_proxy_token()
    while await redir_col.find_one({"token": proxy_token}):
        proxy_token = gen_proxy_token()

    expires_at = datetime.utcnow() + timedelta(hours=expiry_hours) if expiry_hours else None

    await redir_col.insert_one({
        "token":      proxy_token,
        "url":        url,
        "api_key":    api or None,
        "created":    datetime.utcnow(),
        "expires":    expires_at,
        "permanent":  expires_at is None,
    })
    short_url = f"{BASE_URL}/go?t={proxy_token}"
    return JSONResponse({
        "status":      "success",
        "message":     "",
        "shortenedUrl": short_url,
        "expiry":      expiry_label,
    })


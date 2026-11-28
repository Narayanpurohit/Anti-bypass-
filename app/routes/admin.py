"""Admin endpoints for URL, analytics, IP blocklist and API-key management."""
from datetime import datetime, timedelta
from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException
from app.config import BASE_URL
from app.database import urls_col, visits_col, sess_col, block_col, redir_col, config_col, apikey_col
from app.core import chk, gen_proxy_token
from app.schemas import (
    AddURL, ToggleURL, DeleteURL, BlockIPBody, UnblockIPBody,
    SetShortenerConfig, ClearShortenerConfig, CreateAPIKey,
    DeleteAPIKey, ToggleAPIKey,
)
router = APIRouter()

@router.post("/admin/add-url")
async def add_url(body: AddURL):
    chk(body.password)
    url = body.target_url

    shortener_cfg = await config_col.find_one({"_id": "shortener"})
    if shortener_cfg and shortener_cfg.get("enabled") and shortener_cfg.get("shortener_url") and shortener_cfg.get("shortener_api_key"):
        s_url     = shortener_cfg["shortener_url"].rstrip("/")
        s_api_key = shortener_cfg["shortener_api_key"]
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(s_url, params={"api": s_api_key, "url": url, "format": "json"})
                s_data = resp.json()
        except Exception as e:
            raise HTTPException(502, f"Shortener API call failed: {type(e).__name__}: {str(e)[:120]}")
        if s_data.get("status") != "success" or not s_data.get("shortenedUrl"):
            err_msg = s_data.get("message") or s_data.get("error") or "Shortener returned error."
            if isinstance(err_msg, list):
                err_msg = " ".join(err_msg)
            raise HTTPException(400, f"Shortener error: {err_msg}")
        url = s_data["shortenedUrl"]

    proxy_token = gen_proxy_token()
    while await redir_col.find_one({"token": proxy_token}):
        proxy_token = gen_proxy_token()

    expires_at = datetime.utcnow() + timedelta(hours=body.expiry_hours) if body.expiry_hours else None

    await redir_col.insert_one({
        "token":     proxy_token,
        "url":       url,
        "label":     body.label,
        "source":    "admin",
        "permanent": expires_at is None,
        "expires":   expires_at,
        "created":   datetime.utcnow(),
    })

    short_url = f"{BASE_URL}/r/{proxy_token}"
    expiry_label = f"{body.expiry_hours}h" if body.expiry_hours else "permanent"
    return {"ok": True, "token": proxy_token, "url": short_url, "expiry": expiry_label}




@router.post("/admin/delete-url")
async def delete_url(body: DeleteURL):
    chk(body.password)
    r = await redir_col.delete_one({"token": body.token})
    if r.deleted_count == 0:
        r = await urls_col.delete_one({"token": body.token})
        if r.deleted_count == 0:
            raise HTTPException(404, "Not found")
        await visits_col.delete_many({"token": body.token})
        await sess_col.delete_many({"token": body.token})
    return {"ok": True}


@router.get("/admin/go-links")
async def admin_go_links(password: str):
    chk(password)
    docs = await redir_col.find({"source": "admin"}, {"_id": 0}).sort("created", -1).to_list(200)
    for d in docs:
        d["short_url"] = f"{BASE_URL}/r/{d['token']}"
        if d.get("expires"):
            d["expires"] = d["expires"].isoformat()
        if d.get("created"):
            d["created"] = d["created"].isoformat()
    return docs


@router.post("/admin/toggle-url")
async def toggle_url(body: ToggleURL):
    chk(body.password)
    await urls_col.update_one({"token": body.token}, {"$set": {"active": body.active}})
    return {"ok": True}


@router.post("/admin/block-ip")
async def block_ip(body: BlockIPBody):
    chk(body.password)
    await block_col.update_one(
        {"ip": body.ip},
        {"$set": {"ip": body.ip, "reason": body.reason, "ts": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}


@router.post("/admin/unblock-ip")
async def unblock_ip(body: UnblockIPBody):
    chk(body.password)
    await block_col.delete_one({"ip": body.ip})
    return {"ok": True}


@router.get("/admin/urls")
async def admin_urls(password: str):
    chk(password)
    docs = await urls_col.find({}, {"_id": 0}).sort("created", -1).to_list(500)
    for d in docs:
        d["short_url"] = f"{BASE_URL}/token?t={d['token']}"
    return docs


@router.get("/admin/url-details")
async def url_details(token: str, password: str):
    chk(password)
    doc = await urls_col.find_one({"token": token}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Not found")
    doc["short_url"] = f"{BASE_URL}/token?t={doc['token']}"
    visits = await visits_col.find({"token": token}, {"_id": 0}).sort("ts", -1).limit(200).to_list(200)
    return {"url": doc, "visits": visits}


@router.get("/admin/visits")
async def admin_visits(password: str, token: Optional[str] = None, limit: int = 100):
    chk(password)
    q = {"token": token} if token else {}
    docs = await visits_col.find(q, {"_id": 0}).sort("ts", -1).limit(limit).to_list(limit)
    return docs


@router.get("/admin/stats")
async def admin_stats(password: str):
    chk(password)
    stats_pipeline = [{"$group": {
        "_id": None,
        "total_clicks":        {"$sum": "$stats.clicks"},
        "total_visits":        {"$sum": "$stats.visits"},
        "total_blocked":       {"$sum": "$stats.blocked"},
        "total_bots":          {"$sum": "$stats.bots"},
        "total_captcha_fails": {"$sum": "$stats.captcha_fails"},
    }}]
    import asyncio
    url_stats, redirect_stats, url_count, redirect_count = await asyncio.gather(
        urls_col.aggregate(stats_pipeline).to_list(1),
        redir_col.aggregate(stats_pipeline).to_list(1),
        urls_col.count_documents({}),
        redir_col.count_documents({}),
    )
    summary = {"total_urls": url_count + redirect_count}
    for key in ("total_clicks", "total_visits", "total_blocked", "total_bots", "total_captcha_fails"):
        summary[key] = (
            (url_stats[0].get(key, 0) if url_stats else 0)
            + (redirect_stats[0].get(key, 0) if redirect_stats else 0)
        )

    since    = datetime.utcnow() - timedelta(days=7)
    timeline = await visits_col.aggregate([
        {"$match": {"ts": {"$gte": since}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$ts"}}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]).to_list(10)

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    hourly = await visits_col.aggregate([
        {"$match": {"ts": {"$gte": today_start}, "status": "success"}},
        {"$group": {"_id": {"$hour": "$ts"}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}
    ]).to_list(24)

    devices  = await visits_col.aggregate([
        {"$group": {"_id": "$device", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}
    ]).to_list(10)
    browsers = await visits_col.aggregate([
        {"$group": {"_id": "$browser", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}
    ]).to_list(10)
    statuses = await visits_col.aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}
    ]).to_list(10)
    top_ips  = await visits_col.aggregate([
        {"$group": {"_id": "$ip", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 10}
    ]).to_list(10)
    blocked_ips = await block_col.find({}, {"_id": 0}).to_list(100)
    recent_bots = await visits_col.find({"status": "bot"}, {"_id": 0}).sort("ts", -1).limit(20).to_list(20)

    bot_reasons = await visits_col.aggregate([
        {"$match": {"status": "bot"}},
        {"$group": {"_id": "$reason", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}, {"$limit": 10}
    ]).to_list(10)

    return {
        "summary": summary, "timeline": timeline, "hourly": hourly,
        "devices": devices, "browsers": browsers, "statuses": statuses,
        "top_ips": top_ips, "blocked_ips": blocked_ips,
        "recent_bots": recent_bots, "bot_reasons": bot_reasons,
    }


@router.get("/admin/blocked-ips")
async def blocked_ips(password: str):
    chk(password)
    return await block_col.find({}, {"_id": 0}).to_list(200)


@router.get("/admin/shortener-config")
async def get_shortener_config(password: str):
    chk(password)
    doc = await config_col.find_one({"_id": "shortener"}, {"_id": 0})
    if not doc:
        return {"enabled": False, "shortener_url": "", "shortener_api_key": ""}
    return doc

@router.post("/admin/shortener-config")
async def set_shortener_config(body: SetShortenerConfig):
    chk(body.password)
    if body.shortener_url and not body.shortener_url.startswith("http"):
        raise HTTPException(400, "shortener_url must start with http/https")
    await config_col.update_one(
        {"_id": "shortener"},
        {"$set": {
            "shortener_url":     body.shortener_url.rstrip("/"),
            "shortener_api_key": body.shortener_api_key,
            "enabled":           body.enabled,
            "updated":           datetime.utcnow(),
        }},
        upsert=True
    )
    return {"ok": True}

@router.post("/admin/shortener-config/clear")
async def clear_shortener_config(body: ClearShortenerConfig):
    chk(body.password)
    await config_col.delete_one({"_id": "shortener"})
    return {"ok": True}

@router.post("/admin/create-apikey")
async def create_apikey(body: CreateAPIKey):
    chk(body.password)
    key = gen_apikey()
    while await apikey_col.find_one({"key": key}):
        key = gen_apikey()
    await apikey_col.insert_one({
        "key":      key,
        "label":    body.label,
        "active":   True,
        "usage":    0,
        "created":  datetime.utcnow(),
        "last_used": None,
    })
    return {"ok": True, "key": key}


@router.post("/admin/delete-apikey")
async def delete_apikey(body: DeleteAPIKey):
    chk(body.password)
    r = await apikey_col.delete_one({"key": body.key})
    if r.deleted_count == 0:
        raise HTTPException(404, "Key not found")
    return {"ok": True}


@router.post("/admin/toggle-apikey")
async def toggle_apikey(body: ToggleAPIKey):
    chk(body.password)
    await apikey_col.update_one({"key": body.key}, {"$set": {"active": body.active}})
    return {"ok": True}


@router.get("/admin/apikeys")
async def list_apikeys(password: str):
    chk(password)
    docs = await apikey_col.find({}, {"_id": 0}).sort("created", -1).to_list(200)
    return docs

import logging
import os
import re

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
import httpx
import secrets
import string
from pydantic import BaseModel
from typing import Optional

# Don't Make Any Config Changes Here!
MONGO_URL        = os.environ.get("MONGO_URL",        "mongodb+srv://Rename_1by1_robot:4lYZVWmtpiAUopqq@cluster0.r7y7j.mongodb.net/?appName=Cluster0")
HCAPTCHA_SECRET  = os.environ.get("HCAPTCHA_SECRET",  "")
HCAPTCHA_SITEKEY = os.environ.get("HCAPTCHA_SITEKEY", "")
ADMIN_PASSWORD   = os.environ.get("ADMIN_PASSWORD",   "TeamDev@Admin2025")
BASE_URL         = os.environ.get("BASE_URL",         "http://www.nkurl.online").rstrip("/")
PORT             = int(os.environ.get("PORT",         8000))

_mongo     = AsyncIOMotorClient(MONGO_URL)
db         = _mongo["teamdev_proxy"]
urls_col   = db["urls"]
visits_col = db["visits"]
sess_col   = db["sessions"]
block_col  = db["blocked"]
redir_col   = db["redirects"]
apikey_col  = db["apikeys"]
config_col  = db["config"]

app = FastAPI(title="TeamDev Proxy", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TOKEN_CHARS     = string.ascii_letters + string.digits
TOKEN_LEN       = 62
PROXY_TOKEN_LEN = 32
APIKEY_LEN      = 40


def gen_token() -> str:
    return "".join(secrets.choice(TOKEN_CHARS) for _ in range(TOKEN_LEN))

def gen_proxy_token() -> str:
    return "".join(secrets.choice(TOKEN_CHARS) for _ in range(PROXY_TOKEN_LEN))

def gen_apikey() -> str:
    return "td_" + "".join(secrets.choice(TOKEN_CHARS) for _ in range(APIKEY_LEN))

BOT_UA_PATTERNS = [
    "bot","crawl","spider","slurp","mediapartners","googlebot","bingbot",
    "yandex","baidu","duckduck","facebot","ia_archiver","python-requests",
    "curl","wget","libwww","scrapy","phantomjs","headless","selenium",
    "puppeteer","playwright","go-http","java/","httpclient","okhttp",
    "axios","got/","node-fetch","aiohttp","httpx","requests","urllib",
    "dataprovider","msnbot","applebot","semrush","ahref","majestic",
    "dotbot","rogerbot","exabot","gigabot","nutch","archive.org_bot",
    "facebookexternalhit","twitterbot","linkedinbot","whatsapp","telegram",
    "discordbot","slackbot","iframely","embedly","prerender","rendertron",
    "lighthouse","pagespeed","gtmetrix","pingdom","uptimerobot","statuscake",
    "newrelic","datadog","dynatrace","appdynamics","zabbix","nagios",
]

SUSPICIOUS_ACCEPT = ["text/plain", "*/*"]
TYPICAL_BROWSERS  = ["Mozilla/5.0"]

def detect_bot(ua: str, req: Request) -> tuple[bool, str]:
    """Returns (is_bot, reason)"""
    u = ua.lower().strip()

    if not ua:
        return True, "Missing User-Agent"

    for p in BOT_UA_PATTERNS:
        if p in u:
            return True, f"UA pattern: {p}"

    if len(ua) < 20:
        return True, "UA too short"

    if not ua.startswith("Mozilla/"):
        return True, "Non-browser UA prefix"

    accept = req.headers.get("Accept", "")
    if not accept:
        return True, "Missing Accept header"

    if not req.headers.get("Accept-Language", ""):
        return True, "Missing Accept-Language header"

    return False, ""


def client_ip(req: Request) -> str:
    fwd = req.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "0.0.0.0")


def parse_device(ua: str) -> dict:
    u = ua.lower()
    if any(x in u for x in ["iphone","android","mobile","blackberry"]):
        device = "Mobile"
    elif any(x in u for x in ["ipad","tablet"]):
        device = "Tablet"
    else:
        device = "Desktop"

    if "chrome" in u and "chromium" not in u and "edg" not in u:
        browser = "Chrome"
    elif "firefox" in u:
        browser = "Firefox"
    elif "safari" in u and "chrome" not in u:
        browser = "Safari"
    elif "edg" in u:
        browser = "Edge"
    elif "opr" in u or "opera" in u:
        browser = "Opera"
    else:
        browser = "Other"

    if "windows" in u:
        os_n = "Windows"
    elif "mac os" in u:
        os_n = "macOS"
    elif "android" in u:
        os_n = "Android"
    elif "iphone" in u or "ipad" in u:
        os_n = "iOS"
    elif "linux" in u:
        os_n = "Linux"
    else:
        os_n = "Other"

    return {"device": device, "browser": browser, "os": os_n}


async def log_visit(token: str, req: Request, status: str, reason: str = ""):
    ip  = client_ip(req)
    ua  = req.headers.get("User-Agent", "")
    dev = parse_device(ua)
    await visits_col.insert_one({
        "token": token, "ip": ip, "ua": ua, **dev,
        "referer": req.headers.get("Referer", ""),
        "status": status, "reason": reason,
        "ts": datetime.utcnow()
    })
    stat_map = {
        "success":         "stats.visits",
        "blocked":         "stats.blocked",
        "bot":             "stats.bots",
        "captcha_fail":    "stats.captcha_fails",
        "captcha_pending": "stats.clicks",
    }
    field = stat_map.get(status, "stats.clicks")
    extra = {"stats.clicks": 1} if status not in ("captcha_pending",) else {}
    await urls_col.update_one(
        {"token": token},
        {"$inc": {field: 1, **extra}, "$set": {"last_visit": datetime.utcnow()}}
    )

def verify_html(token: str, verify_endpoint: str = "/api/verify") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover"/>
<meta name="theme-color" content="#060810"/>
<title>Verify — TeamDev</title>
<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#060810;--card:#0b0d18;--border:#181d2e;--border2:#222840;
  --cyan:#00d4ff;--violet:#8b5cf6;--green:#00e5a0;--red:#ff4d6d;
  --text:#dde4f0;--muted:#4a5470;
  --mono:'Space Mono',monospace;--sans:'DM Sans',sans-serif;
}}
html{{height:100%;background:var(--bg)}}
body{{min-height:100vh;background:var(--bg);color:var(--text);font-family:var(--sans);
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:20px;padding-bottom:max(20px,env(safe-area-inset-bottom));position:relative;overflow:hidden;}}
body::before{{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 80% 60% at 20% 10%,rgba(139,92,246,.09) 0%,transparent 60%),
    radial-gradient(ellipse 60% 50% at 80% 90%,rgba(0,212,255,.07) 0%,transparent 60%);
  pointer-events:none;z-index:0;}}
body::after{{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,212,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.018) 1px,transparent 1px);
  background-size:52px 52px;pointer-events:none;z-index:0;}}
.glow-orb{{position:fixed;bottom:-20%;right:-10%;width:55%;height:55%;
  background:radial-gradient(ellipse,rgba(0,212,255,.06) 0%,transparent 65%);pointer-events:none;z-index:0;}}
.wrap{{position:relative;z-index:1;width:100%;max-width:400px;animation:slideIn .6s cubic-bezier(.16,1,.3,1) both;}}
@keyframes slideIn{{from{{opacity:0;transform:translateY(28px)}}to{{opacity:1;transform:none}}}}
.brand{{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:24px;}}
.brand-logo{{width:42px;height:42px;background:linear-gradient(135deg,rgba(0,212,255,.15),rgba(139,92,246,.15));
  border:1px solid rgba(0,212,255,.25);border-radius:12px;display:flex;align-items:center;justify-content:center;
  animation:logoPulse 3s ease-in-out infinite;}}
@keyframes logoPulse{{0%,100%{{box-shadow:0 0 0 0 rgba(0,212,255,.2)}}50%{{box-shadow:0 0 0 8px rgba(0,212,255,.0)}}}}
.brand-name{{font-size:20px;font-weight:800;letter-spacing:-.3px;
  background:linear-gradient(135deg,#fff 30%,var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:28px 24px;
  box-shadow:0 0 0 1px rgba(255,255,255,.025),0 28px 64px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.03);}}
.status-pill{{display:inline-flex;align-items:center;gap:6px;background:rgba(0,212,255,.07);
  border:1px solid rgba(0,212,255,.16);border-radius:100px;padding:4px 12px;
  font-family:var(--mono);font-size:9px;color:var(--cyan);letter-spacing:.12em;text-transform:uppercase;margin-bottom:16px;}}
.pill-dot{{width:5px;height:5px;background:var(--cyan);border-radius:50%;animation:blink 1.5s ease-in-out infinite;}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.1}}}}
h1{{font-size:22px;font-weight:800;letter-spacing:-.3px;margin-bottom:6px;
  background:linear-gradient(135deg,#fff 25%,var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.sub{{font-size:12px;color:var(--muted);font-family:var(--mono);line-height:1.65;margin-bottom:22px;}}
.checks{{display:flex;flex-direction:column;gap:7px;margin-bottom:22px;}}
.check-item{{display:flex;align-items:center;gap:9px;padding:9px 13px;border-radius:10px;
  border:1px solid var(--border);background:rgba(255,255,255,.018);
  font-family:var(--mono);font-size:11px;color:var(--muted);transition:all .3s ease;}}
.check-item.done{{border-color:rgba(0,229,160,.3);color:var(--green);background:rgba(0,229,160,.04);}}
.check-item.active{{border-color:rgba(0,212,255,.3);color:var(--cyan);background:rgba(0,212,255,.04);}}
.check-icon{{font-size:13px;flex-shrink:0;width:16px;text-align:center;}}
.spin{{display:inline-block;animation:spin .7s linear infinite;}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.captcha-wrap{{display:flex;justify-content:center;margin-bottom:18px;}}
#verify-btn{{width:100%;padding:13px;border-radius:12px;border:none;
  background:linear-gradient(135deg,var(--cyan),var(--violet));color:#fff;
  font-family:var(--sans);font-weight:700;font-size:14px;cursor:pointer;
  transition:all .25s;box-shadow:0 4px 20px rgba(0,212,255,.18);letter-spacing:.03em;position:relative;overflow:hidden;}}
#verify-btn::before{{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.15),transparent);opacity:0;transition:opacity .25s;}}
#verify-btn:hover:not(:disabled)::before{{opacity:1}}
#verify-btn:hover:not(:disabled){{transform:translateY(-1px);box-shadow:0 8px 28px rgba(0,212,255,.3);}}
#verify-btn:disabled{{opacity:.3;cursor:not-allowed;}}
.warning-bar{{display:flex;align-items:center;gap:7px;margin-top:14px;padding:9px 12px;border-radius:8px;
  background:rgba(255,77,109,.05);border:1px solid rgba(255,77,109,.15);font-family:var(--mono);font-size:10px;color:var(--red);}}
#loading{{position:fixed;inset:0;z-index:50;background:var(--bg);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;
  opacity:0;pointer-events:none;transition:opacity .3s;}}
#loading.show{{opacity:1;pointer-events:all;}}
.ring{{width:48px;height:48px;border:2px solid var(--border2);border-top-color:var(--cyan);border-radius:50%;animation:spin .75s linear infinite;}}
.load-label{{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:.14em;text-transform:uppercase;}}
.progress-track{{width:180px;height:1.5px;background:var(--border2);border-radius:2px;overflow:hidden;}}
.progress-fill{{height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--violet));transition:width .45s cubic-bezier(.16,1,.3,1);}}
#error-screen{{display:none;position:fixed;inset:0;z-index:60;flex-direction:column;align-items:center;justify-content:center;
  background:var(--bg);gap:12px;padding:24px;text-align:center;}}
#error-screen.show{{display:flex;}}
#error-screen h2{{color:var(--red);font-size:20px;font-weight:800;}}
#error-screen p{{color:var(--muted);font-size:12px;max-width:280px;font-family:var(--mono);line-height:1.6;}}
.retry-btn{{padding:10px 24px;border-radius:10px;border:1px solid var(--border2);background:transparent;
  color:var(--text);font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;margin-top:6px;}}
.retry-btn:hover{{border-color:var(--cyan);color:var(--cyan);}}
@media(max-width:480px){{.card{{padding:22px 16px;}}h1{{font-size:20px;}}}}
</style>
</head>
<body>
<div class="glow-orb"></div>
<div id="loading">
  <div class="ring"></div>
  <div class="load-label" id="load-msg">Validating...</div>
  <div class="progress-track"><div class="progress-fill" id="progress-fill"></div></div>
</div>
<div id="error-screen">
  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
    <circle cx="24" cy="24" r="23" stroke="#ff4d6d" stroke-width="1.5"/>
    <path d="M24 14v12M24 32v2" stroke="#ff4d6d" stroke-width="2" stroke-linecap="round"/>
  </svg>
  <h2>Access Denied</h2>
  <p id="error-msg">Verification failed. Please try again.</p>
  <button class="retry-btn" onclick="location.reload()">↺ Try Again</button>
</div>
<div class="wrap" id="verify-wrap">
  <div class="brand">
    <div class="brand-logo">
      <svg width="22" height="22" viewBox="0 0 36 36" fill="none">
        <path d="M18 3L4 9V21C4 28.8 10.4 35.3 18 37C25.6 35.3 32 28.8 32 21V9L18 3Z"
              fill="rgba(0,212,255,0.08)" stroke="#00d4ff" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M12 18L16 22L24 14" stroke="#00d4ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <span class="brand-name">TeamDev</span>
  </div>
  <div class="card">
    <div class="status-pill"><span class="pill-dot"></span>Security Check</div>
    <h1>Verify Access</h1>
    <p class="sub">Complete the captcha below to continue.<br>Automated bots are not permitted.</p>
    <div class="checks">
      <div class="check-item done"><span class="check-icon">✓</span><span>Connection secured</span></div>
      <div class="check-item active" id="check-captcha"><span class="check-icon"><span class="spin">⟳</span></span><span>Human verification</span></div>
      <div class="check-item" id="check-access"><span class="check-icon">○</span><span>Access grant</span></div>
    </div>
    <div class="captcha-wrap">
      <div class="h-captcha" data-sitekey="{HCAPTCHA_SITEKEY}" data-callback="onCaptchaSolved" data-theme="dark"></div>
    </div>
    <button id="verify-btn" disabled onclick="doVerify()">Continue</button>
    <div class="warning-bar"><span>⚠</span><span>Automated access is strictly blocked.</span></div>
  </div>
</div>
<script>
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {{
  if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && 'IJC'.includes(e.key)) || (e.ctrlKey && e.key === 'U'))
    e.preventDefault();
}});
let _captchaToken = null;
function onCaptchaSolved(token) {{
  _captchaToken = token;
  document.getElementById('verify-btn').disabled = false;
  const c = document.getElementById('check-captcha');
  c.className = 'check-item done';
  c.innerHTML = '<span class="check-icon">✓</span><span>Human verified</span>';
}}
const STEPS = [
  [15, 'Validating token...'],
  [35, 'Checking permissions...'],
  [55, 'Establishing tunnel...'],
  [75, 'Loading content...'],
  [92, 'Finalizing...'],
  [100,'Access granted'],
];
function setProgress(pct, msg) {{
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('load-msg').textContent = msg;
}}
async function doVerify() {{
  if (!_captchaToken) return;
  document.getElementById('verify-btn').disabled = true;
  document.getElementById('verify-btn').textContent = 'Verifying...';
  document.getElementById('verify-wrap').style.opacity = '0';
  document.getElementById('verify-wrap').style.transition = 'opacity .3s';
  setTimeout(() => {{
    document.getElementById('verify-wrap').style.display = 'none';
    document.getElementById('loading').classList.add('show');
  }}, 300);
  let stepIdx = 0;
  const iv = setInterval(() => {{
    if (stepIdx < STEPS.length) {{ setProgress(STEPS[stepIdx][0], STEPS[stepIdx][1]); stepIdx++; }}
  }}, 400);
  try {{
    const res = await fetch('{verify_endpoint}', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{cap: _captchaToken, t: '{token}'}})
    }});
    const data = await res.json();
    clearInterval(iv);
    if (!res.ok || !data.ok) {{ showError(data.detail || 'Verification failed.'); return; }}
    setProgress(100, 'Access granted');
    const ca = document.getElementById('check-access');
    ca.className = 'check-item done';
    ca.innerHTML = '<span class="check-icon">✓</span><span>Access granted</span>';
    setTimeout(() => {{
      if (data.redirect) window.location.href = data.redirect;
      else if (data.sid) window.location.href = '/p?s=' + data.sid;
    }}, 600);
  }} catch(err) {{
    clearInterval(iv);
    showError('Network error. Check your connection and retry.');
  }}
}}
function showError(msg) {{
  document.getElementById('loading').classList.remove('show');
  document.getElementById('error-msg').textContent = msg;
  document.getElementById('error-screen').classList.add('show');
}}
</script>
</body>
</html>"""


@app.get("/")
async def root():
    return {"status": "TeamDev Proxy — Online", "version": "3.0"}


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/token", response_class=HTMLResponse)
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


@app.post("/api/verify")
async def api_verify(request: Request):
    body      = await request.json()
    cap_token = body.get("cap", "")
    url_token = body.get("t", "")
    if not cap_token or not url_token or len(url_token) != TOKEN_LEN:
        raise HTTPException(400, detail="Missing fields")
    async with httpx.AsyncClient(verify=False) as c:
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


@app.get("/p")
async def proxy(s: str, request: Request):
    logger = logging.getLogger("teamdev.proxy")
    sess   = await sess_col.find_one({"sid": s})
    if not sess:
        return HTMLResponse(_debug_page("Session Not Found",
            f"SID <code>{s[:30]}…</code> does not exist.<br>Possible causes: expired, DB down, or SID mismatch."), status_code=403)
    if sess["expires"] < datetime.utcnow():
        return HTMLResponse(_debug_page("Session Expired",
            f"Session expired at <code>{sess['expires']}</code>.<br>Sessions last 2 hours. Go back and verify again."), status_code=403)
    target = sess["target"]
    logger.info(f"[PROXY] Target: {target}")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10, verify=False) as c:
            probe       = await c.head(target, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
            final_url   = str(probe.url)
            server_hdr  = probe.headers.get("server", "").lower()
            cf_mitigated = probe.headers.get("cf-mitigated", "")
            is_cf = ("cf-ray" in probe.headers or "cf-cache-status" in probe.headers or "cloudflare" in server_hdr or cf_mitigated != "")
            if is_cf or probe.status_code in (403, 406, 429, 503):
                await sess_col.update_one({"sid": s}, {"$set": {"used": True, "expires": datetime.utcnow()}})
                return RedirectResponse(url=final_url, status_code=302)
    except Exception as e:
        logger.warning(f"[PROXY] Pre-check failed ({type(e).__name__}): {e}")

    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host","cookie","x-forwarded-for","referer","origin","accept-encoding")
    }
    fwd_headers.update({
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer":         target,
        "Origin":          "/".join(target.split("/")[:3]),
    })

    ct = "text/html; charset=utf-8"
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as c:
            probe       = await c.get(target, headers=fwd_headers)
            diag_status = probe.status_code
            diag_headers= dict(probe.headers)
            diag_body   = probe.text[:2000]
            ct          = probe.headers.get("content-type", "text/html")
            cf_ray      = "cf-ray" in diag_headers
            cf_cache    = "cf-cache-status" in diag_headers
            is_cf       = cf_ray or cf_cache or "cloudflare" in diag_headers.get("server","").lower()
            body_lower  = diag_body.lower()
            is_cf_challenge = any(x in body_lower for x in ["just a moment","checking your browser","cf-browser-verification","challenge-platform","__cf_chl"])
            hdr_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in sorted(diag_headers.items()))
            debug_info = f"""
<h3 style='margin:16px 0 8px;color:#f59e0b'>Response Headers</h3>
<table style='width:100%;border-collapse:collapse;font-size:12px;font-family:monospace'>
  <tr style='background:rgba(255,255,255,.05)'><th style='padding:6px 10px;text-align:left'>Header</th><th style='padding:6px 10px;text-align:left'>Value</th></tr>
  {hdr_rows}
</table>
<h3 style='margin:16px 0 8px;color:#f59e0b'>Body Snippet</h3>
<pre style='background:#0a0c14;border:1px solid #1c2035;border-radius:8px;padding:12px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#8892a4'>{diag_body[:1500].replace('<','&lt;').replace('>','&gt;')}</pre>
"""
            if is_cf_challenge:
                return HTMLResponse(_debug_page(f"Cloudflare Challenge (HTTP {diag_status})", f"The target is behind Cloudflare JS challenge.<br><b>Fix:</b> use residential proxy or redirect directly." + debug_info), status_code=200)
            if diag_status == 403:
                return HTMLResponse(_debug_page("Target Returned 403 Forbidden", "The target URL returned HTTP 403." + debug_info), status_code=200)
            if diag_status == 404:
                return HTMLResponse(_debug_page("Target URL Not Found (404)", f"The URL returned 404." + debug_info), status_code=200)
            if diag_status in (406, 429, 503):
                return HTMLResponse(_debug_page(f"Target Blocked Request (HTTP {diag_status})", f"The target server refused with {diag_status}." + debug_info), status_code=200)
    except httpx.ConnectTimeout:
        return HTMLResponse(_debug_page("Connection Timeout", f"Could not connect to <code>{target[:80]}</code> within 15 seconds."), status_code=502)
    except httpx.ConnectError as e:
        return HTMLResponse(_debug_page("Connection Error", f"Failed to connect: <code>{str(e)[:120]}</code>"), status_code=502)
    except Exception as e:
        return HTMLResponse(_debug_page("Unexpected Error", f"<code>{type(e).__name__}: {str(e)[:200]}</code>"), status_code=500)

    async def stream():
        async with httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as c:
            async with c.stream("GET", target, headers=fwd_headers) as resp:
                first = True
                async for chunk in resp.aiter_bytes(8192):
                    if first:
                        first = False
                        base_tag = f'<base href="{target}">'.encode()
                        chunk_lower = chunk.lower()
                        if b"<head>" in chunk_lower:
                            idx = chunk_lower.find(b"<head>") + 6
                            chunk = chunk[:idx] + base_tag + chunk[idx:]
                        elif b"<html" in chunk_lower:
                            idx = chunk_lower.find(b">", chunk_lower.find(b"<html")) + 1
                            chunk = chunk[:idx] + base_tag + chunk[idx:]
                    yield chunk

    return StreamingResponse(stream(), media_type=ct, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})

@app.get("/api")
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
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
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


@app.get("/go")
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


@app.post("/api/go-verify")
async def go_verify(request: Request):
    body        = await request.json()
    cap_token   = body.get("cap", "")
    proxy_token = body.get("t", "")
    if not cap_token or len(proxy_token) != PROXY_TOKEN_LEN:
        raise HTTPException(400, "Missing fields")
    async with httpx.AsyncClient(verify=False) as c:
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

def _debug_page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Debug — {title}</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@600;800&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#060810;color:#dde4f0;font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:40px 20px}}
.wrap{{max-width:780px;width:100%}}
.tag{{display:inline-flex;align-items:center;gap:6px;background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25);border-radius:100px;padding:4px 12px;font-family:'Space Mono',monospace;font-size:9px;color:#ff4d6d;letter-spacing:.12em;text-transform:uppercase;margin-bottom:14px}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.4px;margin-bottom:10px;color:#fff}}
.body{{font-size:13px;color:#5a6480;line-height:1.75;margin-bottom:22px}}
.body code{{background:#0f1120;border:1px solid #181d2e;border-radius:4px;padding:1px 6px;font-family:'Space Mono',monospace;font-size:11px;color:#00d4ff}}
.body b{{color:#dde4f0}}
table td,table th{{padding:7px 10px;border:1px solid #181d2e;font-family:'Space Mono',monospace;font-size:10px;color:#5a6480;text-align:left;word-break:break-all}}
table th{{color:#4a5470;background:#0b0d18}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border-radius:8px;border:1px solid #222840;background:rgba(255,255,255,.04);color:#dde4f0;font-family:'DM Sans',sans-serif;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;margin-top:14px;transition:all .2s}}
.btn:hover{{border-color:#00d4ff;color:#00d4ff}}
</style>
</head>
<body>
<div class="wrap">
  <div class="tag">⚠ Debug Error</div>
  <h1>{title}</h1>
  <div class="body">{body}</div>
  <a href="javascript:history.back()" class="btn">← Go Back</a>
</div>
</body>
</html>"""

def chk(pwd: str):
    if pwd != ADMIN_PASSWORD:
        raise HTTPException(403, "Unauthorized")

class AddURL(BaseModel):
    label: str
    target_url: str
    captcha_enabled: bool = True
    expiry_hours: Optional[int] = None
    password: str

class ToggleURL(BaseModel):
    token: str
    active: bool
    password: str

class DeleteURL(BaseModel):
    token: str
    password: str

class BlockIPBody(BaseModel):
    ip: str
    reason: str = ""
    password: str

class UnblockIPBody(BaseModel):
    ip: str
    password: str

class SetShortenerConfig(BaseModel):
    shortener_url: str
    shortener_api_key: str
    enabled: bool = True
    password: str

class ClearShortenerConfig(BaseModel):
    password: str

class CreateAPIKey(BaseModel):
    label: str
    password: str

class DeleteAPIKey(BaseModel):
    key: str
    password: str

class ToggleAPIKey(BaseModel):
    key: str
    active: bool
    password: str

@app.post("/admin/add-url")
async def add_url(body: AddURL):
    chk(body.password)
    url = body.target_url

    shortener_cfg = await config_col.find_one({"_id": "shortener"})
    if shortener_cfg and shortener_cfg.get("enabled") and shortener_cfg.get("shortener_url") and shortener_cfg.get("shortener_api_key"):
        s_url     = shortener_cfg["shortener_url"].rstrip("/")
        s_api_key = shortener_cfg["shortener_api_key"]
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
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

    short_url = f"{BASE_URL}/go?t={proxy_token}"
    expiry_label = f"{body.expiry_hours}h" if body.expiry_hours else "permanent"
    return {"ok": True, "token": proxy_token, "url": short_url, "expiry": expiry_label}




@app.post("/admin/delete-url")
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


@app.get("/admin/go-links")
async def admin_go_links(password: str):
    chk(password)
    docs = await redir_col.find({"source": "admin"}, {"_id": 0}).sort("created", -1).to_list(200)
    for d in docs:
        d["short_url"] = f"{BASE_URL}/go?t={d['token']}"
        if d.get("expires"):
            d["expires"] = d["expires"].isoformat()
        if d.get("created"):
            d["created"] = d["created"].isoformat()
    return docs


@app.post("/admin/toggle-url")
async def toggle_url(body: ToggleURL):
    chk(body.password)
    await urls_col.update_one({"token": body.token}, {"$set": {"active": body.active}})
    return {"ok": True}


@app.post("/admin/block-ip")
async def block_ip(body: BlockIPBody):
    chk(body.password)
    await block_col.update_one(
        {"ip": body.ip},
        {"$set": {"ip": body.ip, "reason": body.reason, "ts": datetime.utcnow()}},
        upsert=True
    )
    return {"ok": True}


@app.post("/admin/unblock-ip")
async def unblock_ip(body: UnblockIPBody):
    chk(body.password)
    await block_col.delete_one({"ip": body.ip})
    return {"ok": True}


@app.get("/admin/urls")
async def admin_urls(password: str):
    chk(password)
    docs = await urls_col.find({}, {"_id": 0}).sort("created", -1).to_list(500)
    for d in docs:
        d["short_url"] = f"{BASE_URL}/token?t={d['token']}"
    return docs


@app.get("/admin/url-details")
async def url_details(token: str, password: str):
    chk(password)
    doc = await urls_col.find_one({"token": token}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Not found")
    doc["short_url"] = f"{BASE_URL}/token?t={doc['token']}"
    visits = await visits_col.find({"token": token}, {"_id": 0}).sort("ts", -1).limit(200).to_list(200)
    return {"url": doc, "visits": visits}


@app.get("/admin/visits")
async def admin_visits(password: str, token: Optional[str] = None, limit: int = 100):
    chk(password)
    q = {"token": token} if token else {}
    docs = await visits_col.find(q, {"_id": 0}).sort("ts", -1).limit(limit).to_list(limit)
    return docs


@app.get("/admin/stats")
async def admin_stats(password: str):
    chk(password)
    pipe = [{"$group": {
        "_id": None,
        "total_urls":          {"$sum": 1},
        "total_clicks":        {"$sum": "$stats.clicks"},
        "total_visits":        {"$sum": "$stats.visits"},
        "total_blocked":       {"$sum": "$stats.blocked"},
        "total_bots":          {"$sum": "$stats.bots"},
        "total_captcha_fails": {"$sum": "$stats.captcha_fails"},
    }}]
    r = await urls_col.aggregate(pipe).to_list(1)
    summary = r[0] if r else {}
    summary.pop("_id", None)

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


@app.get("/admin/blocked-ips")
async def blocked_ips(password: str):
    chk(password)
    return await block_col.find({}, {"_id": 0}).to_list(200)


@app.get("/admin/shortener-config")
async def get_shortener_config(password: str):
    chk(password)
    doc = await config_col.find_one({"_id": "shortener"}, {"_id": 0})
    if not doc:
        return {"enabled": False, "shortener_url": "", "shortener_api_key": ""}
    return doc

@app.post("/admin/shortener-config")
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

@app.post("/admin/shortener-config/clear")
async def clear_shortener_config(body: ClearShortenerConfig):
    chk(body.password)
    await config_col.delete_one({"_id": "shortener"})
    return {"ok": True}

@app.post("/admin/create-apikey")
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


@app.post("/admin/delete-apikey")
async def delete_apikey(body: DeleteAPIKey):
    chk(body.password)
    r = await apikey_col.delete_one({"key": body.key})
    if r.deleted_count == 0:
        raise HTTPException(404, "Key not found")
    return {"ok": True}


@app.post("/admin/toggle-apikey")
async def toggle_apikey(body: ToggleAPIKey):
    chk(body.password)
    await apikey_col.update_one({"key": body.key}, {"$set": {"active": body.active}})
    return {"ok": True}


@app.get("/admin/apikeys")
async def list_apikeys(password: str):
    chk(password)
    docs = await apikey_col.find({}, {"_id": 0}).sort("created", -1).to_list(200)
    return docs

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    try:
        with open("admin.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h3 style='font-family:monospace;padding:40px'>admin.html not found in server directory</h3>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)

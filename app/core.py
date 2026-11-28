"""Shared helpers for tokens, visit logging, verification HTML and admin checks."""
import secrets
import string
from datetime import datetime
from fastapi import HTTPException, Request
from app.config import ADMIN_PASSWORD, HCAPTCHA_SITEKEY
from app.database import urls_col, visits_col

TOKEN_CHARS = string.ascii_letters + string.digits
TOKEN_LEN = 62
PROXY_TOKEN_LEN = 32
APIKEY_LEN = 40

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


from fastapi.responses import HTMLResponse


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
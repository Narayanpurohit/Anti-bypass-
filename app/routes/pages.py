"""Landing, account placeholder, health and admin HTML routes."""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def root():
    home_file = os.path.join(os.path.dirname(__file__), "templates", "home.html")
    try:
        with open(home_file, "r", encoding="utf-8") as page:
            return HTMLResponse(page.read())
    except FileNotFoundError:
        return HTMLResponse("<h1>Home page is not configured.</h1>", status_code=500)


@router.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse("""
    <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Log in — TeamDev</title><body style="font:16px system-ui;background:#080b14;color:#edf3ff;min-height:100vh;display:grid;place-items:center">
    <main style="text-align:center;padding:32px"><h1>Login</h1><p>Login will be available soon.</p><a style="color:#55d8ee" href="/">Back home</a></main></body></html>
    """)


@router.get("/sign-up", response_class=HTMLResponse)
async def sign_up_page():
    return HTMLResponse("""
    <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Sign up — TeamDev</title><body style="font:16px system-ui;background:#080b14;color:#edf3ff;min-height:100vh;display:grid;place-items:center">
    <main style="text-align:center;padding:32px"><h1>Sign up</h1><p>Registration will be available soon.</p><a style="color:#55d8ee" href="/">Back home</a></main></body></html>
    """)

@router.get("/health")
async def health():
    return {"ok": True}


@router.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    admin_file = Path(__file__).resolve().parents[2] / "admin.html"
    try:
        return HTMLResponse(admin_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return HTMLResponse("<h3>admin.html not found</h3>", status_code=500)

# Project Context — Anti Bypass

> Last reviewed: 2026-11-28  
> Repository: https://github.com/Narayanpurohit/Anti-bypass-  
> Current default branch: `main2` (confirmed from GitHub repository metadata)

## 1. Project overview

This is a Python FastAPI + MongoDB application for managing short links, CAPTCHA verification, redirects, visit analytics, IP blocklists, API keys, and an admin dashboard. The public homepage is a simple welcome page with Log in and Sign up links.

**Important product limitation:** Login and Sign up are placeholders only. There is no user registration, login/session system, password hashing, or user account database implemented yet.

The former `/p` reverse-proxy behavior has intentionally been replaced with a normal HTTP redirect after a valid session. Generated redirect links now use `/r/{8-character-token}`; legacy `/go?t={32-character-token}` links remain supported. Do not restore proxying, browser impersonation, response rewriting, or mechanisms intended to bypass third-party websites' anti-bot or access controls.

## 2. Repository layout

```text
.
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app, middleware and router registration
│   ├── config.py               # Environment configuration; calls load_dotenv()
│   ├── database.py             # Motor client and MongoDB collections
│   ├── core.py                 # Tokens, bot heuristics, visit logging, CAPTCHA HTML, admin check
│   ├── schemas.py              # Pydantic request models
│   └── routes/
│       ├── __init__.py
│       ├── pages.py            # Home, placeholder login/signup, health, admin HTML
│       ├── links.py            # /token, CAPTCHA verification, /p, /go redirects
│       ├── shortener.py        # Public /api short-link creation endpoint
│       └── admin.py            # Admin CRUD, analytics, blocklist and API-key endpoints
├── templates/home.html         # Public landing page
├── admin.html                  # Admin dashboard frontend (large standalone HTML/JS)
├── server.py                   # Backward-compatible import: server:app
├── requirements.txt
├── Dockerfile
├── Procfile
├── app.json
├── heroku.yml
├── .env.example
├── .gitignore
├── README.md
└── README_STRUCTURE.md
```

## 3. Runtime and deployment

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run locally:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The legacy command remains supported:

```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```

Docker runs `uvicorn app.main:app` on port 8000. The Procfile uses the compatibility entry point `server:app` and the platform-provided `$PORT`.

## 4. Environment variables

`app/config.py` calls `load_dotenv()`, so a root-level `.env` file is loaded when present. Existing process/hosting environment variables take precedence under python-dotenv's default behavior.

| Variable | Purpose |
|---|---|
| `MONGO_URL` | MongoDB connection URI; defaults to local MongoDB |
| `HCAPTCHA_SECRET` | hCaptcha server-side secret |
| `HCAPTCHA_SITEKEY` | hCaptcha public site key rendered in verification HTML |
| `ADMIN_PASSWORD` | Admin password; empty means admin access is denied |
| `BASE_URL` | Public application origin used to construct links |
| `PORT` | Listen port; defaults to 8000 |

Start from `.env.example`. Never commit real passwords, database credentials, hCaptcha secrets, API keys, or production environment files. Configure production values in the hosting provider's environment settings.

## 5. MongoDB collections

The database name is `teamdev_proxy`. Collections currently referenced in `app/database.py`:

- `urls` — managed target URLs and counters
- `visits` — request/visit analytics
- `sessions` — post-verification redirect sessions
- `blocked` — blocked IP addresses
- `redirects` — generated short redirect records
- `apikeys` — API keys and usage metadata
- `config` — settings such as external shortener configuration

No explicit MongoDB index creation is currently visible in `app/database.py`.

## 6. Main routes

### Public pages
- `GET /` — homepage
- `GET /login` — placeholder page, not real authentication
- `GET /sign-up` — placeholder page, not real registration
- `GET /health` — basic `{"ok": true}` response
- `GET /admin` — serves `admin.html`

### Link and verification flow
- `GET /token?t=...` — checks a managed URL, applies request heuristics/blocklist, then displays hCaptcha or creates a session
- `POST /api/verify` — verifies hCaptcha and creates a redirect session
- `GET /p?s=...` — checks the session expiry and redirects to its stored destination
- `GET /r/{token}` — serves the hCaptcha page for a generated redirect link using an 8-character token
- `GET /go?t=...` — backward-compatible route for previously generated 32-character links
- `POST /api/go-verify` — verifies hCaptcha and returns the redirect destination
- `GET /api?... ` — creates a generated short link, optionally using a configured external URL shortener

### Admin API
Admin routes are under `/admin/*` and include URL management, redirect-link management, visit/statistics queries, IP block/unblock, shortener configuration, and API-key management. The helper `app.core.chk()` compares the supplied password with `ADMIN_PASSWORD` using `secrets.compare_digest` and rejects access if the configured password is empty.

## 7. Code review findings — address before production

These are source-inspection findings, not claims that a live exploit or runtime failure has been reproduced.

1. **Admin password in query strings:** Several GET admin endpoints accept `password` as a query parameter. Query strings can be retained in browser history, reverse-proxy logs, analytics, and monitoring. Prefer an authenticated admin session or an Authorization header; avoid credentials in URLs.
2. **Redirect session replay:** `GET /p` sets `used: true` but does not reject an already-used session. It also does not compare the requesting IP with the session's stored IP. Enforce one-time use atomically and decide whether IP binding is appropriate.
3. **Verification route state checks:** `POST /api/verify` checks token length and CAPTCHA success, but should also re-check that the URL exists, is active, and is configured for CAPTCHA before issuing a session. Do not rely only on checks performed by the page route.
4. **Optional API-key enforcement:** `GET /api` validates a key only when the `api` parameter is supplied. If this endpoint is intended to require authentication, reject missing keys as well.
5. **URL validation:** `startswith("http")` is not robust URL validation. Parse URLs and allow only explicit `http`/`https` schemes with a valid host; apply validation consistently to public and admin-created destinations.
6. **Client IP trust:** `client_ip()` trusts the first `X-Forwarded-For` value without a trusted-proxy configuration. A directly reachable client may spoof it. Trust forwarding headers only from known reverse proxies.
7. **CORS policy:** `app/main.py` currently allows every origin. Restrict origins to the actual frontend domains if browser-based cross-origin access is needed.
8. **Abuse controls:** No application-level rate limiting is visible for CAPTCHA verification, link creation, or admin login/password attempts. Add suitable limits and monitoring.
9. **Configuration validation:** Fail fast or expose a clear readiness state when production-required values (MongoDB URI, hCaptcha credentials, admin password, public BASE_URL) are missing or invalid.
10. **Database lifecycle/indexes:** Add a FastAPI lifespan handler to close the Motor client cleanly and create indexes for frequently queried fields/uniqueness/expiry where appropriate.
11. **Input bounds:** Add Pydantic constraints for URL lengths, labels, expiry values, IP format, and admin list limits. Ensure all redirects use validated stored URLs.

## 8. Documentation note

`README_STRUCTURE.md` currently says the application does not automatically load `.env`; that statement is stale. The current `app/config.py` does call `load_dotenv()`. Update that README sentence when editing documentation.

## 9. Testing status

- The repository tree currently contains no dedicated `tests/` directory or visible automated test suite.
- This review inspected the current `main2` source files and repository tree through GitHub.
- A local Python import, dependency installation, MongoDB integration test, hCaptcha integration test, browser test, and production deployment test have **not** been run as part of this review.
- Do not describe the application as fully tested until those checks are performed.

## 10. Working rules for future changes

- Work on `main2`, which is the current default branch, unless the repository owner explicitly requests another branch.
- Preserve the modular architecture and the `server:app` compatibility entry point.
- Do not commit real secrets or generated local environment files.
- Before changing a route, inspect its frontend callers in `admin.html` and its database document shape; keep API contracts consistent or update callers together.
- Prefer small, testable changes and add automated tests for route behavior, token/session lifecycle, configuration, and admin authorization.
- Do not claim a test passed unless it was actually run and its result observed.


## 11. Latest maintenance update (2026-11-28)

- Admin dashboard link copying now uses the Clipboard API on secure contexts and a textarea fallback on ordinary HTTP origins.
- Newly generated redirect tokens are 8 characters (base62) and use the compact public path `/r/{token}`.
- The previous `/go?t={token}` route remains available for legacy 32-character links.
- Admin-created and API-created redirect links now both return `/r/{token}`.
- Redirect link entry, CAPTCHA failure, and successful verification events are written to the visits collection. Link counters are updated in the correct collection.
- Dashboard totals now include records from both `urls` and `redirects`, rather than counting only protected-content URLs.
- Clicks count the initial CAPTCHA-pending entry; successful CAPTCHA verification increments the verified/visit count. Bot, blocked, and CAPTCHA-failure counters are tracked separately.
- Existing historical redirect visits were not backfilled. Analytics start accumulating correctly for events after this update.
- These changes were source-reviewed on GitHub, but have not yet been run against a live MongoDB/hCaptcha deployment or verified in a browser.

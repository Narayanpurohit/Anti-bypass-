# Modular application structure

The legacy `server:app` import remains supported.

## Layout
- `app/main.py`: FastAPI application and router registration
- `app/config.py`: environment-based settings
- `app/database.py`: MongoDB client and collections
- `app/core.py`: shared token, CAPTCHA HTML, visitor and admin helpers
- `app/schemas.py`: Pydantic request models
- `app/routes/pages.py`: landing, login/signup placeholders, health and admin page
- `app/routes/links.py`: token verification, CAPTCHA and redirects
- `app/routes/shortener.py`: short-link API
- `app/routes/admin.py`: admin management and analytics
- `templates/home.html`: public landing page

## Configuration
Copy `.env.example` to `.env` and set the MongoDB URI, hCaptcha credentials,
admin password and public base URL. Never commit real credentials.

## Run
Install `requirements.txt`, then run `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
Existing deployments can continue using `uvicorn server:app`.

## Redirect behavior
After CAPTCHA verification, `/p` now performs a normal HTTP redirect to the
configured destination. It does not fetch remote pages, rewrite responses, or
imitate a browser to get around a destination site's anti-bot controls.

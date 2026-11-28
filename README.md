# Anti Bypass

A FastAPI-based link-protection and redirect service with browser-header bot screening, hCaptcha verification, optional third-party URL shortener integration, visit analytics, IP blocking, API keys, and a web admin dashboard.

> **Important:** This is a lightweight access-gating and link-wrapping application. It is not a guaranteed anti-bypass solution, a WAF, or a replacement for strong authentication. User-Agent and header checks are heuristic and can be spoofed. Review the production security checklist before public deployment.

## Contents

- Overview and features
- Link workflows
- Requirements and configuration
- MongoDB and hCaptcha setup
- Ubuntu 22.04 VPS deployment
- Heroku deployment
- Render deployment
- Docker deployment
- Public and admin API reference
- Admin dashboard
- Database collections
- Troubleshooting
- Production security checklist

## Overview

The application provides two distinct link flows:

1. **Protected content flow — /token:** validates a 62-character token, checks whether the link is active, screens browser-like request headers, checks the IP blocklist, optionally requires hCaptcha, creates a temporary session, and redirects the visitor to the stored destination URL after session validation.
2. **Redirect wrapper flow — /r/{token}:** validates an 8-character token, screens browser-like request headers, checks the IP blocklist and link expiry, requires hCaptcha, and then redirects the visitor to the stored destination URL. Legacy `/go?t={32-character-token}` links remain supported.

The public **/api** endpoint creates links for the redirect-wrapper flow. An optional external URL shortener can be configured. When enabled, the destination is shortened first and the resulting URL is wrapped by this application.

## Features

- FastAPI asynchronous web server.
- MongoDB storage using Motor.
- Two token-based link flows: protected content and redirect wrapper.
- hCaptcha verification.
- Basic bot screening using User-Agent, Accept, and Accept-Language headers.
- IP blocklist management.
- Temporary proxy sessions with a two-hour lifetime.
- Optional expiry for generated redirect links.
- Optional third-party shortener API integration.
- API-key creation, activation, deactivation, deletion, and usage counters.
- Visit logs containing IP, User-Agent, device, browser, OS, referrer, status, reason, and timestamp.
- Admin dashboard for link management, analytics, bot logs, blocked IPs, API keys, and shortener settings.
- Health-check endpoint.
- Dockerfile and Procfile included.

## How it works

### Flow A — Protected content link

Entry URL: /token?t=YOUR_62_CHARACTER_TOKEN

1. Visitor opens the protected link.
2. Server validates the token and looks up its record in MongoDB.
3. Unknown or disabled links are rejected.
4. The request is screened using its User-Agent, Accept, and Accept-Language headers.
5. The visitor IP is checked against the blocklist.
6. If CAPTCHA is enabled for the link (enabled by default), an hCaptcha page is displayed.
7. After successful verification, the server creates a session that expires after two hours.
8. The visitor is sent to /p?s=SESSION_ID, which validates the temporary session and performs a normal HTTP redirect to the target URL.

If CAPTCHA is disabled for a protected URL, a session is created after the initial checks without showing hCaptcha.

### Flow B — Redirect wrapper link

Entry URL: /r/YOUR_8_CHARACTER_TOKEN (legacy: /go?t=YOUR_32_CHARACTER_TOKEN)

1. Visitor opens the generated /go link.
2. Server checks browser-like headers, IP blocklist, token validity, and expiry.
3. The hCaptcha verification page is displayed.
4. The browser submits the CAPTCHA response to /api/go-verify.
5. If verification succeeds and the link is still valid, the API returns the stored destination URL.
6. The browser navigates to that destination.

### Flow C — Create a wrapped link through the API

Endpoint: /api?url=DESTINATION_URL&api=API_KEY&format=json&expiry=HOURS

1. The API checks request headers and validates the destination URL.
2. If an API key is supplied, it must exist and be active.
3. If an external shortener is configured and enabled, the destination is sent to that shortener.
4. The resulting URL is saved in MongoDB with a random 8-character token.
5. The API returns a compact `/r/{8-character-token}` link.

**API-key behavior:** In the current implementation, the api parameter is optional. If supplied, it is validated; if omitted, the endpoint does not require a key. Do not assume this endpoint is private or key-protected until the code is changed to require a key.

## Requirements

- Ubuntu 22.04/24.04 or another supported Linux server. This guide uses Ubuntu 24.04.
- Python 3.11 or newer. The included Dockerfile uses Python 3.11.
- MongoDB Atlas or another reachable MongoDB deployment.
- hCaptcha site key and secret key.
- A domain name with DNS access for production.
- Nginx and an HTTPS certificate for a public VPS deployment.

Resource use depends on traffic and the size/concurrency of proxied responses. The proxy streams remote content, so monitor CPU, memory, and network usage under load.

## Configuration

The application reads these environment variables:

| Variable | Required | Description |
|---|---|---|
| MONGO_URL | Yes | MongoDB connection URI. |
| HCAPTCHA_SITEKEY | Yes | Public hCaptcha site key displayed in the browser. |
| HCAPTCHA_SECRET | Yes | Private hCaptcha secret used for server-side verification. |
| ADMIN_PASSWORD | Yes | Password checked by admin API routes and dashboard actions. |
| BASE_URL | Yes | Public base URL used to generate links, e.g. https://links.example.com. |
| PORT | No | Listening port. Defaults to 8000; hosting platforms may set it automatically. |

Example .env file:

~~~dotenv
MONGO_URL="mongodb+srv://DB_USER:DB_PASSWORD@YOUR_CLUSTER.mongodb.net/?retryWrites=true&w=majority"
HCAPTCHA_SITEKEY="your_hcaptcha_site_key"
HCAPTCHA_SECRET="your_hcaptcha_secret_key"
ADMIN_PASSWORD="replace-with-a-long-random-password"
BASE_URL="https://links.example.com"
PORT="8000"
~~~

Replace every example value with your own credentials. Do not commit .env to GitHub or share the MongoDB URI, hCaptcha secret, or admin password.

The current source contains fallback values for some settings. **Always set environment variables explicitly in production**; do not rely on source-code defaults. BASE_URL should be the public HTTPS origin without a trailing slash.

## MongoDB setup

The application uses database teamdev_proxy and the following collections:

- urls
- visits
- sessions
- blocked
- redirects
- apikeys
- config

For MongoDB Atlas:

1. Create a MongoDB cluster.
2. Create a database user with a strong password.
3. Copy the application connection string.
4. Replace the username, password, and cluster hostname.
5. In Network Access, allow the VPS public IP. Avoid allowing access from everywhere unless you understand the risk.
6. Set the URI as MONGO_URL.

The application creates collection records as needed; manual collection creation is normally unnecessary.

## hCaptcha setup

1. Create an account at https://www.hcaptcha.com/.
2. Add the domain where the application will run.
3. Copy the site key and secret key.
4. Set them as HCAPTCHA_SITEKEY and HCAPTCHA_SECRET.

The site key is public and used in the browser. Keep the secret key server-side only. The domain configured in hCaptcha must match the hostname visitors use.

## Deploy on Ubuntu 22.04 VPS (also compatible with Ubuntu 24.04)

This guide targets Ubuntu 22.04 LTS. The commands also work on Ubuntu 24.04 with the matching Python 3 package. Ubuntu 22.04 provides Python 3.10 by default, which is suitable for this project. The example values are:

- Domain: links.example.com
- Project directory: /opt/anti-bypass
- Service user: antibypass
- Application port: 8000

Replace the example domain and values with your own.

### 1. Update the server and install packages

~~~bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-venv python3-pip nginx
~~~

### 2. Create a service user and clone the repository

~~~bash
sudo adduser --system --group --home /opt/anti-bypass antibypass
sudo git clone https://github.com/Narayanpurohit/Anti-bypass-.git /opt/anti-bypass
sudo chown -R antibypass:antibypass /opt/anti-bypass
~~~

If the repository URL or default branch changes, use the current clone URL and branch shown on GitHub.

### 3. Create a virtual environment and install dependencies

~~~bash
sudo -u antibypass python3 -m venv /opt/anti-bypass/venv
sudo -u antibypass /opt/anti-bypass/venv/bin/pip install --upgrade pip
sudo -u antibypass /opt/anti-bypass/venv/bin/pip install -r /opt/anti-bypass/requirements.txt
~~~

### 4. Create the environment file

~~~bash
sudo install -o antibypass -g antibypass -m 600 /dev/null /opt/anti-bypass/.env
sudo nano /opt/anti-bypass/.env
~~~

Add your real configuration:

~~~dotenv
MONGO_URL="mongodb+srv://DB_USER:DB_PASSWORD@YOUR_CLUSTER.mongodb.net/?retryWrites=true&w=majority"
HCAPTCHA_SITEKEY="your_site_key"
HCAPTCHA_SECRET="your_secret_key"
ADMIN_PASSWORD="use-a-long-unique-password"
BASE_URL="https://links.example.com"
PORT="8000"
~~~

The application does not automatically load .env files. The systemd service below reads it using EnvironmentFile so the variables are available to Python.

### 5. Create a systemd service

~~~bash
sudo nano /etc/systemd/system/anti-bypass.service
~~~

Paste:

~~~ini
[Unit]
Description=Anti-bypass FastAPI service
After=network.target

[Service]
Type=simple
User=antibypass
Group=antibypass
WorkingDirectory=/opt/anti-bypass
EnvironmentFile=/opt/anti-bypass/.env
ExecStart=/opt/anti-bypass/venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
~~~

Enable and start the service:

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable --now anti-bypass
sudo systemctl status anti-bypass
~~~

View live logs:

~~~bash
sudo journalctl -u anti-bypass -f
~~~

### 6. Configure Nginx reverse proxy

Create a site configuration:

~~~bash
sudo nano /etc/nginx/sites-available/anti-bypass
~~~

Paste the following and replace the domain:

~~~nginx
server {
    listen 80;
    server_name links.example.com;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
        proxy_buffering off;
    }
}
~~~

Enable the site and test Nginx:

~~~bash
sudo ln -s /etc/nginx/sites-available/anti-bypass /etc/nginx/sites-enabled/anti-bypass
sudo nginx -t
sudo systemctl reload nginx
~~~

Point the domain's DNS A record to the VPS public IP. Ensure ports 80 and 443 are reachable through the server firewall and provider firewall.

### 7. Enable HTTPS

~~~bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d links.example.com
~~~

Choose the HTTPS redirect option when prompted. Confirm BASE_URL in /opt/anti-bypass/.env is the final HTTPS URL, then restart the app:

~~~bash
sudo systemctl restart anti-bypass
~~~

### 8. Verify deployment

Open these URLs:

- https://links.example.com/ — basic home response.
- https://links.example.com/health — should return {"ok":true}.
- https://links.example.com/admin — admin dashboard.

Do not expose port 8000 publicly. Nginx should be the public entry point and the application should remain bound to 127.0.0.1.

## Run with Docker

The repository includes a Dockerfile. Create a secure .env file first, then build and run:

~~~bash
docker build -t anti-bypass .
docker run -d \
  --name anti-bypass \
  --restart unless-stopped \
  --env-file .env \
  -p 127.0.0.1:8000:8000 \
  anti-bypass
~~~

The current Dockerfile starts the application with python server.py, which launches Uvicorn using the PORT environment variable (default 8000). If you change the container port, make sure PORT and the published port mapping agree.

For production, place Nginx or another trusted HTTPS reverse proxy in front of the container. Do not publish the application directly to the public internet without HTTPS and appropriate access controls.

## Deploy on Heroku

The repository already includes a root-level Procfile:

~~~procfile
web: uvicorn server:app --host 0.0.0.0 --port $PORT
~~~

Heroku uses this web process to start FastAPI and route incoming HTTP traffic. The application must listen on the port provided by Heroku through the PORT environment variable.

### Option A — Deploy from GitHub

1. Sign in to [Heroku](https://www.heroku.com/).
2. Create a new Heroku app from the Heroku Dashboard.
3. Open the app's **Deploy** tab.
4. Connect the GitHub account and select the `Narayanpurohit/Anti-bypass-` repository.
5. Select the `main` branch and deploy it.
6. Open the app's **Settings → Config Vars** and add all required variables listed in the Configuration section.
7. Set `BASE_URL` to the HTTPS URL assigned to your Heroku app, for example `https://YOUR-APP-NAME.herokuapp.com`. Confirm the exact hostname in the Heroku dashboard.
8. Trigger a redeploy after setting the configuration values, if required.
9. Open `https://YOUR-APP-NAME.herokuapp.com/health`. A healthy deployment should return `{"ok":true}`.

### Option B — Deploy using Heroku CLI

Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli) and Git, then run these commands from a local clone of the repository:

~~~bash
heroku login
heroku create YOUR-UNIQUE-APP-NAME
heroku config:set MONGO_URL="YOUR_MONGODB_URI"
heroku config:set HCAPTCHA_SITEKEY="YOUR_HCAPTCHA_SITE_KEY"
heroku config:set HCAPTCHA_SECRET="YOUR_HCAPTCHA_SECRET"
heroku config:set ADMIN_PASSWORD="YOUR_LONG_RANDOM_PASSWORD"
heroku config:set BASE_URL="https://YOUR-APP-NAME.herokuapp.com"
git push heroku main
heroku logs --tail
~~~

Replace every placeholder with a real value. If the Heroku app already exists, connect the current repository to it instead of running `heroku create`:

~~~bash
heroku git:remote -a YOUR-APP-NAME
git push heroku main
~~~

After deployment, verify:

~~~bash
heroku open
heroku logs --tail
~~~

The app's `BASE_URL` must match its actual public HTTPS hostname. If you add a custom domain later, update `BASE_URL` and register that hostname in hCaptcha.

**Heroku notes:**

- Keep `Procfile` in the repository root with the exact filename and no extension.
- Keep `requirements.txt` in the repository root so the Python build process can install dependencies.
- Do not upload a local `.env` file or commit secrets. Use Heroku Config Vars.
- The included `app.json` is a Heroku-style manifest, but review all sample/default values before using any one-click deployment flow.
- Heroku's Git deployment documentation: https://devcenter.heroku.com/articles/git
- Heroku Python deployment guide: https://devcenter.heroku.com/articles/getting-started-with-python

## Deploy on Render

Render can deploy this FastAPI application directly from the GitHub repository as a **Web Service**.

### 1. Create a Web Service

1. Sign in to [Render](https://render.com/).
2. Click **New → Web Service**.
3. Connect your GitHub account if it is not connected already.
4. Select the `Narayanpurohit/Anti-bypass-` repository.
5. Select the `main` branch.

### 2. Configure the service

Use these settings:

| Setting | Value |
|---|---|
| Name | `anti-bypass` (or your preferred service name) |
| Runtime / Language | Python 3 |
| Branch | `main` |
| Root Directory | Leave blank |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn server:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/health` |

Choose a suitable instance plan for your expected traffic. The free web service plan may spin down after a period of inactivity, so the first request after idle time can take longer to respond. Check Render's current plan limits before production use.

### 3. Add environment variables

Open the service's **Environment** tab and add:

| Key | Value |
|---|---|
| `MONGO_URL` | Your MongoDB connection URI |
| `HCAPTCHA_SITEKEY` | Your hCaptcha site key |
| `HCAPTCHA_SECRET` | Your hCaptcha secret |
| `ADMIN_PASSWORD` | A strong, unique admin password |
| `BASE_URL` | Your Render HTTPS URL, e.g. `https://YOUR-SERVICE.onrender.com` |
| `PORT` | Usually do not set manually; Render provides it |

Save the variables and let Render redeploy the service. Register the Render hostname in your hCaptcha site configuration.

### 4. Verify the deployment

When the deployment completes, open:

- `https://YOUR-SERVICE.onrender.com/`
- `https://YOUR-SERVICE.onrender.com/health`
- `https://YOUR-SERVICE.onrender.com/admin`

The health endpoint should return `{"ok":true}`.

### 5. Automatic deployments

By default, Render can automatically deploy new commits pushed to the connected branch. Push changes to `main` and monitor the service's **Events** and **Logs** tabs if a deployment fails.

**Render notes:**

- Use a **Web Service**, not a Static Site, because FastAPI runs a server.
- Do not commit `.env` or secrets. Add them through the Render Environment dashboard.
- MongoDB must be reachable from Render. Configure MongoDB Atlas network access appropriately.
- Render's free instances can spin down after inactivity; check current availability, limits, and pricing before relying on the service.
- Official guides: https://render.com/docs/deploy-fastapi and https://render.com/docs/configure-environment-variables
- Health checks: https://render.com/docs/health-checks

## API reference

The routes below are implemented by the current server.py. URL-encode query parameter values when calling the API from scripts.

### Public routes

| Method | Endpoint | Purpose |
|---|---|---|
| GET | / | Basic home response. |
| GET | /health | Health check; returns {"ok": true}. |
| GET | /token?t=TOKEN | Starts protected-content flow; token must be 62 characters. |
| POST | /api/verify | Verifies hCaptcha for /token and creates a two-hour session. |
| GET | /p?s=SESSION_ID | Validates the temporary session and redirects to the stored target URL. |
| GET | /api?url=URL&api=KEY&format=json&expiry=HOURS | Creates a /go wrapper. api is optional in the current code; if supplied, it is validated. |
| GET | /r/TOKEN | Starts redirect-wrapper flow with an 8-character token. Legacy /go?t=TOKEN links (32-character tokens) remain supported. |
| POST | /api/go-verify | Verifies hCaptcha for /go and returns the destination URL. |

### Create a wrapped link

Example request:

~~~bash
curl -G "https://links.example.com/api" \
  --data-urlencode "url=https://example.org/file" \
  --data-urlencode "api=YOUR_API_KEY" \
  --data-urlencode "format=json" \
  --data-urlencode "expiry=24"
~~~

Example success response:

~~~json
{
  "status": "success",
  "message": "",
  "shortenedUrl": "https://links.example.com/r/Ab12Cd34",
  "expiry": "24h"
}
~~~

The expiry value is expressed in hours. Use 0, permanent, or omit it for a permanent link. A positive integer such as 24 expires the generated link after that many hours.

Example error response:

~~~json
{
  "status": "error",
  "message": ["reason"],
  "shortenedUrl": ""
}
~~~

### Admin routes

Admin routes require the configured ADMIN_PASSWORD. The dashboard sends this password with its admin API requests.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /admin | Serves the admin dashboard. |
| POST | /admin/add-url | Creates an admin-managed /go link. |
| POST | /admin/delete-url | Deletes a redirect or protected URL record. |
| GET | /admin/go-links | Lists admin-created redirect links. |
| POST | /admin/toggle-url | Enables/disables a record in the urls collection. |
| GET | /admin/urls | Lists protected URLs from the urls collection. |
| GET | /admin/url-details | Returns one protected URL and its latest visit records. |
| GET | /admin/visits | Lists recent visit records; optional token and limit filters. |
| GET | /admin/stats | Returns dashboard analytics and traffic summaries. |
| POST | /admin/block-ip | Adds or updates an IP blocklist entry. |
| POST | /admin/unblock-ip | Removes an IP from the blocklist. |
| GET | /admin/blocked-ips | Lists blocked IPs. |
| GET | /admin/shortener-config | Reads external shortener configuration. |
| POST | /admin/shortener-config | Saves external shortener configuration. |
| POST | /admin/shortener-config/clear | Clears external shortener configuration. |
| POST | /admin/create-apikey | Creates an API key. |
| POST | /admin/delete-apikey | Deletes an API key. |
| POST | /admin/toggle-apikey | Activates/deactivates an API key. |
| GET | /admin/apikeys | Lists API keys and usage information. |

For GET admin requests, the password is passed as a query parameter. For POST requests, it is included in the JSON body. Protect the dashboard with HTTPS and additional network/access controls.

## Admin dashboard

Open https://links.example.com/admin and enter the configured ADMIN_PASSWORD.

Dashboard sections:

- **Overview:** summary counts and traffic analytics.
- **Protected URLs:** manage entries in the urls collection, view details, and toggle link status.
- **Go Links:** view redirect-wrapper links created from the dashboard.
- **Visits:** inspect recent request activity and block an IP.
- **Bot Logs:** review requests classified as bots or blocked.
- **Blocked IPs:** add and remove IP blocklist entries.
- **API Keys:** create, disable, enable, and delete API keys; view usage counters.
- **Settings:** configure an optional third-party shortener API.

The shortener setting expects a base API endpoint and API key. When enabled, the application calls it with api, url, and format=json parameters and expects a JSON response containing status: "success" and shortenedUrl.

## Database collections

| Collection | Purpose |
|---|---|
| urls | Protected-content link records, target URLs, CAPTCHA setting, active state, and aggregate counters. |
| visits | Request logs: IP, User-Agent, device/browser/OS, referrer, status, reason, and timestamp. |
| sessions | Temporary protected-content proxy sessions. |
| blocked | IP blocklist entries and reasons. |
| redirects | /go tokens, destination URLs, creation time, and optional expiry. |
| apikeys | API keys, labels, active state, usage count, and last-used time. |
| config | Optional external shortener configuration. |

Database name: teamdev_proxy.

## Health check and troubleshooting

### Service is not starting

~~~bash
sudo systemctl status anti-bypass
sudo journalctl -u anti-bypass -n 100 --no-pager
~~~

Check that the virtual environment exists, dependencies installed correctly, the service can access the project directory, and all required environment variables are set.

### MongoDB connection errors

- Verify MONGO_URL and database credentials.
- Confirm the VPS IP is allowed in MongoDB Atlas Network Access.
- Check that the database user has the required permissions.
- URL-encode special characters in the MongoDB password.

### CAPTCHA does not load or verification fails

- Confirm the site key and secret belong to the same hCaptcha configuration.
- Ensure the deployed hostname is registered in hCaptcha.
- Confirm the browser can load https://js.hcaptcha.com/1/api.js.
- Check server logs for outbound connectivity or hCaptcha response errors.

### Generated links use the wrong domain

Set BASE_URL to the exact public HTTPS origin (for example, https://links.example.com) and restart the service.

### Nginx returns 502 Bad Gateway

~~~bash
curl -i http://127.0.0.1:8000/health
sudo systemctl status anti-bypass
sudo nginx -t
~~~

### A visitor is rejected as a bot

The current detector rejects requests with missing or suspicious User-Agent values, short User-Agent strings, non-Mozilla prefixes, missing Accept, or missing Accept-Language. Some legitimate clients and privacy-focused browsers may also be rejected. This is heuristic filtering, not definitive bot identification.

## Security and production checklist

Before using this service with real users:

- [ ] Set unique production values for every environment variable.
- [ ] Remove/replace fallback credentials and test values in source and deployment manifests.
- [ ] Use HTTPS for all public traffic.
- [ ] Restrict MongoDB access to trusted IP addresses.
- [ ] Use a strong, unique admin password.
- [ ] Restrict access to /admin at the reverse proxy or network layer.
- [ ] Keep Uvicorn bound to localhost behind a reverse proxy.
- [ ] Make API-key enforcement mandatory in /api if the endpoint must be private. In the current code, omitting api bypasses API-key validation.
- [ ] Review trust of X-Forwarded-For. The current code trusts the first forwarded IP value; only accept forwarded headers from a trusted reverse proxy.
- [ ] Review outbound HTTP requests. The current source uses verify=False for several httpx calls, disabling TLS certificate verification. Enable certificate verification before production use.
- [ ] Add rate limiting and abuse controls for public endpoints.
- [ ] Add URL scheme, destination-domain, and SSRF protections before allowing untrusted users to submit arbitrary URLs.
- [ ] Define retention limits and privacy requirements for stored IP addresses and visit logs.
- [ ] Back up MongoDB and monitor disk, memory, CPU, and application logs.
- [ ] Test both link flows, expiry behavior, CAPTCHA failure, disabled links, and blocked IP behavior before launch.

**Privacy note:** Visit records include IP addresses and browser metadata. Inform users as appropriate, secure the database, and define a data-retention policy.

## Project structure

~~~text
Anti-bypass-/
├── server.py          # FastAPI application, routes, MongoDB logic
├── admin.html         # Browser-based admin dashboard
├── requirements.txt   # Python dependencies
├── Dockerfile         # Container build/run configuration
├── Procfile           # Procfile-based deployment command
├── app.json           # Platform deployment manifest
└── README.md          # Project documentation
~~~

## License

No license file is currently included in this repository. Unless a license is added, do not assume that the code is open for reuse, modification, or redistribution.

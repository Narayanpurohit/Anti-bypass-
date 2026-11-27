# Anti-bypass — PHP + MySQL edition

This branch contains the PHP rewrite of the original FastAPI/MongoDB project.

## Stack
- PHP 8.6 target runtime
- MySQL 8.x
- Existing admin.html dashboard
- hCaptcha
- Apache mod_rewrite, or an equivalent Nginx rewrite to index.php

## Setup
1. Create a MySQL database and user.
2. Import database/schema.sql using phpMyAdmin or the MySQL CLI.
3. Copy config.example.php to config.php and set database credentials, hCaptcha keys, admin password, and public base URL.
4. Enable PHP extensions pdo_mysql, curl, and json.
5. Upload this branch to the web root. Keep config.php private and never commit it.
6. Configure Apache to allow .htaccess overrides, or route non-file requests to index.php in Nginx.
7. Open /health and verify it returns {"ok":true}. Then open /admin.

Environment variables: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS, HCAPTCHA_SITEKEY, HCAPTCHA_SECRET, ADMIN_PASSWORD, BASE_URL, TRUSTED_PROXY_IPS, APP_DEBUG.

## Routes carried over
Public: /, /health, /token?t=..., /api/verify, /p?s=..., /api?url=..., /go?t=..., /api/go-verify.

Admin: /admin, /admin/add-url, /admin/delete-url, /admin/go-links, /admin/toggle-url, /admin/urls, /admin/url-details, /admin/visits, /admin/stats, /admin/block-ip, /admin/unblock-ip, /admin/blocked-ips, /admin/shortener-config, /admin/shortener-config/clear, /admin/create-apikey, /admin/delete-apikey, /admin/toggle-apikey, /admin/apikeys.

## MySQL tables
urls, redirects, sessions, visits, blocked, apikeys, and config are created by database/schema.sql.

This is a fresh MySQL schema. Existing MongoDB records are not automatically migrated; export/import them separately after reviewing the mapping.

## Compatibility and deployment notes
- Original route names and JSON response shapes are retained where practical.
- The original admin.html is kept unchanged.
- The proxy currently buffers upstream response data in PHP before sending it. This is not equivalent to FastAPI chunked streaming for very large files; production streaming support should be added before using it for large downloads.
- PHP 8.6 is the requested target. Confirm the hosting provider offers it with required extensions.
- Configure TRUSTED_PROXY_IPS only with trusted reverse-proxy IPs. Do not trust arbitrary X-Forwarded-For headers.
- Destination URLs are checked for HTTP(S) and private/local IP targets, but production SSRF controls should validate every redirect hop and account for DNS rebinding.
- TLS certificate verification is enabled for outbound cURL requests.
- Protect MySQL credentials and secrets. Consider hashing API keys and encrypting shortener credentials in a later hardening pass.
- Set a strong unique admin password. Keep config.php out of Git.
- This conversion has not yet been deployed against your hosting environment or tested with live credentials. Run the checklist below before switching production traffic.

## Initial test checklist
- [ ] /health returns {"ok":true}.
- [ ] Admin dashboard loads and login works.
- [ ] URL records can be inserted into urls and /token works.
- [ ] hCaptcha success and failure paths work.
- [ ] CAPTCHA-disabled URL creates a two-hour session.
- [ ] /p fetches and renders an HTML destination.
- [ ] /api creates permanent and expiring redirect links.
- [ ] /go and /api/go-verify complete a redirect.
- [ ] Admin URL, visits, blocked IP, shortener, API-key, and analytics actions work.

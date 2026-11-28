# Anti-bypass — PHP + MySQL edition

PHP 8.6-targeted rewrite of the original Anti-Bypass application, using one MySQL database with three logical table groups.

## First-time installation
1. Upload this branch to a PHP 8.6 web root.
2. Ensure PHP extensions `pdo_mysql`, `curl`, `openssl`, and `json` are enabled.
3. Create an empty MySQL database and a database user with table creation privileges.
4. Open the website root. It redirects to `/install` when no installation is present.
5. Enter MySQL host, port, database name, username and password.
6. Create the first Super Admin username, email and password (minimum 12 characters).
7. The installer creates the schema, writes a private `config.php`, creates an installation lock, then redirects to the homepage.

The installer is locked after successful setup. Do not delete `.installed` or expose `config.php`. Apache rules deny direct requests to both files. For Nginx, add equivalent deny rules.

Set a strong server environment variable `APP_ENCRYPTION_KEY` (at least 32 characters) before configuring a user's shortener API credential. It is used for AES-256-GCM encryption at rest. Also configure `HCAPTCHA_SITEKEY` and `HCAPTCHA_SECRET` through the server environment/configuration before enabling CAPTCHA-protected links.

## Implemented portal foundation
- Public homepage with Login and Sign Up actions; signed-in visitors see Dashboard instead.
- Login with username or email and password.
- Sign Up page displays the temporary registration pause notice.
- Initial Super Admin is created by the installer.
- Super Admin can create Normal User accounts from Admin Dashboard.
- Common User Dashboard with per-user link, click, verified and CAPTCHA-failed statistic tiles.
- Super Admin-only switch to Admin Dashboard.
- User settings include read-only username/email, theme, timezone, shortener domain and encrypted shortener API credential.
- Users can change their own password and manage their own API keys.
- One database with identity/user tables, global website settings, and link/analytics tables.

## Database groups
- **User data:** `users`, `user_settings`, `sessions`, `apikeys`
- **Website settings:** `site_settings`, legacy global `config`
- **Links data:** `urls`, `redirects`, `visits`, `blocked`

The schema is intended for a fresh install. Existing installations need a reviewed migration before applying it; do not run it blindly over a production database.

## Existing Anti-Bypass routes
Public: `/health`, `/token?t=...`, `/api/verify`, `/p?s=...`, `/api?url=...`, `/go?t=...`, `/api/go-verify`.

Legacy admin API routes remain in `index.php` for compatibility and still require the legacy admin credential. The new portal admin dashboard is role-protected and is separate from the legacy `admin.html` interface.

## Important implementation notes
- Public self-registration is intentionally paused.
- The Links workspace and full advanced Admin Dashboard functions are reserved for the next phase.
- Per-user API-key-generated redirect records are associated with their owning user.
- The existing legacy URL creation/admin flows have not yet been fully converted to user ownership; complete ownership enforcement is required before opening link creation to all users.
- Shortener API credentials are encrypted using AES-256-GCM when saved through User Settings.
- This branch has not been deployed against production credentials. Run PHP lint, installer, authentication, authorization, CAPTCHA, redirect, and data-isolation tests before production use.
- Proxy responses are buffered in PHP; very large file streaming needs a separate implementation.
- SSRF protection should be further hardened against redirect-hop and DNS-rebinding scenarios before production.

## Runtime environment
- PHP 8.6 target
- MySQL 8.x / compatible MySQL server
- Apache `mod_rewrite` with `.htaccess` overrides, or equivalent Nginx rewrites to `index.php`
- PHP extensions: `pdo_mysql`, `curl`, `openssl`, `json`

# Project Context — Anti Bypass (PHP + MySQL)

> Active migration branch: main3
> Original Python/MongoDB branch: main2 (unchanged)

## Runtime
PHP 8.1+ with MySQL/MariaDB via PDO. Intended for Apache/cPanel shared hosting. No Python, FastAPI or MongoDB runtime is required.

## First-run installer
- Opening the site before config.php exists displays a two-stage setup wizard.
- Stage 1 validates MySQL host, database name, username and password.
- Stage 2 creates the first Admin account from username, email and password, with optional hCaptcha keys.
- The installer creates the SQL schema, writes config.php, assigns any unowned legacy MySQL records to the first Admin, and starts a session.
- config.php is ignored by Git and blocked by .htaccess.

## Accounts and dashboards
- Email/password authentication uses PHP sessions and password_hash/password_verify.
- The first account is role=admin.
- Public sign-up is paused. Admins create normal user accounts in Admin Dashboard → User Management.
- All users open the same dashboard UI. Admins can switch between their personal User Dashboard and platform-wide Admin Dashboard.
- Admin Dashboard provides platform statistics and user management (create, activate, suspend, delete).
- Each account owns its own links, visits, analytics, API keys, IP blocklist and shortener configuration.
- Backend endpoints enforce ownership using user_id filters. Admin scope is allowed only to Admin role.

## Main files
- index.php — setup wizard, routing, login/logout, link flows, dashboard APIs and user-management endpoints
- lib.php — PDO connection, schema installer/migration, authentication, per-user settings, visit logging and CAPTCHA helpers
- admin.html — user dashboard and admin-mode dashboard UI
- login.html — login page
- signup.html — sign-up pause page
- templates/home.html — public homepage
- install.sql — reference schema; setup wizard installs automatically
- .htaccess — rewrite rules and private-file protections

## Migration
Existing MySQL tables from the earlier PHP port are upgraded with user_id columns and assigned to the first Admin during setup. The old shared shortener setting is copied to the initial Admin's personal settings. Existing MongoDB records are not migrated automatically.

## Validation status
Code has been committed to main3. It has not yet been installed on a live shared host or tested with real MySQL/hCaptcha credentials. Run PHP lint and end-to-end tests on the target hosting before using it in production.

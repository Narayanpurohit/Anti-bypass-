# Anti Bypass — PHP + MySQL multi-user build

## Requirements
- PHP 8.1 or newer
- MySQL 5.7+/MariaDB with permission to create and alter tables
- PHP extensions: PDO MySQL, cURL, OpenSSL
- Apache with mod_rewrite (typical cPanel shared hosting)

## First-time installation
1. Upload the contents of this branch to your hosting account's public_html folder.
2. In cPanel, create a MySQL database and a database user, then grant that user all privileges on the database.
3. Open your domain over HTTPS. The first-run setup wizard will appear.
4. Enter the database host, database name, username and password, then select **Test Database & Continue**.
5. Enter the first administrator username, email and password, and optionally your hCaptcha site/secret keys, then select **Create Admin & Finish Setup**.
6. The installer creates the required MySQL tables, writes the protected config.php file, creates the first Admin account and signs that account in. You will be redirected to the homepage.

The installer creates the schema automatically. Do not import install.sql separately on a fresh installation. The application folder must be writable by PHP during first setup so it can create config.php; after setup, keep config.php private and do not make it publicly readable.

## Accounts and dashboards
- The first account created by the setup wizard is the Admin.
- Sign up is intentionally paused; Admin can create user accounts from Admin Dashboard → User Management.
- All accounts use the same login page.
- Every user has their own links, visits, analytics, API keys, IP blocklist and shortener settings.
- Admins can switch between their own User Dashboard and the platform-wide Admin Dashboard.
- Admin Dashboard includes global usage statistics and user management (create, suspend, activate and delete users).
- User ownership is enforced by server-side database queries, not just by hiding UI elements.

## Existing data
When the wizard is run against an earlier Anti Bypass MySQL schema, it attempts to add user ownership columns and assign unowned legacy rows to the first Admin. Existing MongoDB data is not imported automatically; migrate it separately before switching production traffic.

## Security notes
Use HTTPS. Choose a unique administrator password of at least 10 characters. If you leave the optional hCaptcha keys blank, CAPTCHA-protected links will not verify until you add valid keys to config.php. Do not commit config.php to GitHub.

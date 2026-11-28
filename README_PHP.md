# Anti Bypass — PHP + MySQL

Shared-hosting port. Requires PHP 8.1+, MySQL/MariaDB, PDO MySQL, cURL, OpenSSL and Apache mod_rewrite.

## Install
1. Upload files to public_html.
2. Create a MySQL database and user in cPanel and grant all privileges.
3. Import install.sql using phpMyAdmin.
4. Copy config.example.php to config.php and enter DB credentials, BASE_URL, a strong ADMIN_PASSWORD and hCaptcha keys.
5. Open /health and /admin over HTTPS.

Routes retained: homepage, admin dashboard, health, protected token flow, short redirect flow, short-link API, analytics, IP blocklist, API keys and shortener settings.

Existing MongoDB data is not migrated automatically. Export/import it separately before moving production traffic. The current single-admin password model is retained; multi-user accounts and per-user isolation are a separate feature. Test on hosting before replacing the live deployment.

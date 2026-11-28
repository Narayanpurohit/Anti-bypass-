# Project Context — Anti Bypass (PHP/MySQL)

> PHP shared-hosting conversion branch: main3
> Original branch: main2 (unchanged)

## Runtime
The main3 branch is a PHP 8.1+ application using MySQL/MariaDB through PDO. It is designed for common cPanel/Apache shared hosting and does not require Python, FastAPI, MongoDB, Node.js, Docker, or a background worker.

## Files
- index.php — request router, protected-link flow, CAPTCHA verification, redirect flow, shortener API, admin APIs and analytics
- config.example.php — sample database credentials, admin password, hCaptcha keys and public base URL
- install.sql — tables for URLs, redirects, visits, temporary sessions, blocked IPs, API keys and settings
- .htaccess — rewrite rules and protection for configuration and SQL files
- admin.html — existing admin dashboard frontend
- templates/home.html — public landing page
- README.md — shared-hosting setup instructions

## Install
1. Upload files to public_html.
2. Create a MySQL database and user in cPanel and grant database privileges.
3. Import install.sql using phpMyAdmin.
4. Copy config.example.php to config.php and enter hosting credentials.
5. Set a strong admin password, hCaptcha secret/site key and HTTPS BASE_URL.
6. Verify /health, then test /admin, link generation, CAPTCHA, redirects and analytics.

## Data migration
The SQL schema is new and does not import existing MongoDB records. Export and map MongoDB documents into the corresponding SQL tables before moving production traffic. Do not delete or overwrite the old main2 deployment during testing.

## Scope and limitations
The existing single-admin password flow is preserved to keep the current dashboard compatible. Public user registration, multiple user roles and per-user data isolation have not been implemented in this PHP conversion because those product decisions were not confirmed in the preceding discussion.

The conversion has not yet been deployed to the user's shared host or exercised against their MySQL/hCaptcha credentials. Treat it as a migration build pending syntax checks and end-to-end hosting tests.

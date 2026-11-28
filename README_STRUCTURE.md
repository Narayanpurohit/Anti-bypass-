# PHP Project Structure

- index.php — PHP router, application logic, APIs and redirects
- config.example.php — sample MySQL, hCaptcha and admin settings; copy to config.php
- install.sql — MySQL schema
- .htaccess — Apache route rewriting and config-file protection
- admin.html — existing admin dashboard
- templates/home.html — public homepage
- README.md — shared-hosting installation instructions

Runtime: PHP 8.1+, MySQL/MariaDB, PDO MySQL, cURL and Apache mod_rewrite. No Python or MongoDB runtime is required.

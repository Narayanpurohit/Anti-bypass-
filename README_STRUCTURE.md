# Project Structure

- index.php — first-run wizard, routing, login/session endpoints, protected links and application APIs
- lib.php — schema installer, authentication helpers, per-user settings, analytics and CAPTCHA helpers
- config.php — generated privately by the first-run wizard; contains database credentials and site settings
- .htaccess — URL rewriting and protection for private PHP/config/SQL files
- admin.html — shared user dashboard and role-aware Admin Dashboard
- login.html — email/password login page
- signup.html — temporary sign-up pause message
- templates/home.html — public product homepage
- install.sql — legacy schema reference; fresh installs create tables through the setup wizard

No Python, FastAPI or MongoDB runtime is required.

"""Environment-based application settings. Never commit production credentials."""
import os
from dotenv import load_dotenv

# Load values from the project-root .env file when present; existing VPS
# environment variables take precedence over values in the file.
load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET", "")
HCAPTCHA_SITEKEY = os.getenv("HCAPTCHA_SITEKEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
PORT = int(os.getenv("PORT", "8000"))

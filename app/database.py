"""MongoDB client and collection handles."""
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import MONGO_URL

mongo_client = AsyncIOMotorClient(MONGO_URL)
db = mongo_client["teamdev_proxy"]
urls_col = db["urls"]
visits_col = db["visits"]
sess_col = db["sessions"]
block_col = db["blocked"]
redir_col = db["redirects"]
apikey_col = db["apikeys"]
config_col = db["config"]

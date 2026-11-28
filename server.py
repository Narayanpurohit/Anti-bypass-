"""Compatibility entry point for existing deployments using server:app."""
from app.main import app
from app.config import PORT

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)

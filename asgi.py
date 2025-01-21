import os
from app import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("asgi:app", host="0.0.0.0", port=port, log_level="info")

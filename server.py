import os
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
from app import app

async def main():
    port = int(os.environ.get('PORT', 10000))
    config = Config()
    config.bind = [f"0.0.0.0:{port}"]
    config.use_reloader = False
    await serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())

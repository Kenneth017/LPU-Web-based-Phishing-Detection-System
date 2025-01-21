import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
from app import app
import os

config = Config()
config.bind = [f"0.0.0.0:{int(os.environ.get('PORT', 10000))}"]

async def main():
    await serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())

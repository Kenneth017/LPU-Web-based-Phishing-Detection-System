from hypercorn.config import Config
from hypercorn.asyncio import serve
import asyncio
import os
from app import app

config = Config()
config.bind = [f"0.0.0.0:{int(os.environ.get('PORT', 10000))}"]
config.workers = 4

def run_app():
    asyncio.run(serve(app, config))

if __name__ == "__main__":
    run_app()

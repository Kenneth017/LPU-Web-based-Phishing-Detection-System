from app import app
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
from utils import setup_logger
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logger = setup_logger(__name__)

def run_app():
    config = Config()
    config.bind = [f"0.0.0.0:{int(os.environ.get('PORT', 10000))}"]
    asyncio.run(serve(app, config))

if __name__ == "__main__":
    run_app()

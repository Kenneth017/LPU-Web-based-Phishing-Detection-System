from app import app as application
from utils import setup_logger
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logger = setup_logger(__name__)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    application.run(host='0.0.0.0', port=port)

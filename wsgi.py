from app import app as application
from utils import setup_logger

# Set up logging for the application
logger = setup_logger(__name__)

if __name__ == "__main__":
    application.run()
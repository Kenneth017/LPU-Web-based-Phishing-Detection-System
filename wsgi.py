from app import app as application
from utils import setup_logger
from ml_metrics import add_confidence_score_column
import sqlite3

# Set up logging
logger = setup_logger(__name__)

# Initialize database connection
def get_db_connection():
    conn = sqlite3.connect('phishing_history.db')
    conn.row_factory = sqlite3.Row
    return conn

# Add confidence score column
add_confidence_score_column(get_db_connection())

if __name__ == "__main__":
    application.run()

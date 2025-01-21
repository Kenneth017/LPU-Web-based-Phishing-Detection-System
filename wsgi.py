from app import app as application
from app import init_db, ensure_db_directory, migrate_database

# Initialize database on startup
ensure_db_directory()
init_db()
migrate_database()

if __name__ == "__main__":
    application.run()
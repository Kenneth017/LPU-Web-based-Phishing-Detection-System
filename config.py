import os

# Server settings
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 10000))
WORKERS = int(os.getenv('WEB_CONCURRENCY', 4))

# App settings
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

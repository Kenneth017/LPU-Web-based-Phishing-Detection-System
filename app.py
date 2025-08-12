from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dotenv import load_dotenv
from email import policy
from email import policy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from email_analysis_ml import EmailPhishingDetector
from feedback_handler import FeedbackHandler
from functools import wraps
from io import StringIO
from itsdangerous import URLSafeTimedSerializer
from ml_api import analyze_input 
from ml_metrics import MLMetricsAnalyzer
from quart import Quart, render_template, request, url_for, jsonify, make_response, redirect, session, flash, current_app
from quart import request, flash, redirect, url_for, render_template
from quart import request, jsonify
from quart import websocket
from urllib.parse import urlparse
from utils import setup_logger
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import asyncio
import asyncio
import csv
import datetime as dt
import extract_msg
import extract_msg
import hashlib
import json
import os
import pytz
import re
import smtplib
import sqlite3
import stat
import tempfile
import time
import uuid

# Set up timezone
singapore_tz = pytz.timezone('Asia/Singapore')

# Determine the database path
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    DB_PATH = '/opt/render/project/src/instance/phishing_history.db'
    print(f"Running on Render. Using database path: {DB_PATH}")
else:
    DB_PATH = 'phishing_history.db'
    print(f"Running locally. Using database path: {DB_PATH}")

print(f"Checking database path: {DB_PATH}")
if os.path.exists(os.path.dirname(DB_PATH)):
    print(f"Path exists: {os.path.dirname(DB_PATH)}")
    if os.access(os.path.dirname(DB_PATH), os.W_OK):
        print(f"Path is writable: {os.path.dirname(DB_PATH)}")
    else:
        print(f"Path is not writable: {os.path.dirname(DB_PATH)}")
else:
    print(f"Path does not exist: {os.path.dirname(DB_PATH)}")

def get_singapore_time():
    """Get current time in Singapore timezone (GMT+8)"""
    return datetime.now(singapore_tz).strftime('%Y-%m-%d %H:%M:%S')

# Load environment variables
load_dotenv()

app = Quart(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY')

# CORS setup
@app.after_request
async def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/options', methods=['OPTIONS'])
async def handle_options():
    return '', 204

# Set up logger
logger = setup_logger(__name__)

def cleanup_stale_sessions():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        current_time = datetime.now().isoformat()
        
        # Clear expired sessions
        c.execute("""
            UPDATE users 
            SET session_token = NULL, session_expiry = NULL 
            WHERE session_expiry < ?
        """, (current_time,))
        
        conn.commit()
        conn.close()
        logger.info("Cleaned up stale sessions")
    except Exception as e:
        logger.error(f"Error cleaning up stale sessions: {e}")

@app.before_serving
async def startup():
    cleanup_stale_sessions()  # Clean up stale sessions on startup
    await initialize_db_if_needed()

def convert_to_local_time(timestamp_str):
    """Convert UTC timestamp to GMT+8"""
    try:
        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        dt = pytz.UTC.localize(dt)
        local_dt = dt.astimezone(singapore_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        logger.error(f"Error converting timestamp: {str(e)}")
        return timestamp_str

def ensure_db_directory():
    db_dir = os.path.dirname(DB_PATH)
    print(f"Attempting to create directory: {db_dir}")
    try:
        os.makedirs(db_dir, exist_ok=True)
        print(f"Directory created or already exists: {db_dir}")
        # Check if the directory is writable
        test_file = os.path.join(db_dir, 'test_write.txt')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print(f"Directory is writable: {db_dir}")
        except Exception as e:
            print(f"Directory is not writable: {db_dir}. Error: {str(e)}")
    except Exception as e:
        print(f"Error creating directory {db_dir}: {str(e)}")

def get_db_connection():
    try:
        print(f"Attempting to connect to database at: {DB_PATH}")
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This line is important
        print(f"Successfully connected to database at: {DB_PATH}")
        return conn
    except sqlite3.Error as e:
        print(f"SQLite error in get_db_connection: {str(e)}")
        raise
    except Exception as e:
        print(f"Unexpected error in get_db_connection: {str(e)}")
        raise

async def initialize_db_if_needed():
    if not os.path.exists(DB_PATH):
        logger.info("Database does not exist. Initializing...")
        try:
            init_db()
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")

@app.before_serving
async def startup():
    await initialize_db_if_needed()

def init_db():
    try:
        print(f"Starting database initialization. DB_PATH: {DB_PATH}")
        
        # Check directory permissions
        db_dir = os.path.dirname(DB_PATH)
        print(f"Database directory: {db_dir}")
        
        if os.path.exists(db_dir):
            print(f"Directory exists: {db_dir}")
            try:
                # Check directory permissions
                dir_stat = os.stat(db_dir)
                print(f"Directory permissions: {stat.filemode(dir_stat.st_mode)}")
                print(f"Directory owner: {dir_stat.st_uid}, group: {dir_stat.st_gid}")
            except Exception as e:
                print(f"Could not check directory permissions: {e}")
            
            # Check if we can list the directory contents
            try:
                os.listdir(db_dir)
                print(f"Can list directory contents: {db_dir}")
            except PermissionError:
                print(f"Cannot list directory contents: {db_dir}")
        else:
            print(f"Directory does not exist: {db_dir}")
            try:
                os.makedirs(db_dir, exist_ok=True)
                print(f"Created directory: {db_dir}")
            except PermissionError:
                print(f"Cannot create directory: {db_dir}")
        
        # Attempt to open the database file
        print(f"Attempting to open database file: {DB_PATH}")
        conn = sqlite3.connect(DB_PATH)
        print("Successfully opened database connection")
        
        c = conn.cursor()

        print("Creating users table if it doesn't exist")
        c.execute('''
        CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE NOT NULL,
         email TEXT UNIQUE,
         password TEXT NOT NULL,
         is_admin BOOLEAN NOT NULL DEFAULT 0,
         email_verified BOOLEAN DEFAULT 0,
         session_token TEXT)
        ''')
        print("Users table created or already exists")

        # Add the user_activity_log table creation here
        print("Creating user_activity_log table if it doesn't exist")
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("User activity log table created or already exists")

        # Check if columns exist, if not add them
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'email_verified' not in columns:
            try:
                c.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0")
                print("Added email_verified column to users table")
            except Exception as e:
                print(f"Error adding email_verified column: {e}")
        
        if 'session_token' not in columns:
            try:
                c.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
                print("Added session_token column to users table")
            except Exception as e:
                print(f"Error adding session_token column: {e}")
                
        if 'session_expiry' not in columns:
            try:
                c.execute("ALTER TABLE users ADD COLUMN session_expiry TEXT")
                print("Added session_expiry column to users table")
            except Exception as e:
                print(f"Error adding session_expiry column: {e}")

        # Create or modify analysis_history table
        c.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_string TEXT NOT NULL,
            input_type TEXT NOT NULL,
            is_malicious INTEGER NOT NULL,
            main_verdict TEXT NOT NULL,
            community_score TEXT,
            metadata TEXT,
            vendor_analysis TEXT,
            user_id INTEGER,
            analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            confidence_score REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Check if new columns exist in analysis_history, if not add them
        c.execute("PRAGMA table_info(analysis_history)")
        columns = [column[1] for column in c.fetchall()]
        
        # Add new columns if they don't exist
        if 'timezone' not in columns:
            c.execute("ALTER TABLE analysis_history ADD COLUMN timezone TEXT DEFAULT 'UTC'")
        
        if 'response_time' not in columns:
            c.execute("ALTER TABLE analysis_history ADD COLUMN response_time REAL")
        
        if 'last_checked' not in columns:
            c.execute("ALTER TABLE analysis_history ADD COLUMN last_checked DATETIME")
        
        if 'status_code' not in columns:
            c.execute("ALTER TABLE analysis_history ADD COLUMN status_code INTEGER")

        # Create indexes for analysis_history
        c.execute('CREATE INDEX IF NOT EXISTS idx_analysis_date ON analysis_history(analysis_date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_main_verdict ON analysis_history(main_verdict)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_input_string ON analysis_history(input_string)')
        
        # Only create last_checked index if the column exists
        try:
            c.execute('CREATE INDEX IF NOT EXISTS idx_last_checked ON analysis_history(last_checked)')
        except sqlite3.OperationalError as e:
            print(f"Note: Could not create last_checked index: {e}")
        
        # Set timezone to Asia/Singapore (GMT+8)
        c.execute("PRAGMA timezone = 'Asia/Singapore'")

        # Handle user_feedback table
        try:
            c.execute("PRAGMA table_info(user_feedback)")
            columns = [column[1] for column in c.fetchall()]
            
            if 'url' in columns and 'input_string' not in columns:
                print("Migrating user_feedback table...")
                c.execute('''
                    CREATE TABLE user_feedback_new
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     feedback_type TEXT,
                     input_string TEXT,
                     message TEXT,
                     submission_date DATETIME,
                     FOREIGN KEY (user_id) REFERENCES users(id))
                ''')
                
                c.execute('''
                    INSERT INTO user_feedback_new (id, user_id, feedback_type, input_string, message, submission_date)
                    SELECT id, user_id, feedback_type, url, message, submission_date FROM user_feedback
                ''')
                
                c.execute('DROP TABLE user_feedback')
                c.execute('ALTER TABLE user_feedback_new RENAME TO user_feedback')
                print("Migration completed successfully")
            else:
                c.execute('''
                    CREATE TABLE IF NOT EXISTS user_feedback
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     feedback_type TEXT,
                     input_string TEXT,
                     message TEXT,
                     submission_date DATETIME,
                     FOREIGN KEY (user_id) REFERENCES users(id))
                ''')
        except Exception as e:
            print(f"Error during migration: {e}")
            c.execute('''
                CREATE TABLE IF NOT EXISTS user_feedback
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 feedback_type TEXT,
                 input_string TEXT,
                 message TEXT,
                 submission_date DATETIME,
                 FOREIGN KEY (user_id) REFERENCES users(id))
            ''')

        # Add or update admin user with environment variables
        admin_username = os.getenv('ADMIN_DEFAULT_USERNAME')
        admin_email = os.getenv('ADMIN_DEFAULT_EMAIL')
        admin_password = os.getenv('ADMIN_DEFAULT_PASSWORD')
    
        if not all([admin_username, admin_email, admin_password]):
            print("Warning: Admin credentials not fully set in environment variables.")
            logger.warning("Admin credentials not fully set in environment variables.")
        else:
            try:
                # Check for existing admin user
                c.execute("SELECT id, username, email FROM users WHERE username = ?", (admin_username,))
                admin_user = c.fetchone()
                
                if admin_user is None:
                    # Create new admin user
                    hashed_password = generate_password_hash(admin_password)
                    c.execute("""
                        INSERT INTO users 
                        (username, email, password, is_admin, session_token, session_expiry, email_verified) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (admin_username, admin_email, hashed_password, True, None, None, True))
                    print(f"Admin user '{admin_username}' created successfully.")
                else:
                    # Update existing admin user
                    hashed_password = generate_password_hash(admin_password)
                    c.execute("""
                        UPDATE users 
                        SET email = ?,
                            password = ?,
                            is_admin = 1,
                            email_verified = 1
                        WHERE id = ?
                    """, (admin_email, hashed_password, admin_user[0]))
                    print(f"Admin user '{admin_username}' updated with new credentials.")
            except Exception as e:
                print(f"Error managing admin user: {e}")
                logger.error(f"Error managing admin user: {e}")

        # Add main_verdict column to analysis_history if it doesn't exist
        c.execute("PRAGMA table_info(analysis_history)")
        columns = [column[1] for column in c.fetchall()]
        if 'main_verdict' not in columns:
            c.execute("ALTER TABLE analysis_history ADD COLUMN main_verdict TEXT NOT NULL DEFAULT 'unknown'")
            print("Added main_verdict column to analysis_history table")

        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_analysis_date ON analysis_history(analysis_date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_main_verdict ON analysis_history(main_verdict)')
        print("Created indexes on analysis_history table")

        conn.commit()
        conn.close()
        print("Database initialized successfully")
        
    except sqlite3.Error as e:
        print(f"SQLite error in init_db: {str(e)}")
        logger.error(f"SQLite error in init_db: {str(e)}")
        raise
    except Exception as e:
        print(f"Unexpected error in init_db: {str(e)}")
        logger.error(f"Unexpected error in init_db: {str(e)}")
        raise

def update_admin_username():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET username = 'admin' WHERE username = 'admin Admin'")
    affected_rows = c.rowcount
    conn.commit()
    conn.close()
    if affected_rows > 0:
        print("Admin username updated.")
    else:
        print("No admin username update needed.")

# Call init_db when your app starts
init_db()
update_admin_username()

def migrate_database():
    conn = get_db_connection()
    c = conn.cursor()

    try:
        # Check if users table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if c.fetchone() is None:
            # If users table doesn't exist, run init_db to create it
            init_db()
            return

        # Check for and add missing columns
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'email_verified' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0")
            print("Added email_verified column to users table")
        
        if 'session_token' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN session_token TEXT")
            print("Added session_token column to users table")

        conn.commit()
        print("Database migration completed successfully")
    except Exception as e:
        print(f"Error during database migration: {e}")
    finally:
        conn.close()

# Call migrate_database at app startup
migrate_database()

def login_required(func):
    @wraps(func)
    async def decorated_view(*args, **kwargs):
        if 'user_id' not in session or 'session_token' not in session:
            return redirect(url_for('login', next=request.url))
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT session_token, session_expiry FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            conn.close()
            
            if not user or user['session_token'] != session['session_token'] or \
               datetime.now() > datetime.fromisoformat(user['session_expiry']):
                # Session is invalid or expired, clear it
                session.clear()
                await flash('Your session has expired or been invalidated. Please login again.', 'error')
                return redirect(url_for('login', next=request.url))
            
            # If session is valid, extend its expiry time
            new_expiry = datetime.now() + dt.timedelta(days=1)  # Use dt.timedelta here
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE users SET session_expiry = ? WHERE id = ?", 
                     (new_expiry.isoformat(), session['user_id']))
            conn.commit()
            conn.close()
            
            session['session_expiry'] = new_expiry.isoformat()
                
        except Exception as e:
            logger.error(f"Error checking session token: {str(e)}")
            session.clear()
            await flash('An error occurred. Please login again.', 'error')
            return redirect(url_for('login', next=request.url))
            
        return await func(*args, **kwargs)
    return decorated_view

def log_user_activity(username, action):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO user_activity_log (username, action, timestamp)
            VALUES (?, ?, ?)
        """, (username, action, get_singapore_time()))
        conn.commit()
        conn.close()
        logger.info(f"Logged user activity: {username} - {action}")
    except Exception as e:
        logger.error(f"Error logging user activity: {str(e)}")

@app.route('/admin_dashboard')
@login_required
async def admin_dashboard():
    if not session.get('is_admin'):
        await flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Get date 90 days ago
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')

        # Get login/logout activity for last 90 days
        c.execute("""
            SELECT username, action, timestamp
            FROM user_activity_log
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        """, (ninety_days_ago,))
        activity_log = c.fetchall()

        # Get analysis metrics for last 90 days
        c.execute("""
            SELECT 
                COUNT(*) as total_analyses,
                SUM(CASE WHEN main_verdict = 'phishing' THEN 1 ELSE 0 END) as phishing_count,
                SUM(CASE WHEN main_verdict = 'malicious' THEN 1 ELSE 0 END) as malicious_count,
                SUM(CASE WHEN main_verdict = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
                SUM(CASE WHEN main_verdict = 'safe' THEN 1 ELSE 0 END) as safe_count
            FROM analysis_history
            WHERE analysis_date >= ?
        """, (ninety_days_ago,))
        metrics = c.fetchone()

        # Get recent analysis activities for last 90 days
        c.execute("""
            SELECT 
                ah.input_string,
                ah.main_verdict,
                ah.analysis_date,
                u.username
            FROM analysis_history ah
            JOIN users u ON ah.user_id = u.id
            WHERE ah.analysis_date >= ?
            ORDER BY ah.analysis_date DESC
        """, (ninety_days_ago,))
        all_analysis_activities = c.fetchall()

        conn.close()

        # Calculate detection rates
        total_analyses = metrics['total_analyses'] or 1  # Avoid division by zero
        detection_rates = {
            'safe_rate': (metrics['safe_count'] / total_analyses) * 100,
            'phishing_rate': (metrics['phishing_count'] / total_analyses) * 100,
            'malicious_rate': (metrics['malicious_count'] / total_analyses) * 100,
            'suspicious_rate': (metrics['suspicious_count'] / total_analyses) * 100
        }

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 25
        total = len(all_analysis_activities)
        
        # Calculate start and end indices for the current page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get activities for current page
        analysis_activities = all_analysis_activities[start_idx:end_idx]
        
        # Calculate total pages
        total_pages = (total + per_page - 1) // per_page

        return await render_template(
            'admin_dashboard.html',
            activity_log=activity_log,
            metrics=metrics,
            detection_rates=detection_rates,
            analysis_activities=analysis_activities,
            current_page=page,
            total_pages=total_pages,
            total_items=total,
            per_page=per_page,
            start_idx=start_idx + 1,
            end_idx=min(start_idx + per_page, total)
        )

    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        await flash('An error occurred while loading the admin dashboard.', 'error')
        return redirect(url_for('home'))

@app.route('/export_logs')
@login_required
async def export_logs():
    if not session.get('is_admin'):
        await flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Get date 90 days ago
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')

        # Get all logs for last 90 days
        c.execute("""
            SELECT username, action, timestamp
            FROM user_activity_log
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        """, (ninety_days_ago,))
        activity_log = c.fetchall()

        c.execute("""
            SELECT 
                u.username,
                ah.input_string,
                ah.main_verdict,
                ah.analysis_date
            FROM analysis_history ah
            JOIN users u ON ah.user_id = u.id
            WHERE ah.analysis_date >= ?
            ORDER BY ah.analysis_date DESC
        """, (ninety_days_ago,))
        analysis_activities = c.fetchall()

        conn.close()

        # Create CSV file
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Log Type', 'Username', 'Action/Input', 'Verdict', 'Timestamp'])
        
        for log in activity_log:
            cw.writerow(['Activity', log['username'], log['action'], '', log['timestamp']])
        
        for activity in analysis_activities:
            cw.writerow(['Analysis', activity['username'], activity['input_string'], activity['main_verdict'], activity['analysis_date']])

        output = await make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    except Exception as e:
        logger.error(f"Error exporting logs: {str(e)}")
        await flash('An error occurred while exporting logs.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'])
async def register():
    if request.method == 'POST':
        form = await request.form
        username = form.get('username')
        email = form.get('email')
        password = form.get('password')
        confirm_password = form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            await flash('All fields are required.', 'error')
            return await render_template('register.html')

        if password != confirm_password:
            await flash('Passwords do not match.', 'error')
            return await render_template('register.html')

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if c.fetchone():
                await flash('Username or email already exists.', 'error')
                return await render_template('register.html')

            hashed_password = generate_password_hash(password)
            c.execute("""
                INSERT INTO users (username, email, password, is_admin, email_verified) 
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_password, False, False))
            conn.commit()

            # Send verification email
            token = serializer.dumps(email, salt='email-verification-salt')
            verification_url = url_for('verify_email', token=token, _external=True)
            
            subject = 'Verify your email for Phishing Detection System'
            html_content = f"""
            <html>
                <body>
                    <h2>Welcome to Phishing Detection System</h2>
                    <p>Please click the link below to verify your email:</p>
                    <a href="{verification_url}">Verify Email</a>
                </body>
            </html>
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = os.getenv('APP_EMAIL')
            msg['To'] = email
            msg.attach(MIMEText(html_content, 'html'))

            await send_email_async(
                os.getenv('APP_EMAIL'),
                email,
                os.getenv('APP_EMAIL_PASSWORD'),
                msg
            )

            await flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            await flash('An error occurred during registration.', 'error')
        finally:
            conn.close()

    return await render_template('register.html')

@app.route('/extend_session', methods=['POST'])
@login_required
async def extend_session():
    try:
        new_expiry = datetime.now() + timedelta(days=1)
        session['session_expiry'] = new_expiry.isoformat()
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET session_expiry = ? WHERE id = ?", 
                 (new_expiry.isoformat(), session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error extending session: {str(e)}")
        return jsonify({'success': False})



@app.route('/force_logout/<int:user_id>', methods=['POST'])
@login_required
async def force_logout(user_id):
    if not session.get('is_admin'):
        await flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))
        
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET session_token = NULL, session_expiry = NULL WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        # If the logged-out user is the current user, clear their session
        if user_id == session.get('user_id'):
            session.clear()
            return jsonify({'success': True, 'redirect': url_for('login')})
        else:
            await flash('User has been logged out from all devices.', 'success')
            return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error during force logout: {str(e)}")
        await flash('An error occurred while logging out the user.', 'error')
        return jsonify({'success': False})

@app.route('/')
@login_required
async def home():
    user_id = session.get('user_id')
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT input_string, main_verdict, analysis_date 
            FROM analysis_history 
            WHERE user_id = ?
            ORDER BY analysis_date DESC LIMIT 5
        ''', (user_id,))
    except sqlite3.OperationalError:
        # If main_verdict doesn't exist, fall back to the old query
        c.execute('''
            SELECT input_string, is_malicious, analysis_date 
            FROM analysis_history 
            WHERE user_id = ?
            ORDER BY analysis_date DESC LIMIT 5
        ''', (user_id,))
    history = c.fetchall()
    conn.close()
    return await render_template('index.html', history=history)

def preprocess_url(url):
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Check if the URL starts with a protocol
    if not url.startswith(('http://', 'https://')):
        # Check if it starts with 'www.'
        if url.startswith('www.'):
            url = 'http://' + url
        else:
            # Add 'http://' as a default
            url = 'http://' + url
    
    # Ensure there's a path
    if '/' not in url.split('://', 1)[1]:
        url += '/'
    
    return url

def should_analyze_url(url):
    """Check if the URL should be analyzed."""
    excluded_schemes = ['chrome', 'chrome-extension', 'about', 'data', 'javascript', 'file']
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return (
            parsed.scheme not in excluded_schemes and
            not url.startswith('chrome://') and
            not url.startswith('chrome-extension://') and
            not url.startswith('about:') and
            not url.startswith('data:') and
            not url.startswith('javascript:') and
            not url.startswith('file://')
        )
    except:
        return False

@app.websocket('/ws')
async def ws():
    print("New WebSocket connection attempt")
    try:
        while True:
            try:
                print("Waiting for data...")
                data = await websocket.receive_json()
                print(f"Received data: {data}")
                
                if data.get('type') == 'ping':
                    await websocket.send_json({'type': 'pong'})
                    continue
                
                if data.get('type') == 'check_url' and 'url' in data:
                    url = data['url']
                    print(f"Processing URL: {url}")

                    # Only perform analysis if explicitly requested
                    if data.get('analyze', False):
                        user_id = data.get('user_id', 1)  # Get user_id from request, default to 1 if not provided
                        save_to_history = data.get('saveToHistory', False)  # New flag for saving to history

                        print("Analyzing input...")
                        result = await analyze_input(url)
                        print(f"Analysis result: {result}")
                        
                        # Your existing verdict calculation logic
                        verdict_priorities = {
                            'phishing': 0,
                            'malicious': 0,
                            'suspicious': 0,
                            'safe': 0
                        }
                        
                        for vendor in result['vendor_analysis']:
                            verdict = vendor['verdict'].lower()
                            if verdict == 'phishing':
                                verdict_priorities['phishing'] += 1
                            elif verdict == 'malicious':
                                verdict_priorities['malicious'] += 1
                            elif verdict == 'suspicious':
                                verdict_priorities['suspicious'] += 1
                            elif verdict in ['clean', 'harmless', 'safe']:
                                verdict_priorities['safe'] += 1
                        
                        print(f"Verdict priorities: {verdict_priorities}")
                        
                        main_verdict = 'safe'
                        if verdict_priorities['phishing'] > 0:
                            main_verdict = 'phishing'
                        elif verdict_priorities['malicious'] > 0:
                            main_verdict = 'malicious'
                        elif verdict_priorities['suspicious'] > 0:
                            main_verdict = 'suspicious'
                        
                        result['main_verdict'] = main_verdict
                        result['is_malicious'] = main_verdict != 'safe'
                        
                        print(f"Main verdict: {main_verdict}")
                        
                        # Only store in database if saveToHistory is True
                        if save_to_history:
                            print("Storing result in database...")
                            conn = get_db_connection()
                            c = conn.cursor()
                            c.execute('''
                                INSERT INTO analysis_history 
                                (input_string, input_type, is_malicious, community_score, metadata, 
                                 vendor_analysis, user_id, analysis_date, main_verdict)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                url,
                                result['input_type'],
                                int(result['is_malicious']),
                                result['community_score'],
                                json.dumps(result['metadata']),
                                json.dumps(result['vendor_analysis']),
                                user_id,
                                get_singapore_time(),
                                main_verdict
                            ))
                            conn.commit()
                            conn.close()
                            print("Result stored in database")
                        else:
                            print("Result not stored in database (automatic check)")

                        print("Sending result back to client...")
                        await websocket.send_json(result)
                        print("Result sent to client")
                    else:
                        print("URL received but analysis not requested")
                else:
                    print("Received data does not contain 'url' key or is not a check request")
                    await websocket.send_json({'error': 'Invalid data format'})
                    
            except asyncio.CancelledError:
                print("WebSocket connection cancelled")
                break
            except Exception as e:
                print(f"Error in WebSocket handler: {str(e)}")
                logger.error(f"Error in WebSocket handler: {str(e)}")
                await websocket.send_json({'error': 'An error occurred while checking the URL'})
    except Exception as e:
        print(f"WebSocket connection error: {str(e)}")
        logger.error(f"WebSocket connection error: {str(e)}")

@app.route('/feedback', methods=['GET'])
@login_required
async def feedback():
    return await render_template('feedback.html')

@app.route('/submit_feedback', methods=['POST'])
@login_required
async def submit_feedback():
    try:
        form = await request.form
        print("Received form data:", dict(form))
        
        feedback_type = form.get('feedback_type')
        input_string = form.get('input_string')
        message = form.get('message')
        user_id = session.get('user_id')
        
        # Get user's username and check for duplicates
        conn = get_db_connection()
        c = conn.cursor()
        
        # Check for recent duplicate submissions
        c.execute("""
            SELECT COUNT(*) FROM user_feedback 
            WHERE user_id = ? 
            AND feedback_type = ? 
            AND input_string = ? 
            AND message = ? 
            AND submission_date > datetime('now', '-1 minute')
        """, (user_id, feedback_type, input_string, message))
        
        recent_duplicates = c.fetchone()[0]
        if recent_duplicates > 0:
            return await make_response(jsonify({
                "success": False, 
                "message": "Duplicate submission detected. Please wait before submitting again."
            }), 429)

        # Get username
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        result = c.fetchone()
        username = result[0] if result else "Unknown User"
        
        print(f"Processed data: type={feedback_type}, input_string={input_string}, message={message}, username={username}")

        # Email configuration
        sender_email = os.getenv('APP_EMAIL', 'your-app-email@gmail.com')  
        receiver_email = os.getenv('PERSONAL_EMAIL', 'your-personal-email@gmail.com')
        password = os.getenv('APP_EMAIL_PASSWORD', 'your-app-email-password')

        subject = f"Phishing Detection System Feedback: {feedback_type}"
        
        # HTML content
        html_content = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    h1 {{ color: #4a4a4a; }}
                    .feedback-item {{ margin-bottom: 15px; }}
                    .feedback-label {{ font-weight: bold; }}
                    .feedback-value {{ margin-left: 10px; }}
                    .message-box {{ background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Phishing Detection System Feedback Received</h1>
                    <div class="feedback-item">
                        <span class="feedback-label">Feedback Type:</span>
                        <span class="feedback-value">{feedback_type}</span>
                    </div>
                    <div class="feedback-item">
                        <span class="feedback-label">Inputs:</span>
                        <span class="feedback-value">{input_string}</span>
                    </div>
                    <div class="feedback-item">
                        <span class="feedback-label">User:</span>
                        <span class="feedback-value">{username}</span>
                    </div>
                    <div class="feedback-item">
                        <span class="feedback-label">Message:</span>
                        <div class="message-box">{message}</div>
                    </div>
                </div>
            </body>
        </html>
        """

        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # Attach both plain text and HTML versions
        text_content = f"""
        Feedback Type: {feedback_type}
        Input String: {input_string}
        User: {username}
        Message:
        {message}
        """
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')

        msg.attach(part1)
        msg.attach(part2)

        # Run email sending in a separate thread
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_email, sender_email, receiver_email, password, msg)
        
        # Store feedback in database
        c.execute("""
            INSERT INTO user_feedback (user_id, feedback_type, input_string, message, submission_date)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (user_id, feedback_type, input_string, message))
        
        conn.commit()
        conn.close()

        return await make_response(jsonify({
            "success": True, 
            "message": "Feedback submitted successfully"
        }))
        
    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        return await make_response(jsonify({
            "success": False, 
            "message": "Error submitting feedback"
        }), 500)

def send_email(sender_email, receiver_email, password, msg):
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Error in send_email: {e}")
        raise

@app.route('/feedback/stats')
@login_required
async def feedback_stats():
    try:
        user_id = session.get('user_id')
        is_admin = session.get('is_admin', False)
        
        # Get user-specific stats
        user_stats = await feedback_handler.get_feedback_stats(user_id)
        
        # If admin, also get overall stats
        if is_admin:
            overall_stats = await feedback_handler.get_feedback_stats()
            return await make_response(jsonify({
                "user_stats": user_stats,
                "overall_stats": overall_stats
            }))
        
        return await make_response(jsonify(user_stats))
        
    except Exception as e:
        logger.error(f"Error getting feedback stats: {str(e)}")
        return await make_response(jsonify({
            "status": "error",
            "message": f"Error getting feedback stats: {str(e)}"
        }), 500)


@app.route('/history')
@login_required
async def history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        sort_by = request.args.get('sort', 'analysis_date')
        order = request.args.get('order', 'desc')
        filter_result = request.args.get('filter', 'all')
        type_filter = request.args.get('type', 'all')
        user_id = session.get('user_id')
        
        # Add date range filtering
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Base query
        query = """
            SELECT 
                id, 
                input_string,
                input_type,
                main_verdict,
                analysis_date,
                metadata,
                vendor_analysis
            FROM analysis_history 
            WHERE user_id = ?
        """
        params = [user_id]
        
        # Apply type filter
        if type_filter != 'all':
            query += " AND input_type = ?"
            params.append(type_filter)
        
        # Apply result filter
        if filter_result != 'all':
            query += " AND main_verdict = ?"
            params.append(filter_result)
        
        # Apply date range filter
        if date_from:
            query += " AND analysis_date >= ?"
            params.append(date_from)
        if date_to:
            query += " AND analysis_date <= ?"
            params.append(date_to)
        
        # Apply sorting
        if sort_by in ['input_string', 'input_type', 'main_verdict', 'analysis_date']:
            query += f" ORDER BY {sort_by} {order.upper()}"
        else:
            query += f" ORDER BY analysis_date {order.upper()}"
        
        # Apply pagination
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        c.execute(query, params)
        history = c.fetchall()
        
        # Get total count with the same filters
        count_query = "SELECT COUNT(*) FROM analysis_history WHERE user_id = ?"
        count_params = [user_id]
        
        if type_filter != 'all':
            count_query += " AND input_type = ?"
            count_params.append(type_filter)
            
        if filter_result != 'all':
            count_query += " AND main_verdict = ?"
            count_params.append(filter_result)
        
        # Apply date range filter to count query
        if date_from:
            count_query += " AND analysis_date >= ?"
            count_params.append(date_from)
        if date_to:
            count_query += " AND analysis_date <= ?"
            count_params.append(date_to)
                
        c.execute(count_query, count_params)
        total = c.fetchone()[0]
        
        conn.close()
        
        return await render_template('history.html', 
                                   history=history,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   sort_by=sort_by,
                                   order=order,
                                   filter_result=filter_result,
                                   type_filter=type_filter,
                                   date_from=date_from,
                                   date_to=date_to)
    except Exception as e:
        logger.error(f"Error in history route: {str(e)}", exc_info=True)
        return await render_template('error.html', error='An unexpected error occurred'), 500

@app.route('/api/analysis_details/<int:id>')
@login_required
async def api_analysis_details(id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM analysis_history WHERE id = ?', (id,))
    result = c.fetchone()
    conn.close()

    if result:
        return jsonify({
            'input_string': result['input_string'],
            'input_type': result['input_type'],
            'is_malicious': bool(result['is_malicious']),
            'analysis_date': result['analysis_date'],
            'metadata': json.loads(result['metadata']) if result['metadata'] else {},
            'vendor_analysis': json.loads(result['vendor_analysis']) if result['vendor_analysis'] else []
        })
    else:
        return jsonify({'error': 'Analysis not found'}), 404

@app.route('/profile', methods=['GET', 'POST'])
@login_required
async def profile():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        c = conn.cursor()

        if request.method == 'POST':
            form = await request.form
            new_username = form.get('username')
            new_password = form.get('password')
            
            if new_username:
                c.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
                session['username'] = new_username
            
            if new_password:
                hashed_password = generate_password_hash(new_password)
                c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            
            conn.commit()
            await flash('Profile updated successfully', 'success')
            print(f"Profile updated for user ID: {user_id}")  # Add this for debugging

        # Get user's total checks
        c.execute("SELECT COUNT(*) FROM analysis_history WHERE user_id = ?", (user_id,))
        total_checks = c.fetchone()[0]
        
        # Get user's recent activity
        c.execute("""
            SELECT input_string, main_verdict, analysis_date 
            FROM analysis_history 
            WHERE user_id = ? 
            ORDER BY analysis_date DESC LIMIT 5
        """, (user_id,))
        recent_activity = c.fetchall()
        
        # Get additional statistics
        c.execute("""
            SELECT 
                COUNT(CASE WHEN main_verdict = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN main_verdict = 'malicious' THEN 1 END) as malicious_count,
                COUNT(CASE WHEN main_verdict = 'suspicious' THEN 1 END) as suspicious_count
            FROM analysis_history 
            WHERE user_id = ?
        """, (user_id,))
        threat_stats = c.fetchone()
        
        phishing_detected = threat_stats[0]
        malicious_detected = threat_stats[1]
        suspicious_detected = threat_stats[2]
        total_threats = phishing_detected + malicious_detected + suspicious_detected
        
        # Calculate detection rate
        detection_rate = (total_threats / total_checks * 100) if total_checks > 0 else 0

        # Get user details
        c.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,))
        user_details = c.fetchone()
        
        conn.close()
        
        return await render_template('profile.html', 
                                   username=user_details[0],
                                   is_admin=user_details[1],
                                   total_checks=total_checks,
                                   recent_activity=recent_activity,
                                   phishing_detected=phishing_detected,
                                   malicious_detected=malicious_detected,
                                   suspicious_detected=suspicious_detected,
                                   total_threats=total_threats,
                                   detection_rate=detection_rate)
    except Exception as e:
        logger.error(f"Error in profile route: {str(e)}", exc_info=True)
        return await render_template('error.html', error='An unexpected error occurred while loading the profile.'), 500

@app.route('/dashboard')
@login_required
async def dashboard():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        c = conn.cursor()
        
        # User's stats
        c.execute("""
            SELECT 
                COUNT(*) as total_checks,
                COUNT(CASE WHEN main_verdict != 'safe' THEN 1 END) as threats_detected,
                COUNT(CASE WHEN main_verdict = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN main_verdict = 'malicious' THEN 1 END) as malicious_count,
                COUNT(CASE WHEN main_verdict = 'suspicious' THEN 1 END) as suspicious_count,
                COUNT(CASE WHEN main_verdict = 'safe' THEN 1 END) as safe_count
            FROM analysis_history 
            WHERE user_id = ?
        """, (user_id,))
        user_stats = c.fetchone()
        
        # User specific data
        user_total_checks = user_stats[0]
        user_threats_detected = user_stats[1]
        user_phishing_detected = user_stats[2]
        user_malicious_detected = user_stats[3]
        user_suspicious_detected = user_stats[4]
        user_safe_count = user_stats[5]
        
        # Calculate user's threat percentage
        user_threat_percentage = (user_threats_detected / user_total_checks * 100) if user_total_checks > 0 else 0
        
        # Global stats
        c.execute("""
            SELECT 
                COUNT(*) as total_checks,
                COUNT(CASE WHEN main_verdict != 'safe' THEN 1 END) as threats_detected,
                COUNT(CASE WHEN main_verdict = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN main_verdict = 'malicious' THEN 1 END) as malicious_count,
                COUNT(CASE WHEN main_verdict = 'suspicious' THEN 1 END) as suspicious_count,
                COUNT(CASE WHEN main_verdict = 'safe' THEN 1 END) as safe_count
            FROM analysis_history
        """)
        global_stats = c.fetchone()
        
        # Global data
        global_total_checks = global_stats[0]
        global_total_threats = global_stats[1]
        global_phishing_detected = global_stats[2]
        global_malicious_detected = global_stats[3]
        global_suspicious_detected = global_stats[4]
        global_safe_count = global_stats[5]
        
        # Calculate global threat percentage
        global_threat_percentage = (global_total_threats / global_total_checks * 100) if global_total_checks > 0 else 0
        
        # Fetch data for Detection Trends (last 7 days)
        c.execute("""
            SELECT 
                date(analysis_date) as check_date,
                COUNT(CASE WHEN main_verdict = 'safe' THEN 1 END) as safe_count,
                COUNT(CASE WHEN main_verdict = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN main_verdict = 'malicious' THEN 1 END) as malicious_count,
                COUNT(CASE WHEN main_verdict = 'suspicious' THEN 1 END) as suspicious_count
            FROM analysis_history
            WHERE user_id = ? AND analysis_date >= date('now', '-7 days')
            GROUP BY date(analysis_date)
            ORDER BY check_date
        """, (user_id,))
        trend_data = [dict(row) for row in c.fetchall()]

        # Fetch data for URL Analysis Distribution
        c.execute("""
            SELECT 
                COUNT(CASE WHEN main_verdict = 'safe' THEN 1 END) as safe_count,
                COUNT(CASE WHEN main_verdict = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN main_verdict = 'suspicious' THEN 1 END) as suspicious_count,
                COUNT(CASE WHEN main_verdict = 'malicious' THEN 1 END) as malicious_count
            FROM analysis_history
            WHERE user_id = ?
        """, (user_id,))
        distribution_data = dict(c.fetchone())

        # Recent activity - change LIMIT 5 to LIMIT 50
        c.execute("""
            SELECT input_string, main_verdict, analysis_date 
            FROM analysis_history 
            WHERE user_id = ? 
            ORDER BY analysis_date DESC LIMIT 50
        """, (user_id,))
        recent_activity = [dict(row) for row in c.fetchall()]
        
        # Close database connection
        conn.close()
        
        # Prepare chart data
        chart_data = {
            'trend_data': trend_data,
            'distribution_data': distribution_data
        }

        return await render_template(
            'dashboard.html',
            # User specific data
            total_checks=user_total_checks,
            total_threats=user_threats_detected,
            phishing_detected=user_phishing_detected,
            malicious_detected=user_malicious_detected,
            suspicious_detected=user_suspicious_detected,
            total_threat_percentage=user_threat_percentage,
            # Global data
            global_total_checks=global_total_checks,
            global_total_threats=global_total_threats,
            global_phishing_detected=global_phishing_detected,
            global_malicious_detected=global_malicious_detected,
            global_suspicious_detected=global_suspicious_detected,
            global_threat_percentage=global_threat_percentage,
            # Additional data
            chart_data=json.dumps(chart_data),
            recent_activity=recent_activity,  # This line was missing
            username=session.get('username'),
            is_admin=session.get('is_admin', False)
        )

    except Exception as e:
        app.logger.error(f"Error in dashboard route: {str(e)}", exc_info=True)
        return await render_template('error.html', error='An unexpected error occurred while loading the dashboard.'), 500

@app.route('/ml-dashboard')
@login_required
async def ml_dashboard():
    try:
        conn = get_db_connection()
        metrics_analyzer = MLMetricsAnalyzer(conn)
        
        basic_metrics = metrics_analyzer.get_basic_metrics()
        performance_graphs = metrics_analyzer.generate_performance_graphs()
        feature_importance = metrics_analyzer.get_feature_importance()
        model_evolution = metrics_analyzer.get_model_evolution()
        vendor_agreement = metrics_analyzer.get_vendor_agreement_analysis()
        
        conn.close()

        return await render_template(
            'ml_dashboard.html',
            basic_metrics=basic_metrics,
            performance_graphs=performance_graphs,
            feature_importance=feature_importance,
            model_evolution=model_evolution,
            vendor_agreement=vendor_agreement
        )
    except Exception as e:
        logger.error(f"Error in ML dashboard: {str(e)}", exc_info=True)
        return await render_template('error.html', error='An error occurred while loading the ML dashboard')

@app.route('/check', methods=['POST'])
@login_required
async def check_input():
    try:
        # Get start time for response time calculation
        start_time = time.time()
        
        data = await request.get_json()
        input_string = data.get('input', '').strip()
        user_id = session.get('user_id')
        
        # Get current time in GMT+8
        current_time = get_singapore_time()
        
        # Log the input for debugging
        logger.info(f"Analyzing input: {input_string}")
        
        result = await analyze_input(input_string)
        
        # Calculate response time
        response_time = time.time() - start_time
        
        # Initialize verdict priorities
        verdict_priorities = {
            'phishing': 0,
            'malicious': 0,
            'suspicious': 0,
            'safe': 0
        }
        
        # Count verdicts with priority logic
        for vendor in result['vendor_analysis']:
            verdict = vendor['verdict'].lower()
            if verdict == 'phishing':
                verdict_priorities['phishing'] += 1
            elif verdict == 'malicious':
                verdict_priorities['malicious'] += 1
            elif verdict == 'suspicious':
                verdict_priorities['suspicious'] += 1
            elif verdict in ['clean', 'harmless', 'safe']:
                verdict_priorities['safe'] += 1
        
        # Determine main verdict based on priority
        main_verdict = 'safe'
        if verdict_priorities['phishing'] > 0:
            main_verdict = 'phishing'
        elif verdict_priorities['malicious'] > 0:
            main_verdict = 'malicious'
        elif verdict_priorities['suspicious'] > 0:
            main_verdict = 'suspicious'
        
        # Add main_verdict to the result
        result['main_verdict'] = main_verdict
        result['is_malicious'] = main_verdict != 'safe'
        
        # Store the result in database
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO analysis_history 
                (input_string, input_type, is_malicious, community_score, metadata, 
                vendor_analysis, user_id, analysis_date, main_verdict)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                input_string,
                result['input_type'],
                int(result['is_malicious']),
                result['community_score'],
                json.dumps(result['metadata']),
                json.dumps(result['vendor_analysis']),
                user_id,
                current_time,
                main_verdict
            ))
            conn.commit()
            
            # Verify the insertion
            c.execute("""
                SELECT input_string, main_verdict, analysis_date 
                FROM analysis_history 
                WHERE input_string = ? 
                ORDER BY analysis_date DESC 
                LIMIT 1
            """, (input_string,))
            verification = c.fetchone()
            logger.info(f"Verification of insertion: {verification}")
            
        except Exception as db_error:
            logger.error(f"Database error: {str(db_error)}")
            raise
        finally:
            conn.close()

        # Store the result in session
        session['analysis_result'] = {
            'input_string': input_string,
            'main_verdict': main_verdict,
            'is_malicious': result['is_malicious'],
            'community_score': result['community_score'],
            'metadata': result['metadata'],
            'vendor_analysis': result['vendor_analysis'],
            'analysis_date': current_time
        }

        # Return a JSON response with the redirect URL
        return jsonify({
            'status': 'success',
            'redirect': url_for('result')
        })
        
    except Exception as e:
        logger.error(f"Error in check_input: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/result')
@login_required
async def result():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        c = conn.cursor()
        
        # Get the latest analysis
        c.execute("""
            SELECT 
                input_string,
                is_malicious,
                main_verdict,
                metadata,
                vendor_analysis,
                analysis_date,
                community_score
            FROM analysis_history 
            WHERE user_id = ?
            ORDER BY analysis_date DESC 
            LIMIT 1
        """, (user_id,))
        
        analysis = c.fetchone()
        conn.close()
        
        if not analysis:
            return await render_template('result.html', error='No analysis found')

        metadata = json.loads(analysis['metadata']) if analysis['metadata'] else {}
        vendor_analysis = json.loads(analysis['vendor_analysis']) if analysis['vendor_analysis'] else []
        
        # Calculate probability based on vendor verdicts
        total_vendors = len(vendor_analysis)
        malicious_count = sum(1 for v in vendor_analysis if v['verdict'].lower() in ['phishing', 'malicious', 'suspicious'])
        probability = malicious_count / total_vendors if total_vendors > 0 else 0

        # Convert analysis_date to Singapore time
        analysis_date = datetime.strptime(analysis['analysis_date'], '%Y-%m-%d %H:%M:%S')
        singapore_time = analysis_date.replace(tzinfo=pytz.UTC).astimezone(singapore_tz)
        formatted_date = singapore_time.strftime('%Y-%m-%d %H:%M:%S %Z')

        # Create features dictionary
        features = {
            'Final URL': metadata.get('final_url', 'N/A'),
            'Serving IP': metadata.get('serving_ip', 'N/A'),
            'Analysis Date': formatted_date,
            'Verdict': analysis['main_verdict'].capitalize(),
            'Total Vendors': total_vendors,
            'Malicious Detections': malicious_count,
            'Community Score': analysis['community_score']
        }

        return await render_template('result.html',
                                   url=analysis['input_string'],
                                   is_phishing=analysis['is_malicious'],
                                   probability=probability,
                                   features=features,
                                   vendor_analysis=vendor_analysis)
        
        # Add a small delay (e.g., 0.5 seconds)
        await asyncio.sleep(0.5)

        # Return a JSON response with the redirect URL
        return jsonify({
            'status': 'success',
            'redirect': url_for('result')
        })
        
    except Exception as e:
        logger.error(f"Error in check_input: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/analysis_details/<path:url>')
@login_required
async def analysis_details(url):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("""
            SELECT 
                input_string, main_verdict, analysis_date, community_score, metadata, vendor_analysis
            FROM analysis_history 
            WHERE input_string = ?
            ORDER BY analysis_date DESC 
            LIMIT 1
        """, (url,))
        
        result = c.fetchone()
        conn.close()
        
        if not result:
            app.logger.error(f"Analysis not found for URL: {url}")
            return jsonify({'error': 'Analysis not found'}), 404
            
        details = {
            'url': result[0],
            'main_verdict': result[1],
            'analysis_date': result[2],
            'community_score': result[3],
            'metadata': json.loads(result[4]) if result[4] else {},
            'vendor_analysis': json.loads(result[5]) if result[5] else []
        }
        
        app.logger.info(f"Successfully fetched details for URL: {url}")
        return jsonify(details)
        
    except Exception as e:
        app.logger.error(f"Error fetching analysis details for URL {url}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/reanalyze', methods=['POST'])
@login_required
async def reanalyze():
    try:
        data = await request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        # Reuse your existing analysis function
        result = await analyze_input(url)
        
        # Determine main verdict
        verdict_counts = {
            'phishing': 0,
            'malicious': 0,
            'suspicious': 0,
            'safe': 0
        }
        
        for vendor in result['vendor_analysis']:
            verdict = vendor['verdict'].lower()
            if verdict == 'phishing':
                verdict_counts['phishing'] += 1
            elif verdict == 'malicious':
                verdict_counts['malicious'] += 1
            elif verdict == 'suspicious':
                verdict_counts['suspicious'] += 1
            elif verdict in ['clean', 'harmless', 'safe']:
                verdict_counts['safe'] += 1

        # Determine main verdict based on priority
        main_verdict = 'safe'
        if verdict_counts['phishing'] > 0:
            main_verdict = 'phishing'
        elif verdict_counts['malicious'] > 0:
            main_verdict = 'malicious'
        elif verdict_counts['suspicious'] > 0:
            main_verdict = 'suspicious'
        
        # Store the new analysis in the database
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO analysis_history 
            (input_string, input_type, is_malicious, community_score, metadata, 
             vendor_analysis, user_id, analysis_date, main_verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            url,
            result['input_type'],
            int(result['is_malicious']),
            result['community_score'],
            json.dumps(result['metadata']),
            json.dumps(result['vendor_analysis']),
            session.get('user_id'),
            get_singapore_time(),
            main_verdict
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error reanalyzing URL: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/refresh_activity')
@login_required
async def refresh_activity():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        c = conn.cursor()
        
        # Fetch recent activity
        c.execute("""
            SELECT input_string, is_malicious, analysis_date 
            FROM analysis_history 
            WHERE user_id = ? 
            ORDER BY analysis_date DESC LIMIT 5
        """, (user_id,))
        
        recent_activity = []
        for row in c.fetchall():
            recent_activity.append({
                'input_string': row[0],
                'is_malicious': bool(row[1]),
                'analysis_date': row[2]
            })
            
        conn.close()
        
        return jsonify({
            'status': 'success',
            'recent_activity': recent_activity
        })
        
    except Exception as e:
        logger.error(f"Error refreshing activity: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/export')
@login_required
async def export_history():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, input_string, is_malicious, analysis_date, metadata, vendor_analysis 
            FROM analysis_history 
            WHERE user_id = ? 
            ORDER BY analysis_date DESC
        ''', (user_id,))
        history = c.fetchall()
        conn.close()

        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'URL', 'Result', 'Date', 'Details', 'Vendor Analysis'])
        
        for row in history:
            # Convert the is_malicious boolean to "Suspicious"/"Safe"
            result = "Suspicious" if row[2] else "Safe"
            # Format the row for CSV
            csv_row = [
                row[0],  # ID
                row[1],  # URL (input_string)
                result,  # Result
                row[3],  # Date (analysis_date)
                row[4],  # Details (metadata)
                row[5]   # Vendor Analysis
            ]
            cw.writerow(csv_row)

        output = await make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=url_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        output.headers["Content-type"] = "text/csv"
        return output
        
    except Exception as e:
        logger.error(f"Error in export_history: {str(e)}", exc_info=True)
        return jsonify({'error': 'An error occurred while exporting history'}), 500
    
# Initialize the EmailPhishingDetector at app startup
detector = EmailPhishingDetector()
detector.load_model()  # Load the trained model

def parse_email_file(file_path, file_type):
    """Parse email file and extract content with enhanced link and attachment detection"""
    try:
        if file_type == '.msg':
            msg = extract_msg.Message(file_path)
            body = msg.body
            html_content = msg.htmlBody
            subject = msg.subject
            sender = msg.sender
            headers = msg.header
            attachments = []
            for attachment in msg.attachments:
                attachment_data = {
                    'filename': attachment.longFilename,
                    'size': len(attachment.data),
                    'content_type': attachment.mime_type,
                    'hash': {
                        'md5': hashlib.md5(attachment.data).hexdigest(),
                        'sha1': hashlib.sha1(attachment.data).hexdigest(),
                        'sha256': hashlib.sha256(attachment.data).hexdigest()
                    }
                }
                attachments.append(attachment_data)
        elif file_type == '.eml':
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            body = ''
            html_content = ''
            attachments = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode()
                elif part.get_content_type() == "text/html":
                    html_content += part.get_payload(decode=True).decode()
                elif part.get_content_disposition() == 'attachment':
                    attachment_data = part.get_payload(decode=True)
                    attachments.append({
                        'filename': part.get_filename(),
                        'size': len(attachment_data),
                        'content_type': part.get_content_type(),
                        'hash': {
                            'md5': hashlib.md5(attachment_data).hexdigest(),
                            'sha1': hashlib.sha1(attachment_data).hexdigest(),
                            'sha256': hashlib.sha256(attachment_data).hexdigest()
                        }
                    })

            subject = msg['subject']
            sender = msg['from']
            headers = dict(msg)

        # Extract links from HTML content
        embedded_links = []
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                text = link.get_text()
                if href:
                    embedded_links.append({
                        'url': href,
                        'text': text,
                        'suspicious': is_suspicious_url(href)
                    })

        # Also look for URLs in plain text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        text_urls = re.findall(url_pattern, body)
        for url in text_urls:
            if not any(link['url'] == url for link in embedded_links):
                embedded_links.append({
                    'url': url,
                    'text': url,
                    'suspicious': is_suspicious_url(url)
                })

        return {
            'body': body,
            'html_content': html_content,
            'subject': subject,
            'sender': sender,
            'headers': headers,
            'embedded_links': embedded_links,
            'attachments': attachments
        }
    except Exception as e:
        logger.error(f"Error parsing email file: {str(e)}")
        raise
        
def _build_email_result_from_parts(
    *,
    subject: str = "",
    sender: str = "",
    body_text: str = "",
    html_text: str = "",
    links: list | None = None,
    attachments: list | None = None,
    model_output: dict | None = None
) -> dict:
    links = links or []
    attachments = attachments or []
    model_output = model_output or {}

    # Default feature skeleton (mirrors your manual-upload route)
    default_features = {
        'has_greeting': False,
        'has_signature': False,
        'url_count': 0,
        'suspicious_url_count': 0,
        'contains_urgent': False,
        'urgent_count': 0,
        'contains_personal': False,
        'contains_financial': False,
        'text_length': 0,
        'word_count': 0,
        'uppercase_ratio': 0.0,
        'digit_ratio': 0.0,
        'punctuation_ratio': 0.0,
        'is_service_email': False,
        'has_account_info': False,
        'has_company_signature': False,
        'has_personal_greeting': False,
    }

    # Fold in model-provided features if any
    if isinstance(model_output, dict) and 'features' in model_output:
        for k in default_features.keys():
            if k in model_output['features']:
                default_features[k] = model_output['features'][k]

    # Derive URL counts from the provided links (HTML + text)
    default_features['url_count'] = len(links)
    default_features['suspicious_url_count'] = sum(1 for l in links if l.get('suspicious'))

    # Confidence
    conf = float(model_output.get('confidence', 0.0) or 0.0)
    conf_level = 'High' if conf > 0.8 else 'Medium' if conf > 0.5 else 'Low'

    # Indicators (same style as manual flow)
    suspicious_indicators = []
    safe_indicators = []

    if default_features['has_greeting']:
        safe_indicators.append("Contains proper greeting")
    else:
        suspicious_indicators.append("Missing email greeting")

    if default_features['has_signature']:
        safe_indicators.append("Contains proper signature")
    else:
        suspicious_indicators.append("Missing email signature")

    if default_features['url_count'] > 0:
        if default_features['suspicious_url_count'] > 0:
            suspicious_indicators.append(f"Contains {default_features['suspicious_url_count']} suspicious URL(s)")
        else:
            safe_indicators.append("Contains links but none look suspicious")
    else:
        safe_indicators.append("No links found in the email")

    if default_features['contains_urgent'] or default_features['urgent_count'] > 0:
        suspicious_indicators.append("Contains urgent or time-sensitive language")
    else:
        safe_indicators.append("No urgent or time-sensitive language detected")

    if default_features['contains_personal'] or default_features['contains_financial']:
        suspicious_indicators.append("Possible request for personal/financial information")

    if attachments:
        safe_indicators.append("Attachments found")  # you can flip to a caution message if you prefer

    # Risk assessment buckets like in the template
    risk_assessment = {
        'url_risk': 'High' if default_features['suspicious_url_count'] > 0 else 'Low',
        'content_risk': 'High' if bool(model_output.get('is_phishing')) else 'Low',
        'structure_risk': 'High' if (not default_features['has_greeting'] or not default_features['has_signature']) else 'Low',
    }

    result = {
        'is_phishing': bool(model_output.get('is_phishing', False)),
        'confidence': conf,
        'features': default_features,

        # Metadata and content (what your template expects)
        'subject': subject or "",
        'sender': sender or "",
        'date': get_singapore_time(),
        'body': body_text or "",
        'html_content': html_text or "",
        'embedded_links': links,
        'attachments': attachments,

        'explanation': {
            'confidence_level': conf_level,
            'suspicious_indicators': suspicious_indicators,
            'safe_indicators': safe_indicators,
            'risk_assessment': risk_assessment
        }
    }

    # Optional convenience used by the extension popup:
    result['summary'] = "Likely phishing" if result['is_phishing'] else "Likely Safe"
    result['confidence_percentage'] = f"{round(conf * 100, 1)}%"

    return result

def process_eml_file(file_storage):
    """
    Accepts a Werkzeug/Quart FileStorage for a .eml or .msg, parses it,
    runs the ML detector, and returns a JSON-serializable dict.
    """
    try:
        filename = file_storage.filename or "upload.eml"
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ('.eml', '.msg'):
            return {"error": "Invalid file type. Please upload a .eml or .msg file."}, 400

        # Save to a temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            file_storage.save(tmp.name)
            temp_path = tmp.name

        # Parse and analyze
        email_data = parse_email_file(temp_path, ext)
        # Your detector has two shapes in the codebase; the /api/analyze_email path expects a dict.
        # We'll build the same flat structure expected elsewhere.
        body_text = email_data.get('body', '') or ''
        html_text = email_data.get('html_content', '') or ''
        if not body_text and not html_text:
            return {
                "error": "Empty email content",
                "is_phishing": False,
                "confidence": 0.0,
                "explanation": {
                    "suspicious_indicators": ["No email content to analyze"],
                    "safe_indicators": [],
                    "risk_assessment": {
                        "url_risk": "Low",
                        "content_risk": "Low",
                        "structure_risk": "Low"
                    }
                }
            }, 400

        # Run model (your code shows detector.analyze_email used with either text or a dict)
        # If your model expects combined text, pass both:
        analysis = detector.analyze_email(body_text, html_text)

        # Attach useful metadata for the UI
        analysis = analysis if isinstance(analysis, dict) else {}
        analysis.setdefault("is_phishing", False)
        analysis.setdefault("confidence", 0.0)
        analysis.setdefault("explanation", {
            "suspicious_indicators": [],
            "safe_indicators": [],
            "risk_assessment": {
                "url_risk": "Low",
                "content_risk": "Low",
                "structure_risk": "Low"
            }
        })

        analysis.update({
            "subject": email_data.get("subject", ""),
            "sender": email_data.get("sender", ""),
            "date": get_singapore_time(),
            "embedded_links": email_data.get("embedded_links", []),
            "attachments": email_data.get("attachments", []),
            # Optional convenience fields for your popup:
            "summary": "Likely phishing" if analysis["is_phishing"] else "Likely safe",
            "confidence_percentage": f"{round(float(analysis.get('confidence', 0.0)) * 100)}%"
        })

        return analysis
    except Exception as e:
        logger.error(f"process_eml_file error: {e}", exc_info=True)
        return {"error": "Failed to process email file"}, 500
    finally:
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.unlink(temp_path)
        except Exception:
            pass


def is_suspicious_url(url):
    """Enhanced suspicious URL detection"""
    try:
        parsed_url = urlparse(url)
        suspicious_indicators = [
            parsed_url.netloc != parsed_url.path.strip('/'),
            len(parsed_url.netloc.split('.')) > 3,
            any(char in parsed_url.netloc for char in ['@', '-', '_']),
            bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc)),
            len(url) > 100,
            bool(re.search(r'(password|login|account|bank|verify|security)', parsed_url.path.lower())),
            parsed_url.scheme == 'http',
            bool(re.search(r'[A-Z]{4,}', parsed_url.netloc))
        ]
        return sum(suspicious_indicators) >= 2
    except:
        return True

@app.route('/email_analysis', methods=['GET', 'POST'])
@login_required
async def email_analysis():
    if request.method == 'GET':
        return await render_template('email_analysis.html')
    
    try:
        # POST request handling
        files = await request.files
        if 'email_file' not in files:
            return jsonify({'error': 'No file part'}), 400
        
        file = files['email_file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in ['.msg', '.eml']:
            return jsonify({'error': 'Invalid file type. Please upload a .msg or .eml file.'}), 400

        temp_file_path = None
        try:
            # Save uploaded file
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
                await file.save(temp_file.name)
                temp_file_path = temp_file.name

            # Parse and analyze email
            email_data = parse_email_file(temp_file_path, file_ext)
            result = detector.analyze_email(email_data['body'], email_data.get('html_content', ''))
            
            # Create default features dictionary
            default_features = {
                'has_greeting': False,
                'has_signature': False,
                'url_count': 0,
                'suspicious_url_count': 0,
                'contains_urgent': False,
                'urgent_count': 0,
                'contains_personal': False,
                'contains_financial': False,
                'text_length': 0,
                'word_count': 0,
                'uppercase_ratio': 0.0,
                'digit_ratio': 0.0,
                'punctuation_ratio': 0.0,
                'is_service_email': False
            }

            # Update features from result
            if 'features' in result:
                for key in default_features.keys():
                    if key in result['features']:
                        default_features[key] = result['features'][key]

            # Add metadata to result
            result['subject'] = email_data['subject']
            result['sender'] = email_data['sender']
            result['date'] = get_singapore_time()
            result['html_content'] = email_data.get('html_content', '')
            result['attachments'] = email_data.get('attachments', [])
            
            # Store analysis in session
            session['email_analysis'] = {
                'is_phishing': result['is_phishing'],
                'confidence': float(result['confidence']),
                'features': default_features,
                'metadata': {
                    'subject': result['subject'],
                    'sender': result['sender'],
                    'date': result['date']
                },
                'explanation': {
                    'confidence_level': 'High' if result['confidence'] > 0.8 else 'Medium' if result['confidence'] > 0.5 else 'Low',
                    'suspicious_indicators': [],
                    'safe_indicators': [],
                    'risk_assessment': {
                        'url_risk': 'High' if default_features['suspicious_url_count'] > 0 else 'Low',
                        'content_risk': 'High' if result['is_phishing'] else 'Low',
                        'structure_risk': 'High' if not default_features['has_greeting'] or not default_features['has_signature'] else 'Low'
                    }
                }
            }

            # Generate indicators
            suspicious_indicators = []
            safe_indicators = []
            
            # Email structure analysis
            if default_features['has_greeting']:
                safe_indicators.append("Contains proper greeting")
            else:
                suspicious_indicators.append("Missing email greeting")
            
            if default_features['has_signature']:
                safe_indicators.append("Contains proper signature")
            else:
                suspicious_indicators.append("Missing email signature")
            
            # URL analysis
            if default_features['url_count'] > 0:
                if default_features['suspicious_url_count'] > 0:
                    suspicious_indicators.append(f"Contains {default_features['suspicious_url_count']} suspicious URLs")
                else:
                    safe_indicators.append("All URLs appear legitimate")
            else:
                safe_indicators.append("No links found in the email")
            
            # Content analysis
            if default_features.get('contains_urgent', False):
                suspicious_indicators.append("Contains urgent or time-sensitive language")
            else:
                safe_indicators.append("No urgent or time-sensitive language detected")
            
            # Improved sensitive information check
            sensitive_keywords = ['password', 'credit card', 'social security', 'bank account', 'login credentials']
            email_text_lower = email_data['body'].lower()
            contains_sensitive = any(keyword in email_text_lower for keyword in sensitive_keywords)
            
            if contains_sensitive:
                suspicious_indicators.append("Potential sensitive information requested")
            else:
                safe_indicators.append("No obvious requests for sensitive information detected")
            
            # Attachment analysis
            if email_data.get('attachments', []):
                suspicious_indicators.append(f"Contains {len(email_data['attachments'])} attachment(s)")
            else:
                safe_indicators.append("No attachments found")
            
            # Service email indicators
            if default_features.get('is_service_email', False):
                safe_indicators.append("Matches patterns of legitimate service email")
                if default_features.get('has_account_info', False):
                    safe_indicators.append("Contains expected account information")
                if default_features.get('has_company_signature', False):
                    safe_indicators.append("Contains valid company signature")
            
            # Update the explanation with the generated indicators
            session['email_analysis']['explanation']['suspicious_indicators'] = suspicious_indicators
            session['email_analysis']['explanation']['safe_indicators'] = safe_indicators
            
            # Update risk assessment
            session['email_analysis']['explanation']['risk_assessment'] = {
                'url_risk': 'High' if default_features['suspicious_url_count'] > 0 else 'Low',
                'content_risk': 'High' if contains_sensitive or default_features.get('contains_urgent', False) else 'Low',
                'structure_risk': 'High' if not default_features['has_greeting'] or not default_features['has_signature'] else 'Low'
            }

            # Store larger data in temporary file
            try:
                analysis_id = str(uuid.uuid4())
                temp_data_path = os.path.join(tempfile.gettempdir(), f'email_analysis_{analysis_id}.json')
                
                logger.debug(f"Storing email data in temporary file: {temp_data_path}")
                
                temp_data = {
                    'body': email_data['body'],
                    'html_content': email_data.get('html_content', ''),
                    'embedded_links': result.get('embedded_links', []),
                    'attachments': email_data.get('attachments', [])
                }
                
                with open(temp_data_path, 'w') as f:
                    json.dump(temp_data, f)
                
                session['email_analysis_id'] = analysis_id
                logger.debug(f"Successfully stored email data with analysis_id: {analysis_id}")
            
            except Exception as e:
                logger.error(f"Error storing email data: {str(e)}")
                session['email_analysis_id'] = None
                session['email_analysis']['minimal_data'] = {
                    'body': email_data['body'][:1000] + '...' if len(email_data['body']) > 1000 else email_data['body']
                }

            return jsonify({'redirect': url_for('email_analysis_result')})

        except Exception as e:
            logger.error(f"Error in email analysis: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

        finally:
            # Clean up temporary file
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception as e:
                    logger.error(f"Error deleting temporary file: {str(e)}")

    except Exception as e:
        logger.error(f"Error in request handling: {str(e)}", exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/api/upload_email', methods=['POST'])
def upload_email():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400

    # Parse the email file (your existing function)
    try:
        filename = file.filename or "upload.eml"
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ('.eml', '.msg'):
            return jsonify({"error": "Invalid file type. Please upload a .eml or .msg file."}), 400

        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            file.save(tmp.name)
            temp_path = tmp.name

        email_data = parse_email_file(temp_path, ext)  # subject, sender, body, html_content, embedded_links, attachments

        body_text = email_data.get('body', '') or ''
        html_text = email_data.get('html_content', '') or ''
        model_out = detector.analyze_email(body_text, html_text)

        result = _build_email_result_from_parts(
            subject=email_data.get('subject', ''),
            sender=email_data.get('sender', ''),
            body_text=body_text,
            html_text=html_text,
            links=email_data.get('embedded_links', []),
            attachments=email_data.get('attachments', []),
            model_output=model_out if isinstance(model_out, dict) else {}
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"/api/upload_email error: {e}", exc_info=True)
        return jsonify({"error": "Failed to process email file"}), 500
    finally:
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.unlink(temp_path)
        except Exception:
            pass


@app.route('/email_analysis_result')
@login_required
async def email_analysis_result():
    try:
        analysis = session.get('email_analysis')
        analysis_id = session.get('email_analysis_id')
        
        if not analysis or not analysis_id:
            return redirect(url_for('email_analysis'))
        
        # Load additional data from temporary file
        temp_data_path = os.path.join(tempfile.gettempdir(), f'email_analysis_{analysis_id}.json')
        try:
            with open(temp_data_path, 'r') as f:
                additional_data = json.load(f)
        except FileNotFoundError:
            additional_data = {}
        
        # Combine the data
        result = {
            'is_phishing': analysis['is_phishing'],
            'confidence': analysis['confidence'],
            'features': analysis['features'],
            'subject': analysis['metadata']['subject'],
            'sender': analysis['metadata']['sender'],
            'date': analysis['metadata']['date'],
            'body': additional_data.get('body', ''),
            'html_content': additional_data.get('html_content', ''),
            'embedded_links': additional_data.get('embedded_links', []),
            'attachments': additional_data.get('attachments', []),
            'explanation': analysis['explanation']  # Changed this line
        }

        # Debug logging for URL detection
        # logger.debug(f"Embedded links: {embedded_links}")

        # Save to analysis history
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Prepare the data for insertion
            user_id = session.get('user_id')
            input_string = result['sender']  # or could be result['subject']
            input_type = 'email'
            main_verdict = 'phishing' if result['is_phishing'] else 'safe'
            analysis_date = get_singapore_time()
            is_malicious = 1 if result['is_phishing'] else 0
            
            # Convert features and additional data to JSON string for metadata
            metadata = json.dumps({
                'subject': result['subject'],
                'sender': result['sender'],
                'confidence': result['confidence'],
                'features': result['features'],
                'embedded_links': result['embedded_links'],
                'attachments': result['attachments']
            })

            # Insert into database
            c.execute("""
                INSERT INTO analysis_history (
                    user_id, 
                    input_string, 
                    input_type, 
                    main_verdict, 
                    analysis_date, 
                    metadata,
                    is_malicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                input_string,
                input_type,
                main_verdict,
                analysis_date,
                metadata,
                is_malicious
            ))
            
            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error saving email analysis to history: {str(e)}", exc_info=True)
            # Continue with the response even if saving to history fails
        
        # Clean up
        try:
            os.unlink(temp_data_path)
        except:
            pass
            
        session.pop('email_analysis', None)
        session.pop('email_analysis_id', None)
        
        # Pass both result and additional_data to the template for debugging
        return await render_template(
            'email_analysis_result.html', 
            result=result,
            additional_data=additional_data
        )
        
    except Exception as e:
        logger.error(f"Error displaying analysis result: {str(e)}", exc_info=True)
        return redirect(url_for('email_analysis'))

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        form = await request.form
        username_or_email = form['username']
        password = form['password']
        
        conn = get_db_connection()
        c = conn.cursor()
        
        try:
            # Clean up any stale sessions first
            cleanup_stale_sessions()
            
            c.execute("SELECT * FROM users WHERE username = ? OR email = ?", 
                     (username_or_email, username_or_email))
            user = c.fetchone()

            if user and check_password_hash(user['password'], password):
                # For admin users or users with expired sessions, allow login
                if not user['is_admin']:
                    if user['session_token'] and user['session_expiry']:
                        try:
                            expiry_time = datetime.fromisoformat(user['session_expiry'])
                            if datetime.now() < expiry_time:
                                await flash('This account is already logged in on another device.', 'error')
                                return redirect(url_for('login'))
                        except (ValueError, TypeError):
                            # If there's any error parsing the expiry time, treat it as expired
                            pass

                # Create new session
                session_token = str(uuid.uuid4())
                expiry_time = datetime.now() + dt.timedelta(days=1)
                
                c.execute("""
                    UPDATE users 
                    SET session_token = ?, 
                        session_expiry = ? 
                    WHERE id = ?
                """, (session_token, expiry_time.isoformat(), user['id']))
                conn.commit()
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['session_token'] = session_token
                session['session_expiry'] = expiry_time.isoformat()
                
                # Add the log_user_activity call here, after setting up the session
                log_user_activity(user['username'], 'login')
                
                await flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                await flash('Invalid username or password.', 'error')
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            await flash('An error occurred during login.', 'error')
        finally:
            conn.close()
            
    return await render_template('login.html')
    
@app.route('/logout')
@login_required
async def logout():
    try:
        # Add the log_user_activity call here, before clearing the session
        log_user_activity(session.get('username'), 'logout')
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET session_token = NULL, session_expiry = NULL WHERE id = ?",
                 (session['user_id'],))
        conn.commit()
        conn.close()
        
        session.clear()
        await flash('You have been successfully logged out.', 'success')
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        await flash('An error occurred during logout.', 'error')
    
    return redirect(url_for('login'))

@app.route('/perform_system_cleanup/<secret_key>', methods=['GET'])
async def trigger_system_cleanup(secret_key):
    if secret_key != os.getenv('CLEANUP_SECRET_KEY', 'cleanup_2025_secure'):
        return "Unauthorized", 401

    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Backup admin credentials
        c.execute("""
            SELECT username, email, password, is_admin 
            FROM users 
            WHERE is_admin = 1 AND username = ?
        """, (os.getenv('ADMIN_DEFAULT_USERNAME'),))
        admin_data = c.fetchone()

        if not admin_data:
            return "Admin user not found!", 500

        # Drop all existing tables
        tables_to_drop = ['analysis_history', 'user_feedback', 'user_activity_log', 'users']
        for table in tables_to_drop:
            c.execute(f"DROP TABLE IF EXISTS {table}")

        # Recreate users table
        c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0,
            email_verified BOOLEAN DEFAULT 0,
            session_token TEXT,
            session_expiry TEXT
        )
        ''')

        # Restore admin user
        c.execute("""
            INSERT INTO users (username, email, password, is_admin, email_verified)
            VALUES (?, ?, ?, 1, 1)
        """, (admin_data['username'], admin_data['email'], admin_data['password']))

        # Recreate analysis_history table
        c.execute('''
        CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_string TEXT NOT NULL,
            input_type TEXT NOT NULL,
            is_malicious INTEGER NOT NULL,
            main_verdict TEXT NOT NULL,
            community_score TEXT,
            metadata TEXT,
            vendor_analysis TEXT,
            user_id INTEGER,
            analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            confidence_score REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Recreate user_activity_log table
        c.execute('''
        CREATE TABLE user_activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Recreate user_feedback table
        c.execute('''
        CREATE TABLE user_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            feedback_type TEXT,
            input_string TEXT,
            message TEXT,
            submission_date DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_analysis_date ON analysis_history(analysis_date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_main_verdict ON analysis_history(main_verdict)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_input_string ON analysis_history(input_string)')

        # Commit changes
        conn.commit()
        conn.close()

        # Create a new connection for VACUUM
        conn = get_db_connection()
        conn.execute("VACUUM")
        conn.close()

        return """
        <html>
            <body>
                <h2>System cleanup completed successfully!</h2>
                <p>Please follow these steps:</p>
                <ol>
                    <li>Go to Render dashboard</li>
                    <li>Click "Manual Deploy"</li>
                    <li>Choose "Clear build cache & deploy"</li>
                    <li>Wait for deployment to complete</li>
                    <li>Clear your browser cache</li>
                    <li>Log out and log back in</li>
                </ol>
            </body>
        </html>
        """, 200

    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return f"Error during cleanup: {str(e)}", 500


import secrets
import string

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
async def create_user():
    if not session.get('is_admin'):
        await flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        form = await request.form
        username = form['username'].strip()
        email = form['email'].strip()
        is_admin = 'is_admin' in form

        # Email validation
        if not email or '@' not in email:
            await flash('Valid email address is required.', 'error')
            return await render_template('create_user.html')

        # Generate a secure temporary password
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(12))

        conn = get_db_connection()
        c = conn.cursor()
        try:
            # Check if username or email already exists
            c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if c.fetchone():
                await flash('Username or email already exists.', 'error')
                return await render_template('create_user.html')

            # Create new user with temporary password
            hashed_password = generate_password_hash(temp_password)
            c.execute("""
                INSERT INTO users 
                (username, email, password, is_admin, email_verified) 
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_password, is_admin, True))
            conn.commit()

            # Send welcome email with credentials
            try:
                subject = 'Welcome to Cyber Phishing Detection System'
                login_url = url_for('login', _external=True)
                html_content = f"""
                <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                            .important {{ 
                                background-color: #fff3cd; 
                                border: 1px solid #ffeeba; 
                                padding: 15px; 
                                margin: 20px 0; 
                                border-radius: 5px; 
                            }}
                            .credentials {{
                                background-color: #f8f9fa;
                                padding: 15px;
                                border-radius: 5px;
                                margin: 15px 0;
                            }}
                            .button {{
                                display: inline-block;
                                padding: 10px 20px;
                                background-color: #007bff;
                                color: #ffffff;
                                text-decoration: none;
                                border-radius: 5px;
                                margin-top: 20px;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>Welcome to Cyber Phishing Detection System</h2>
                            <p>Hello {username},</p>
                            <p>Your account has been created successfully. Below are your login credentials:</p>
                            
                            <div class="credentials">
                                <p><strong>Username:</strong> {username}</p>
                                <p><strong>Temporary Password:</strong> {temp_password}</p>
                            </div>
                            
                            <div class="important">
                                <h3>⚠️ Important Security Notice</h3>
                                <p>For security reasons, please follow these steps:</p>
                                <ol>
                                    <li>Click the login button below</li>
                                    <li>Use the credentials above to log in</li>
                                    <li>Go to your Profile page</li>
                                    <li>Change your password immediately</li>
                                </ol>
                            </div>
                            
                            <a href="{login_url}" class="button">Login to Your Account</a>
                            
                            <p>If you have any questions or need assistance, please contact the system administrator.</p>
                            <p>Best regards,<br>Cyber Phishing Detection Team</p>
                        </div>
                    </body>
                </html>
                """

                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = os.getenv('APP_EMAIL')
                msg['To'] = email
                msg.attach(MIMEText(html_content, 'html'))

                await send_email_async(
                    os.getenv('APP_EMAIL'),
                    email,
                    os.getenv('APP_EMAIL_PASSWORD'),
                    msg
                )
                await flash('User created successfully! Login credentials have been sent to their email.', 'success')
                return redirect(url_for('manage_users'))
            except Exception as e:
                logger.error(f"Error sending welcome email: {str(e)}")
                await flash('User created but there was an error sending the welcome email.', 'warning')
                return redirect(url_for('manage_users'))

        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            await flash(f'An error occurred while creating the user.', 'error')
        finally:
            conn.close()

    return await render_template('create_user.html')

# Add email verification route
@app.route('/verify_email/<token>')
async def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=3600*24)  # 24 hour expiration
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET email_verified = ? WHERE email = ?", (True, email))
        conn.commit()
        conn.close()
        await flash('Email verified successfully!', 'success')
    except Exception as e:
        logger.error(f"Error verifying email: {str(e)}")
        await flash('Invalid or expired verification link.', 'error')
    return redirect(url_for('login'))

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() == 'true'
app.config['APP_EMAIL'] = os.getenv('APP_EMAIL')
app.config['APP_EMAIL_PASSWORD'] = os.getenv('APP_EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Create a serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/reset_password_request', methods=['GET', 'POST'])
async def reset_password_request():
    logger.info("Reset password request route accessed")
    if request.method == 'POST':
        logger.info("POST request received")
        form = await request.form
        identifier = form.get('identifier')
        logger.info(f"Identifier submitted: {identifier}")
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
        user = c.fetchone()
        conn.close()

        if user:
            logger.info(f"User found for identifier: {identifier}")
            try:
                # Use email if available, otherwise use username
                email = user['email'] if user['email'] else user['username']
                
                # Generate token
                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # Create email message
                subject = 'Phishing Detection System - Password Reset Request'
                html_content = f"""
                <html>
                    <head>
                        <style>
                            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                            .button {{ 
                                display: inline-block;
                                padding: 10px 20px;
                                background-color: #4CAF50;
                                color: white;
                                text-decoration: none;
                                border-radius: 5px;
                                margin: 20px 0;
                            }}
                            .warning {{ color: #ff4444; font-size: 0.9em; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>Password Reset Request</h2>
                            <p>Hello,</p>
                            <p>We received a request to reset the password for your Phishing Detection System account.</p>
                            <p>To reset your password, click the button below:</p>
                            <a href="{reset_url}" class="button">Reset Password</a>
                            <p>If you didn't request this password reset, you can safely ignore this email.</p>
                            <p class="warning">This password reset link will expire in 1 hour for security reasons.</p>
                            <p>Best regards,<br>The Phishing Detection System Team</p>
                        </div>
                    </body>
                </html>
                """
                
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = os.getenv('APP_EMAIL')
                msg['To'] = email

                # Add HTML content
                msg.attach(MIMEText(html_content, 'html'))

                # Send email
                logger.info(f"Attempting to send email to {email}")
                await send_email_async(
                    os.getenv('APP_EMAIL'),
                    email,
                    os.getenv('APP_EMAIL_PASSWORD'),
                    msg
                )
                logger.info("Email sent successfully")

                await flash('Password reset instructions have been sent to your email.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                logger.error(f"Error sending password reset email: {str(e)}")
                await flash('Error sending password reset email. Please try again later.', 'error')
        else:
            logger.info(f"No user found for identifier: {identifier}")
            await flash('No account found with that username or email address.', 'error')

    return await render_template('reset_password_request.html')

async def send_email_async(sender_email, receiver_email, password, msg):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_email, sender_email, receiver_email, password, msg)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
async def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token expires after 1 hour
    except:
        await flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        form = await request.form
        password = form.get('password')
        confirm_password = form.get('confirm_password')

        if password != confirm_password:
            await flash('Passwords do not match.', 'error')
            return await render_template('reset_password.html')

        if len(password) < 8:
            await flash('Password must be at least 8 characters long.', 'error')
            return await render_template('reset_password.html')

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (generate_password_hash(password), email)
            )
            conn.commit()
            conn.close()

            await flash('Your password has been successfully reset. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            await flash('An error occurred while resetting your password. Please try again.', 'error')

    return await render_template('reset_password.html')

@app.route('/manage_users')
@login_required
async def manage_users():
    if not session.get('is_admin'):
        await flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, username, email, 
                   CASE 
                       WHEN password IS NOT NULL THEN '********'
                       ELSE 'No password set'
                   END as masked_password,
                   is_admin,
                   CASE
                       WHEN session_token IS NOT NULL THEN 'Online'
                       ELSE 'Offline'
                   END as status
            FROM users
            ORDER BY username
        """)
        users = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return await render_template('manage_users.html', users=users)
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        await flash('An error occurred while loading the user management page.', 'error')
        return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
async def delete_user(user_id):
    if not session.get('is_admin'):
        await flash('You do not have permission to delete users.', 'error')
        return redirect(url_for('home'))

    if user_id == session.get('user_id'):
        await flash('You cannot delete your own account.', 'error')
        return redirect(url_for('manage_users'))

    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Get the username before deletion
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        
        if user:
            # Delete user's records from related tables first (if any)
            c.execute("DELETE FROM analysis_history WHERE user_id = ?", (user_id,))
            c.execute("DELETE FROM user_feedback WHERE user_id = ?", (user_id,))
            
            # Delete the user
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            await flash(f'User {user["username"]} has been deleted successfully.', 'success')
        else:
            await flash('User not found.', 'error')
        
        conn.close()
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        await flash(f'An error occurred while deleting the user: {str(e)}', 'error')

    return redirect(url_for('manage_users'))

@app.route('/admin_initiate_reset/<int:user_id>', methods=['POST'])
@login_required
async def admin_initiate_reset(user_id):
    if not session.get('is_admin'):
        await flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, username FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()

        if not user:
            await flash('User not found.', 'error')
            return redirect(url_for('manage_users'))

        # Generate password reset token
        token = serializer.dumps(user['email'], salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)

        # Create email message
        subject = 'Phishing Detection System - Password Reset Initiated by Administrator'
        html_content = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .button {{ 
                        display: inline-block;
                        padding: 10px 20px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px 0;
                    }}
                    .warning {{ color: #ff4444; font-size: 0.9em; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Password Reset Request</h2>
                    <p>Hello {user['username']},</p>
                    <p>An administrator has initiated a password reset for your Phishing Detection System account.</p>
                    <p>To set your new password, click the button below:</p>
                    <a href="{reset_url}" class="button">Reset Password</a>
                    <p>If you didn't expect this password reset, please contact the administrator.</p>
                    <p class="warning">This password reset link will expire in 1 hour for security reasons.</p>
                    <p>Best regards,<br>The Phishing Detection System Team</p>
                </div>
            </body>
        </html>
        """

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = os.getenv('APP_EMAIL')
        msg['To'] = user['email']
        msg.attach(MIMEText(html_content, 'html'))

        # Send email
        await send_email_async(
            os.getenv('APP_EMAIL'),
            user['email'],
            os.getenv('APP_EMAIL_PASSWORD'),
            msg
        )

        await flash(f'Password reset link has been sent to {user["email"]}.', 'success')
    except Exception as e:
        logger.error(f"Error initiating password reset: {str(e)}")
        await flash('An error occurred while initiating password reset.', 'error')

    return redirect(url_for('manage_users'))

@app.route('/api/analyze_email', methods=['POST'])
async def api_analyze_email():
    try:
        data = await request.get_json()
        if not data:
            return jsonify({
                'error': 'No data provided',
                'is_phishing': False,
                'confidence': 0.0,
                'explanation': {
                    'suspicious_indicators': ['No email content to analyze'],
                    'safe_indicators': [],
                    'risk_assessment': {
                        'url_risk': 'Low', 'content_risk': 'Low', 'structure_risk': 'Low'
                    }
                }
            }), 400

        logger.info(f"Received email data: {json.dumps(data, indent=2)}")

        subject = data.get('subject', '')
        sender  = data.get('sender', '')
        body    = data.get('body', '') or ''
        html    = data.get('html', '') or ''
        links   = data.get('links', []) or []
        # Optional attachments if your extension ever sends them
        attachments = data.get('attachments', []) or []

        if not body and not html:
            return jsonify({
                'error': 'Empty email content',
                'is_phishing': False,
                'confidence': 0.0,
                'explanation': {
                    'suspicious_indicators': ['No email content to analyze'],
                    'safe_indicators': [],
                    'risk_assessment': {
                        'url_risk': 'Low', 'content_risk': 'Low', 'structure_risk': 'Low'
                    }
                }
            }), 400

        model_out = detector.analyze_email(body, html)
        result = _build_email_result_from_parts(
            subject=subject, sender=sender, body_text=body, html_text=html,
            links=links, attachments=attachments,
            model_output=model_out if isinstance(model_out, dict) else {}
        )
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in api_analyze_email: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'is_phishing': False,
            'confidence': 0.0,
            'explanation': {
                'suspicious_indicators': [f'Error analyzing email: {str(e)}'],
                'safe_indicators': [],
                'risk_assessment': {
                    'url_risk': 'Low', 'content_risk': 'Low', 'structure_risk': 'Low'
                }
            }
        }), 500


@app.errorhandler(404)
async def not_found(e):
    logger.error(f"404 Not Found: {request.url}")
    return await render_template('error.html', error='Not Found'), 404

@app.errorhandler(Exception)
async def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return await render_template('error.html', error='An unexpected error occurred'), 500

ensure_db_directory()
migrate_database()  # Then migrate if needed
feedback_handler = FeedbackHandler()

if __name__ == '__main__':
    try:
        init_db()
    except Exception as e:
        print(f"Failed to initialize database: {str(e)}")
    
    migrate_database()  # This will handle both new and existing databases
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)








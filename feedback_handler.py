# feedback_handler.py

import sqlite3
from datetime import datetime
from typing import Dict, Any
from utils import setup_logger

logger = setup_logger(__name__)

class FeedbackHandler:
    def __init__(self, db_path: str = 'phishing_history.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the feedback tables in the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Create URL feedback table
            c.execute('''
                CREATE TABLE IF NOT EXISTS url_feedback
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 url TEXT NOT NULL,
                 original_prediction BOOLEAN NOT NULL,
                 user_feedback BOOLEAN NOT NULL,
                 user_id TEXT NOT NULL,
                 feedback_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 notes TEXT)
            ''')
            
            # Create user feedback table (for general feedback)
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
            
            conn.commit()
            conn.close()
            logger.info("Feedback database initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing feedback database: {str(e)}")
            raise

    async def store_feedback(self, 
                           url: str, 
                           original_prediction: bool, 
                           user_feedback: bool, 
                           user_id: str, 
                           notes: str = None) -> Dict[str, Any]:
        """Store URL feedback in the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO url_feedback 
                (url, original_prediction, user_feedback, user_id, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, original_prediction, user_feedback, user_id, notes))
            
            conn.commit()
            feedback_id = c.lastrowid
            conn.close()
            
            logger.info(f"Feedback stored successfully for URL: {url}")
            return {
                "status": "success",
                "feedback_id": feedback_id,
                "message": "Feedback stored successfully"
            }
            
        except Exception as e:
            logger.error(f"Error storing feedback: {str(e)}")
            return {
                "status": "error",
                "message": f"Error storing feedback: {str(e)}"
            }

    async def submit_feedback(self, user_id: int, feedback_type: str, input_string: str, message: str) -> Dict[str, Any]:
        """Submit general user feedback"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Check for recent duplicate submissions
            c.execute("""
                SELECT COUNT(*) FROM user_feedback 
                WHERE user_id = ? 
                AND feedback_type = ? 
                AND input_string = ? 
                AND submission_date > datetime('now', '-1 minute')
            """, (user_id, feedback_type, input_string))
            
            if c.fetchone()[0] > 0:
                return {
                    "success": False,
                    "message": "Duplicate submission detected. Please wait before submitting again."
                }

            # Insert new feedback
            c.execute("""
                INSERT INTO user_feedback 
                (user_id, feedback_type, input_string, message, submission_date)
                VALUES (?, ?, ?, ?, datetime('now'))
            """, (user_id, feedback_type, input_string, message))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "message": "Feedback submitted successfully"
            }
            
        except Exception as e:
            logger.error(f"Error submitting feedback: {str(e)}")
            return {
                "success": False,
                "message": f"Error submitting feedback: {str(e)}"
            }

    async def get_feedback_stats(self, user_id: str = None) -> Dict[str, Any]:
        """Get feedback statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Get URL feedback stats
            if user_id:
                c.execute('''
                    SELECT 
                        COUNT(*) as total_feedback,
                        SUM(CASE WHEN original_prediction != user_feedback THEN 1 ELSE 0 END) as disagreements
                    FROM url_feedback
                    WHERE user_id = ?
                ''', (user_id,))
            else:
                c.execute('''
                    SELECT 
                        COUNT(*) as total_feedback,
                        SUM(CASE WHEN original_prediction != user_feedback THEN 1 ELSE 0 END) as disagreements
                    FROM url_feedback
                ''')
            
            url_stats = c.fetchone()
            
            # Get general feedback stats
            if user_id:
                c.execute("""
                    SELECT 
                        feedback_type,
                        COUNT(*) as count
                    FROM user_feedback
                    WHERE user_id = ?
                    GROUP BY feedback_type
                """, (user_id,))
            else:
                c.execute("""
                    SELECT 
                        feedback_type,
                        COUNT(*) as count
                    FROM user_feedback
                    GROUP BY feedback_type
                """)
            
            general_stats = c.fetchall()
            
            conn.close()
            
            return {
                "url_feedback": {
                    "total_feedback": url_stats[0],
                    "disagreements": url_stats[1],
                    "agreement_rate": (url_stats[0] - url_stats[1]) / url_stats[0] if url_stats[0] > 0 else 0
                },
                "general_feedback": {
                    row[0]: row[1] for row in general_stats
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting feedback stats: {str(e)}")
            return {
                "status": "error",
                "message": f"Error getting feedback stats: {str(e)}"
            }
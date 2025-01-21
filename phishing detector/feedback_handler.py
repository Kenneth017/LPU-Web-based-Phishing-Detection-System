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
        """Initialize the feedback table in the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Create feedback table if it doesn't exist
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
        """Store user feedback in the database"""
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

    async def get_feedback_stats(self, user_id: str = None) -> Dict[str, Any]:
        """Get feedback statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            if user_id:
                # Get stats for specific user
                c.execute('''
                    SELECT 
                        COUNT(*) as total_feedback,
                        SUM(CASE WHEN original_prediction != user_feedback THEN 1 ELSE 0 END) as disagreements
                    FROM url_feedback
                    WHERE user_id = ?
                ''', (user_id,))
            else:
                # Get overall stats
                c.execute('''
                    SELECT 
                        COUNT(*) as total_feedback,
                        SUM(CASE WHEN original_prediction != user_feedback THEN 1 ELSE 0 END) as disagreements
                    FROM url_feedback
                ''')
            
            row = c.fetchone()
            
            # Get recent feedback
            if user_id:
                c.execute('''
                    SELECT url, original_prediction, user_feedback, feedback_date
                    FROM url_feedback
                    WHERE user_id = ?
                    ORDER BY feedback_date DESC
                    LIMIT 5
                ''', (user_id,))
            else:
                c.execute('''
                    SELECT url, original_prediction, user_feedback, feedback_date
                    FROM url_feedback
                    ORDER BY feedback_date DESC
                    LIMIT 5
                ''')
            
            recent_feedback = c.fetchall()
            conn.close()
            
            return {
                "total_feedback": row[0],
                "disagreements": row[1],
                "agreement_rate": (row[0] - row[1]) / row[0] if row[0] > 0 else 0,
                "recent_feedback": [
                    {
                        "url": f[0],
                        "original_prediction": f[1],
                        "user_feedback": f[2],
                        "date": f[3]
                    } for f in recent_feedback
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting feedback stats: {str(e)}")
            return {
                "status": "error",
                "message": f"Error getting feedback stats: {str(e)}"
            }
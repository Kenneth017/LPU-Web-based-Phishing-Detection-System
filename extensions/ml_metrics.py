import numpy as np
from sklearn.metrics import roc_curve, auc, confusion_matrix, precision_recall_curve
from typing import Dict, List, Tuple
import pandas as pd
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
import sqlite3
from utils import setup_logger
import json

# Set up logger
logger = setup_logger(__name__)

class MLMetricsAnalyzer:
    def __init__(self, db_connection):
        self.conn = db_connection

    def get_basic_metrics(self) -> Dict:
        """Calculate basic ML metrics from the database"""
        cursor = self.conn.cursor()
        
        # Get overall statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as phishing_detected,
                AVG(CASE WHEN is_malicious = 1 THEN 1.0 ELSE 0.0 END) as detection_rate
            FROM analysis_history
            WHERE analysis_date >= datetime('now', '-30 day')
        """)
        stats = cursor.fetchone()

        # Get daily detection rates
        cursor.execute("""
            SELECT 
                date(analysis_date) as check_day,
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as phishing_detected
            FROM analysis_history
            GROUP BY date(analysis_date)
            ORDER BY check_day DESC
            LIMIT 30
        """)
        daily_stats = cursor.fetchall()

        return {
            'total_checks': stats[0] if stats[0] else 0,
            'phishing_detected': stats[1] if stats[1] else 0,
            'detection_rate': stats[2] if stats[2] else 0,
            'daily_stats': daily_stats
        }

    def get_feature_importance(self) -> Dict:
        """Calculate and return feature importance scores"""
        cursor = self.conn.cursor()
        
        # Get metadata from recent analyses
        cursor.execute("""
            SELECT metadata
            FROM analysis_history
            WHERE metadata IS NOT NULL
            ORDER BY analysis_date DESC
            LIMIT 100
        """)
        
        results = cursor.fetchall()
        
        # Initialize feature importance dictionary
        features = {
            'url_structure': {
                'length': 0.15,
                'special_chars': 0.10,
                'subdomain_depth': 0.08,
                'path_depth': 0.07
            },
            'domain_analysis': {
                'age': 0.12,
                'registration_length': 0.08,
                'suspicious_tld': 0.09
            },
            'security_indicators': {
                'ssl_valid': 0.10,
                'whois_privacy': 0.06,
                'dns_records': 0.08
            },
            'content_analysis': {
                'forms_present': 0.07,
                'external_links': 0.06,
                'obfuscation': 0.05
            }
        }
        
        # Update feature importance based on actual data if available
        for row in results:
            if row[0]:
                try:
                    metadata = json.loads(row[0])
                    # Update feature importance based on metadata
                    # Add your logic here
                except json.JSONDecodeError:
                    continue
        
        return features

    def generate_performance_graphs(self) -> Dict:
        """Generate performance visualization data"""
        cursor = self.conn.cursor()
        
        # Get vendor analysis results and actual outcomes
        cursor.execute("""
            SELECT is_malicious, vendor_analysis
            FROM analysis_history
            WHERE analysis_date >= datetime('now', '-30 day')
            AND vendor_analysis IS NOT NULL
        """)
        
        results = cursor.fetchall()
        
        if not results:
            logger.warning("No data available for performance graphs.")
            return {
                'roc_curve': {'fpr': [], 'tpr': [], 'auc': 0},
                'pr_curve': {'precision': [], 'recall': []}
            }
        
        # Calculate confidence scores based on vendor agreement
        y_true = []
        y_scores = []
        
        for is_malicious, vendor_analysis in results:
            try:
                vendors = json.loads(vendor_analysis)
                malicious_count = sum(1 for v in vendors if v['verdict'] in ['malicious', 'phishing'])
                total_vendors = len(vendors)
                confidence = malicious_count / total_vendors if total_vendors > 0 else 0.5
                
                y_true.append(is_malicious)
                y_scores.append(confidence)
            except (json.JSONDecodeError, KeyError):
                continue
        
        if not y_true or not y_scores:
            return {
                'roc_curve': {'fpr': [], 'tpr': [], 'auc': 0},
                'pr_curve': {'precision': [], 'recall': []}
            }
        
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        
        return {
            'roc_curve': {
                'fpr': fpr.tolist(),
                'tpr': tpr.tolist(),
                'auc': roc_auc
            },
            'pr_curve': {
                'precision': precision.tolist(),
                'recall': recall.tolist()
            }
        }

    def get_model_evolution(self) -> Dict:
        """Track model performance evolution over time"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT 
                date(analysis_date) as check_day,
                COUNT(*) as total_checks,
                AVG(CASE WHEN is_malicious = 1 THEN 1.0 ELSE 0.0 END) as detection_rate
            FROM analysis_history
            GROUP BY date(check_day)
            ORDER BY check_day DESC
            LIMIT 30
        """)
            
        evolution_data = cursor.fetchall()
        
        return {
            'dates': [row[0] for row in evolution_data],
            'accuracy': [row[2] for row in evolution_data] if evolution_data else [],
            'volume': [row[1] for row in evolution_data] if evolution_data else []
        }

    def get_vendor_agreement_analysis(self) -> Dict:
        """Analyze agreement between different vendors"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                input_string,
                vendor_analysis,
                is_malicious
            FROM analysis_history
            WHERE analysis_date >= datetime('now', '-7 day')
            AND vendor_analysis IS NOT NULL
        """)
        results = cursor.fetchall()
        
        agreement_stats = {
            'full_agreement': 0,
            'partial_agreement': 0,
            'disagreement': 0
        }
        
        for row in results:
            try:
                vendors = json.loads(row[1]) if row[1] else []
                if not vendors:
                    continue
                    
                verdicts = [v['verdict'] for v in vendors]
                
                if all(v == verdicts[0] for v in verdicts):
                    agreement_stats['full_agreement'] += 1
                elif any(v in ['phishing', 'malicious'] for v in verdicts) and any(v == 'clean' for v in verdicts):
                    agreement_stats['disagreement'] += 1
                else:
                    agreement_stats['partial_agreement'] += 1
            except json.JSONDecodeError:
                continue
        
        return agreement_stats

def add_confidence_score_column(conn):
    """Add confidence_score column to the database if it doesn't exist"""
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE analysis_history ADD COLUMN confidence_score REAL")
        conn.commit()
        logger.info("Added confidence_score column to analysis_history table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            logger.info("confidence_score column already exists")
        else:
            logger.error(f"Error adding confidence_score column: {e}")
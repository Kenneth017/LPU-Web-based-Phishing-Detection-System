import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from scipy import sparse
import joblib
import os
from tqdm import tqdm
import string
from sklearn.impute import SimpleImputer
import logging
import hashlib
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header

# Set up logging
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Create a file handler
    log_directory = 'logs'
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    
    file_handler = logging.FileHandler(os.path.join(log_directory, 'email_analysis.log'))
    file_handler.setLevel(logging.INFO)
    
    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

class EmailPhishingDetector:
    def __init__(self):
        self.model = None
        self.tfidf = None
        self.trained = False
        self.feature_names = None
        self.suspicious_words = {
            'urgent': ['urgent', 'immediate', 'action required', 'account suspended', 'verify now'],
            'financial': ['bank', 'account', 'credit card', 'payment', 'transfer', 'transaction'],
            'security': ['password', 'login', 'verify', 'security', 'update required', 'unauthorized'],
            'personal': ['ssn', 'social security', 'date of birth', 'personal details', 'confidential'],
            'threat': ['suspended', 'blocked', 'unauthorized', 'suspicious', 'limited', 'locked'],
            'action': ['click here', 'sign in', 'confirm', 'verify', 'validate', 'update'],
        }
        self.models = {
            'SVM': SVC(kernel='rbf', C=1.0, probability=True, random_state=42, class_weight='balanced'),
            'Random Forest': RandomForestClassifier(n_estimators=200, max_depth=20, min_samples_split=5, min_samples_leaf=2, random_state=42, class_weight='balanced', n_jobs=-1),
            'XGBoost': XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)
        }

    def load_dataset(self, filepath, text_column='Email Text', class_column='Email Type', chunksize=1000):
        """Load and preprocess the dataset in chunks"""
        try:
            print("Loading dataset in chunks...")
            chunks = pd.read_csv(filepath, chunksize=chunksize, low_memory=False)
            
            processed_chunks = []
            total_rows = 0
            phishing_count = 0
            
            for chunk in tqdm(chunks, desc="Processing chunks"):
                if text_column not in chunk.columns or class_column not in chunk.columns:
                    raise ValueError(f"Required columns not found. Available columns: {chunk.columns.tolist()}")
                
                chunk = chunk.dropna(subset=[text_column, class_column])
                chunk[text_column] = chunk[text_column].apply(self._preprocess_text)
                chunk['Class'] = chunk[class_column].map({'Safe Email': 0, 'Phishing Email': 1})
                
                # Extract potential HTML content
                chunk['HTML Content'] = chunk[text_column].apply(self._extract_html_content)
                
                processed_chunks.append(chunk[[text_column, 'HTML Content', 'Class']])
                total_rows += len(chunk)
                phishing_count += sum(chunk['Class'] == 1)
            
            df = pd.concat(processed_chunks, ignore_index=True)
            
            print(f"\nDataset Statistics:")
            print(f"Total emails: {total_rows}")
            print(f"Phishing emails: {phishing_count}")
            print(f"Legitimate emails: {total_rows - phishing_count}")
            print(f"Phishing ratio: {phishing_count/total_rows:.2%}")
            
            if df['Class'].isnull().any():
                print("\nWarning: NaN values found in 'Class' column after processing. Removing these rows.")
                df = df.dropna(subset=['Class'])
            
            df['Class'] = df['Class'].astype(int)
            
            return df
        except Exception as e:
            print(f"Error loading dataset: {str(e)}")
            raise

    def _extract_html_content(self, text):
        """Extract HTML content from text if present"""
        if '<html' in text.lower():
            try:
                # Find the HTML portion
                html_start = text.lower().find('<html')
                html_end = text.lower().rfind('</html>') + 7
                if html_end > html_start:
                    return text[html_start:html_end]
            except:
                pass
        return ''

    def extract_features(self, text, html_content=''):
        """Enhanced feature extraction from email text and HTML content"""
        features = {}
        
        # Basic text features
        features['text_length'] = len(text)
        words = text.split()
        features['word_count'] = len(words)
        
        # Safe calculation of average word length
        if words:
            features['avg_word_length'] = sum(len(word) for word in words) / len(words)
        else:
            features['avg_word_length'] = 0
        
        # URL features
        embedded_links = self._extract_urls(text, html_content)
        features['url_count'] = len(embedded_links)
        features['suspicious_url_count'] = sum(1 for link in embedded_links if link['suspicious'])
        features['url_to_text_ratio'] = features['url_count'] / features['word_count'] if features['word_count'] > 0 else 0
        
        # Suspicious content features
        for category, words in self.suspicious_words.items():
            count = sum(1 for word in words if word in text.lower())
            features[f'contains_{category}'] = 1 if count > 0 else 0
            features[f'{category}_count'] = count
        
        # Character-based features
        text_length = len(text) if len(text) > 0 else 1  # Prevent division by zero
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / text_length
        features['digit_ratio'] = sum(1 for c in text if c.isdigit()) / text_length
        features['punctuation_ratio'] = sum(1 for c in text if c in string.punctuation) / text_length
        
        # Add urgent count feature
        urgent_words = ['urgent', 'immediate', 'action required', 'account suspended', 'verify now']
        features['urgent_count'] = sum(1 for word in urgent_words if word.lower() in text.lower())
        
        # Email structure features
        features['has_greeting'] = 1 if re.search(r'\b(dear|hello|hi|hey)\b', text.lower()) else 0
        features['has_signature'] = 1 if re.search(r'\b(regards|sincerely|thank|thanks)\b', text.lower()) else 0
        
        # HTML features
        features['contains_html'] = 1 if html_content else 0
        features['html_tag_count'] = len(re.findall(r'<[^>]+>', html_content)) if html_content else 0
        
        # Link manipulation features
        features['mismatched_links'] = self._check_link_manipulation(text, html_content)
        
        # Add these new features
        features['has_multipart'] = 1 if html_content else 0
        features['html_to_text_ratio'] = len(html_content) / len(text) if text else 0
        features['has_base64'] = 1 if 'base64' in text.lower() or 'base64' in html_content.lower() else 0
        features['has_script'] = 1 if '<script' in html_content.lower() else 0
        features['has_iframe'] = 1 if '<iframe' in html_content.lower() else 0
        features['has_form'] = 1 if '<form' in html_content.lower() else 0
        
        return features

    def _check_link_manipulation(self, text, html_content=''):
        """Check for common link manipulation techniques"""
        count = 0
        
        # Check for URLs with IP addresses
        if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', text) or (html_content and re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', html_content)):
            count += 1
        
        # Check for URLs with @ symbol
        if re.search(r'http[s]?://.*?@', text) or (html_content and re.search(r'http[s]?://.*?@', html_content)):
            count += 1
        
        # Check for extremely long URLs
        urls = self._extract_urls(text, html_content)
        if any(len(link['url']) > 100 for link in urls):
            count += 1
        
        # Check for URL shortening services
        shortening_services = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
        if any(service in text.lower() for service in shortening_services) or (html_content and any(service in html_content.lower() for service in shortening_services)):
            count += 1
        
        return count

    def _is_suspicious_url(self, url):
        try:
            parsed_url = urlparse(url)
            suspicious_indicators = [
                # ... (existing indicators)
                
                # Add these new indicators
                bool(re.search(r'[0-9]{10,}', url)),  # Long numeric sequences
                bool(re.search(r'[a-zA-Z0-9]{25,}', url)),  # Very long alphanumeric sequences
                parsed_url.netloc.count('.') > 3,  # Too many subdomains
                bool(re.search(r'(signin|login|account|verify|secure|banking)', parsed_url.path.lower())),
                any(tld in parsed_url.netloc.lower() for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']),  # Suspicious TLDs
                bool(re.search(r'[^\x00-\x7F]', url))  # Non-ASCII characters
            ]
            return sum(suspicious_indicators) >= 2
        except:
            return True

    def _preprocess_text(self, text):
        """Enhanced text preprocessing"""
        if not isinstance(text, str):
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove email headers
        text = re.sub(r'^.*?subject:', '', text, flags=re.MULTILINE | re.DOTALL)
        
        # Normalize whitespace
        text = ' '.join(text.split())
        
        # Normalize URLs (keep but standardize)
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', 'URL', text)
        
        # Remove repeated punctuation
        text = re.sub(r'([!?.]){2,}', r'\1', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text

    def train(self, df):
        """Enhanced training process with multiple models and cross-validation"""
        try:
            logger.info("Starting enhanced training process...")
            
            # 1. Feature Extraction
            logger.info("1. Extracting features...")
            
            # TF-IDF features
            logger.info("   - Creating TF-IDF features...")
            self.tfidf = TfidfVectorizer(
                max_features=2000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=5,
                max_df=0.95
            )
            X_text = self.tfidf.fit_transform(tqdm(df['Email Text'].values, desc="TF-IDF"))
            
            # Custom features
            logger.info("   - Extracting custom features...")
            custom_features = []
            for text, html in tqdm(zip(df['Email Text'].values, df['HTML Content'].values), desc="Custom Features", total=len(df)):
                features = self.extract_features(text, html)
                custom_features.append([
                    features['text_length'],
                    features['word_count'],
                    features['avg_word_length'],
                    features['url_count'],
                    features['suspicious_url_count'],
                    features['url_to_text_ratio'],
                    features['contains_urgent'],
                    features['contains_financial'],
                    features['contains_security'],
                    features['contains_personal'],
                    features['contains_threat'],
                    features['contains_action'],
                    features['uppercase_ratio'],
                    features['digit_ratio'],
                    features['punctuation_ratio'],
                    features['has_greeting'],
                    features['has_signature'],
                    features['contains_html'],
                    features['html_tag_count'],
                    features['mismatched_links'],
                    features.get('has_multipart', 0),
                    features.get('html_to_text_ratio', 0),
                    features.get('has_base64', 0),
                    features.get('has_script', 0),
                    features.get('has_iframe', 0),
                    features.get('has_form', 0)
                ])
            custom_features = np.array(custom_features)
                
            # Combine features
            logger.info("   - Combining features...")
            X = sparse.hstack((X_text, custom_features))
            y = df['Class'].values
            
            # Store feature names
            self.feature_names = np.concatenate([
                self.tfidf.get_feature_names_out(),
                [
                    'text_length', 'word_count', 'avg_word_length',
                    'url_count', 'suspicious_url_count', 'url_to_text_ratio',
                    'contains_urgent', 'contains_financial', 'contains_security',
                    'contains_personal', 'contains_threat', 'contains_action',
                    'uppercase_ratio', 'digit_ratio', 'punctuation_ratio',
                    'has_greeting', 'has_signature', 'contains_html',
                    'html_tag_count', 'mismatched_links',
                    # Add new feature names here
                    'has_multipart', 'html_to_text_ratio', 'has_base64',
                    'has_script', 'has_iframe', 'has_form'
                ]
            ])
            
            # Handle NaN values
            logger.info("   - Handling NaN values...")
            X = X.toarray()
            X = np.nan_to_num(X)  # Replace NaN with 0
            
            # 2. Data Splitting
            logger.info("2. Splitting dataset...")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=0.2, 
                random_state=42,
                stratify=y
            )
            
            # 3. Model Training and Selection
            logger.info("3. Training and evaluating multiple models...")
            
            # Evaluate models using cross-validation
            best_score = 0
            best_model = None
            best_model_name = None
            
            for name, model in self.models.items():
                logger.info(f"Evaluating {name}...")
                scores = cross_val_score(model, X_train, y_train, cv=5, scoring='f1_weighted')
                mean_score = scores.mean()
                std_score = scores.std()
                
                logger.info(f"   {name} CV Score: {mean_score:.3f} (+/- {std_score * 2:.3f})")
                
                if mean_score > best_score:
                    best_score = mean_score
                    best_model = model
                    best_model_name = name
            
            # Train the best model on the full training set
            logger.info(f"4. Training final model ({best_model_name})...")
            best_model.fit(X_train, y_train)
            self.model = best_model
            
            # 5. Final Evaluation
            logger.info("5. Evaluating final model...")
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred)
            conf_matrix = confusion_matrix(y_test, y_pred)
            
            # 6. Feature Importance Analysis
            if isinstance(self.model, (RandomForestClassifier, XGBClassifier)):
                self._analyze_feature_importance()
            
            self.trained = True
            
            return {
                'accuracy': accuracy,
                'classification_report': report,
                'confusion_matrix': conf_matrix,
                'best_model': best_model_name,
                'cross_val_score': best_score
            }
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}", exc_info=True)
            raise

    def _analyze_feature_importance(self):
        """Analyze and print feature importance for Random Forest or XGBoost model"""
        if isinstance(self.model, (RandomForestClassifier, XGBClassifier)):
            # Get feature importances
            importances = self.model.feature_importances_
            
            # Sort features by importance
            feature_importance = sorted(
                zip(self.feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )
            
            print("\nTop 20 Most Important Features:")
            for feature, importance in feature_importance[:20]:
                print(f"{feature}: {importance:.4f}")
            
            return feature_importance
        else:
            print("Feature importance analysis is not available for this model type.")
            return []  # Return an empty list if feature importance is not available

    def analyze_email(self, email_content, html_content=''):
        """Analyze a single email"""
        if not self.trained:
            logger.error("Model has not been trained yet")
            raise ValueError("Model has not been trained yet")
        
        try:
            logger.info("Starting email analysis")
            processed_text = self._preprocess_text(email_content)
            
            # Extract features
            logger.debug("Extracting features")
            text_features = self.tfidf.transform([processed_text])
            custom_features = self.extract_features(processed_text, html_content)
            
            # Convert custom features to array
            custom_features_array = np.array([
                custom_features['text_length'],
                custom_features['word_count'],
                custom_features['avg_word_length'],
                custom_features['url_count'],
                custom_features['suspicious_url_count'],
                custom_features['url_to_text_ratio'],
                custom_features['contains_urgent'],
                custom_features['contains_financial'],
                custom_features['contains_security'],
                custom_features['contains_personal'],
                custom_features['contains_threat'],
                custom_features['contains_action'],
                custom_features['uppercase_ratio'],
                custom_features['digit_ratio'],
                custom_features['punctuation_ratio'],
                custom_features['has_greeting'],
                custom_features['has_signature'],
                custom_features['contains_html'],
                custom_features['html_tag_count'],
                custom_features['mismatched_links'],
                # Add new features here
                custom_features.get('has_multipart', 0),
                custom_features.get('html_to_text_ratio', 0),
                custom_features.get('has_base64', 0),
                custom_features.get('has_script', 0),
                custom_features.get('has_iframe', 0),
                custom_features.get('has_form', 0)
            ]).reshape(1, -1)
            
            # Combine features
            X = sparse.hstack((text_features, custom_features_array))
            
            # Handle feature vector size
            if X.shape[1] < self.model.n_features_in_:
                padding = sparse.csr_matrix((1, self.model.n_features_in_ - X.shape[1]))
                X = sparse.hstack((X, padding))
            elif X.shape[1] > self.model.n_features_in_:
                X = X[:, :self.model.n_features_in_]
            
            # Handle NaN values
            X = X.toarray()
            X = np.nan_to_num(X)
            
            # Get prediction and probability
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]
            
            # Extract URLs from the email
            embedded_links = self._extract_urls(email_content, html_content)
            
            logger.info(f"Analysis complete. Prediction: {prediction}, Probability: {probability[1]}")
            
            # Generate explanation
            explanation = self._generate_explanation(custom_features, probability, embedded_links)
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(probability[1]),
                'features': {
                    'has_greeting': bool(custom_features['has_greeting']),
                    'has_signature': bool(custom_features['has_signature']),
                    'url_count': int(custom_features['url_count']),
                    'suspicious_url_count': int(custom_features['suspicious_url_count']),
                    'contains_urgent': bool(custom_features['contains_urgent']),
                    'urgent_count': int(custom_features.get('urgent_count', 0)),
                    'contains_personal': bool(custom_features['contains_personal']),
                    'contains_financial': bool(custom_features['contains_financial']),
                    'text_length': int(custom_features['text_length']),
                    'word_count': int(custom_features['word_count']),
                    'uppercase_ratio': float(custom_features['uppercase_ratio']),
                    'digit_ratio': float(custom_features['digit_ratio']),
                    'punctuation_ratio': float(custom_features['punctuation_ratio'])
                },
                'explanation': explanation,
                'subject': '',
                'sender': '',
                'date': '',
                'body': email_content,
                'html_content': html_content,
                'embedded_links': embedded_links
            }
            
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}", exc_info=True)
            raise
        
    def analyze_headers(self, headers):
        suspicious_headers = []
        if headers:
            # Check for missing or suspicious headers
            required_headers = ['From', 'To', 'Subject', 'Date']
            for header in required_headers:
                if header not in headers:
                    suspicious_headers.append(f"Missing {header} header")
            
            # Check for suspicious return paths
            if 'Return-Path' in headers:
                if headers['Return-Path'] != headers.get('From', ''):
                    suspicious_headers.append("Mismatched Return-Path and From headers")
            
            # Check for suspicious X-headers
            suspicious_x_headers = ['X-PHP-Script', 'X-Mailer']
            for header in suspicious_x_headers:
                if header in headers:
                    suspicious_headers.append(f"Suspicious header found: {header}")
        
        return suspicious_headers
        
    def _extract_urls(self, text_content, html_content=''):
        urls = set()
        
        # Function to extract URLs from text
        def extract_urls_from_text(text):
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            return re.findall(url_pattern, text)

        # Extract URLs from text content
        text_urls = extract_urls_from_text(text_content)
        urls.update(text_urls)
        
        # Extract URLs from HTML content
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract URLs from href attributes
            for a in soup.find_all('a', href=True):
                url = a['href']
                if url.startswith('http'):
                    urls.add(url)
                elif url.startswith('/'):
                    # Relative URL, try to construct full URL
                    base_url = self._extract_base_url(text_content)
                    if base_url:
                        full_url = urljoin(base_url, url)
                        urls.add(full_url)
            
            # Extract URLs from button elements
            for button in soup.find_all('button'):
                onclick = button.get('onclick', '')
                button_urls = extract_urls_from_text(onclick)
                urls.update(button_urls)
            
            # Extract URLs from inline styles
            for tag in soup.find_all(style=True):
                style_urls = extract_urls_from_text(tag['style'])
                urls.update(style_urls)
            
            # Extract URLs from background images
            for tag in soup.find_all(lambda tag: any(attr.startswith('background') for attr in tag.attrs)):
                for attr, value in tag.attrs.items():
                    if attr.startswith('background'):
                        bg_urls = extract_urls_from_text(value)
                        urls.update(bg_urls)
        
        # Process and classify URLs
        embedded_links = []
        for url in urls:
            embedded_links.append({
                'url': url,
                'text': self._get_link_text(url, html_content) or url,
                'suspicious': self._is_suspicious_url(url)
            })
        
        return embedded_links

    def _get_link_text(self, url, html_content):
        if html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            for a in soup.find_all('a', href=True):
                if a['href'] == url:
                    return a.text.strip()
        return None

    def _extract_base_url(self, content):
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        if urls:
            parsed_url = urlparse(urls[0])
            return f"{parsed_url.scheme}://{parsed_url.netloc}"
        return None
    
    def _generate_explanation(self, features, probability, embedded_links):
        """Generate a human-readable explanation for the prediction"""
        suspicious_indicators = []
        safe_indicators = []
        
        # Check various features and add to appropriate list
        if embedded_links:
            suspicious_urls = [link for link in embedded_links if link['suspicious']]
            if suspicious_urls:
                suspicious_indicators.append(f"Contains {len(suspicious_urls)} suspicious URLs out of {len(embedded_links)} total URLs")
            else:
                safe_indicators.append(f"Contains {len(embedded_links)} legitimate URLs")
        else:
            safe_indicators.append("No URLs present in the email")
        
        if features['contains_urgent']:
            suspicious_indicators.append("Contains urgent or time-sensitive language")
        
        if features['contains_financial']:
            suspicious_indicators.append("Contains financial-related terms")
        
        if features['contains_security']:
            suspicious_indicators.append("Contains security-related terms")
        
        if features['contains_personal']:
            suspicious_indicators.append("Requests for personal information detected")
        
        if features['mismatched_links'] > 0:
            suspicious_indicators.append("Contains potentially manipulated links")
        
        if features['has_greeting'] and features['has_signature']:
            safe_indicators.append("Contains proper email structure (greeting and signature)")
        elif not features['has_greeting'] and not features['has_signature']:
            suspicious_indicators.append("Missing proper greeting and signature")
        elif not features['has_greeting']:
            suspicious_indicators.append("Missing proper greeting")
        elif not features['has_signature']:
            suspicious_indicators.append("Missing proper signature")
        
        # Generate final explanation
        explanation = {
            'confidence': f"{probability[1]*100:.1f}% confidence in classification",
            'suspicious_indicators': suspicious_indicators,
            'safe_indicators': safe_indicators
        }
        
        return explanation
        
    def extract_attachments(self, email_data):
        """Extract and analyze attachments from email data"""
        attachments = []
        
        if hasattr(email_data, 'attachments'):
            for attachment in email_data.attachments:
                attachment_info = {
                    'filename': attachment.filename,
                    'size': len(attachment.payload),
                    'content_type': attachment.content_type,
                    'hash': {
                        'md5': hashlib.md5(attachment.payload).hexdigest(),
                        'sha1': hashlib.sha1(attachment.payload).hexdigest(),
                        'sha256': hashlib.sha256(attachment.payload).hexdigest()
                    }
                }
                attachments.append(attachment_info)
        
        return attachments

    def retrain_model(self, dataset_path):
        """Retrain the model with current XGBoost version"""
        try:
            # Load and preprocess the dataset
            df = self.load_dataset(dataset_path)
            
            # Train the model
            results = self.train(df)
            
            # Save the newly trained model
            self.save_model()
            
            return results
        except Exception as e:
            print(f"Error retraining model: {str(e)}")
            raise

    def save_model(self, model_dir='models'):
        """Save the trained model and vectorizer"""
        if not self.trained:
            raise ValueError("Model has not been trained yet")
        
        try:
            print(f"Saving model to {model_dir}...")
            os.makedirs(model_dir, exist_ok=True)
            joblib.dump(self.model, os.path.join(model_dir, 'phishing_model.joblib'))
            joblib.dump(self.tfidf, os.path.join(model_dir, 'tfidf_vectorizer.joblib'))
            joblib.dump(self.feature_names, os.path.join(model_dir, 'feature_names.joblib'))
            print(f"Model saved successfully in {model_dir}")
        except Exception as e:
            print(f"Error saving model: {str(e)}")
            raise

    def load_model(self, model_dir='models'):
        """Load a trained model and vectorizer with fallback options"""
        try:
            print(f"Loading model from {model_dir}...")
            
            # Try loading the XGBoost model from JSON first
            xgb_json_path = os.path.join(model_dir, 'xgboost_model.json')
            if os.path.exists(xgb_json_path):
                self.model = XGBClassifier()
                self.model.load_model(xgb_json_path)
                print("XGBoost model loaded from JSON successfully")
            else:
                # Fallback to joblib if JSON is not available
                self.model = joblib.load(os.path.join(model_dir, 'phishing_model.joblib'))
                print("Model loaded from joblib successfully")
            
            # Load other components
            self.tfidf = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.joblib'))
            self.feature_names = joblib.load(os.path.join(model_dir, 'feature_names.joblib'))
            
            self.trained = True
            print("All model components loaded successfully")
                
        except Exception as e:
            print(f"Error loading model components: {str(e)}")
            raise
            
            # Load other components
            self.tfidf = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.joblib'))
            self.feature_names = joblib.load(os.path.join(model_dir, 'feature_names.joblib'))
            
            # Set trained flag based on whether we need to retrain
            self.trained = hasattr(self.model, 'booster')
            
            if not self.trained:
                print("Warning: Model needs to be retrained")
            else:
                print("Model loaded successfully")
                
        except Exception as e:
            print(f"Error loading model components: {str(e)}")
            raise

# Enable progress bar for pandas operations
tqdm.pandas()

# Example usage
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        # Initialize detector
        detector = EmailPhishingDetector()
        
        # Load dataset
        dataset_path = r"C:\Users\Kenneth\Desktop\LPU\Phishing Detection System\Phishing_Email.csv"
        logging.info(f"Loading dataset from: {dataset_path}")
        df = detector.load_dataset(dataset_path)
        
        # Train model
        results = detector.train(df)
        
        # Print results
        print("\nTraining Results:")
        print(f"Best Model: {results['best_model']}")
        print(f"Cross-validation Score: {results['cross_val_score']:.3f}")
        print(f"Final Test Accuracy: {results['accuracy']:.3f}")
        print("\nClassification Report:")
        print(results['classification_report'])
        print("\nConfusion Matrix:")
        print(results['confusion_matrix'])
        
        # Save model
        detector.save_model()
        
        # Test the model
        test_email = """
        Dear User,
        Your account security needs immediate attention. Please click the link below to verify your information:
        http://suspicious-bank.com/verify
        Urgent action required within 24 hours.
        """
        
        result = detector.analyze_email(test_email)
        print("\nTest Email Analysis:")
        print(f"Is Phishing: {result['is_phishing']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print("\nExplanation:")
        print(f"Confidence Level: {result['explanation']['confidence']}")
        print("\nSuspicious Indicators:")
        for indicator in result['explanation']['suspicious_indicators']:
            print(f"- {indicator}")
        print("\nSafe Indicators:")
        for indicator in result['explanation']['safe_indicators']:
            print(f"- {indicator}")
        
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}", exc_info=True)

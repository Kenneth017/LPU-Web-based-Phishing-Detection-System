import logging
from email_analysis_ml import EmailPhishingDetector
import time
import gc
import sys
import os
from xgboost import XGBClassifier

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def train_and_save_model():
    try:
        # Initialize detector
        detector = EmailPhishingDetector()
        
        # Update XGBoost model configuration for version 1.7.3 compatibility
        detector.models['XGBoost'] = XGBClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42,
            eval_metric='logloss'  # Added for compatibility
        )
        
        # Load dataset
        logger.info("Loading dataset...")
        dataset_path = r"C:\Users\Kenneth\Desktop\LPU\Phishing Detection System\Phishing_Email.csv"
        df = detector.load_dataset(dataset_path)
        
        # Train model
        logger.info("Starting model training...")
        logger.info(f"Models being evaluated: {', '.join(detector.models.keys())}")
        start_time = time.time()
        results = detector.train(df)
        training_time = time.time() - start_time
        
        # Print results
        logger.info("\nTraining Results:")
        logger.info(f"Best Model: {results['best_model']}")
        logger.info(f"Cross-validation Score: {results['cross_val_score']:.3f}")
        logger.info(f"Final Test Accuracy: {results['accuracy']:.3f}")
        logger.info(f"Training Time: {training_time:.2f} seconds")
        logger.info("\nClassification Report:")
        logger.info(results['classification_report'])
        logger.info("\nConfusion Matrix:")
        logger.info(str(results['confusion_matrix']))
        
        # Log feature importance if applicable
        if results['best_model'] in ['Random Forest', 'XGBoost']:
            logger.info("\nTop 10 Most Important Features:")
            feature_importance = detector._analyze_feature_importance()
            if feature_importance:
                for feature, importance in feature_importance[:10]:
                    logger.info(f"{feature}: {importance:.4f}")
            else:
                logger.info("Feature importance analysis is not available.")
        
        # Save model with special handling for XGBoost
        logger.info("Saving model...")
        save_path = 'models'
        os.makedirs(save_path, exist_ok=True)
        
        if isinstance(detector.model, XGBClassifier):
            # Save XGBoost model in both formats for compatibility
            model_json_path = os.path.join(save_path, 'xgboost_model.json')
            detector.model.save_model(model_json_path)
            logger.info(f"XGBoost model saved in JSON format at {model_json_path}")
        
        detector.save_model()
        logger.info("Model saved successfully")
        
        # Test the model with a sample email
        test_email = """
        Dear User,
        Your account security needs immediate attention. Please click the link below to verify your information:
        http://suspicious-bank.com/verify
        Urgent action required within 24 hours.
        """
        
        try:
            # Verify model loading
            logger.info("Testing model loading...")
            detector_test = EmailPhishingDetector()
            detector_test.load_model()
            
            logger.info("Testing email analysis...")
            result = detector_test.analyze_email(test_email)
            logger.info("\nTest Email Analysis:")
            logger.info(f"Is Phishing: {result['is_phishing']}")
            logger.info(f"Confidence: {result['confidence']:.2f}")
            logger.info("\nExplanation:")
            logger.info(f"Confidence Level: {result['explanation']['confidence']}")
            logger.info("\nSuspicious Indicators:")
            for indicator in result['explanation']['suspicious_indicators']:
                logger.info(f"- {indicator}")
            logger.info("\nSafe Indicators:")
            for indicator in result['explanation']['safe_indicators']:
                logger.info(f"- {indicator}")
        except Exception as e:
            logger.error(f"Error in email analysis: {str(e)}", exc_info=True)
        
        logger.info("Training and testing completed successfully!")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        # Cleanup
        gc.collect()

if __name__ == "__main__":
    train_and_save_model()
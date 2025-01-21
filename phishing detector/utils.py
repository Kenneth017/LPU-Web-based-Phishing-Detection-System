# utils.py
import logging
import time
import os
from typing import Dict, Any
from collections import Counter
import math

def setup_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        try:
            # Create logs directory if it doesn't exist
            log_dir = 'logs'
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # File handler with proper path
            log_file = os.path.join(log_dir, 'app.log')
            fh = logging.FileHandler(log_file)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            logger.warning(f"Could not set up file logging: {str(e)}")
    
    return logger

def print_elapsed_time(start_time, message):
    elapsed_time = time.time() - start_time
    logger = logging.getLogger(__name__)
    logger.info(f"{message}: {elapsed_time:.2f} seconds")

def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher entropy indicates more randomness/complexity in the string.
    """
    if not text:
        return 0.0
    
    try:
        # Count the frequency of each character
        counts = Counter(text)
        
        # Calculate the probability of each character
        probabilities = [count / len(text) for count in counts.values()]
        
        # Calculate entropy using Shannon's formula
        entropy = -sum(p * math.log2(p) for p in probabilities)
        
        return entropy
    except Exception as e:
        logger.error(f"Error calculating entropy: {str(e)}")
        return 0.0

# Set up logger for this module
logger = setup_logger(__name__)
# utils.py
import logging
import time
from typing import Dict, Any
import numpy as np
import math
from collections import Counter

def setup_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        fh = logging.FileHandler('app.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    
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
    
    # Count the frequency of each character
    counts = Counter(text)
    
    # Calculate the probability of each character
    probabilities = [count / len(text) for count in counts.values()]
    
    # Calculate entropy using Shannon's formula
    entropy = -sum(p * math.log2(p) for p in probabilities)
    
    return entropy

# Set up logger for this module
logger = setup_logger(__name__)
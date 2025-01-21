# setup_nltk.py

import ssl
import nltk
import os

def setup_nltk():
    # Disable SSL verification (if needed)
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context

    # Create NLTK data directory if it doesn't exist
    nltk_data_dir = os.path.expanduser('~/nltk_data')
    if not os.path.exists(nltk_data_dir):
        os.makedirs(nltk_data_dir)

    # Download required NLTK data
    try:
        nltk.download('punkt', download_dir=nltk_data_dir, force=True)
        nltk.download('averaged_perceptron_tagger', download_dir=nltk_data_dir, force=True)
        nltk.download('maxent_ne_chunker', download_dir=nltk_data_dir, force=True)
        nltk.download('words', download_dir=nltk_data_dir, force=True)
        print("NLTK resources downloaded successfully")
    except Exception as e:
        print(f"Error downloading NLTK resources: {str(e)}")

if __name__ == "__main__":
    setup_nltk()
# input_analyzer.py

from urllib.parse import urlparse
from ipaddress import ip_address
import re
import logging
from enum import Enum
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

class InputType(Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    UNKNOWN = "unknown"

def detect_input_type(input_string: str) -> Tuple[InputType, str]:
    """
    Detect the type of input (URL, Domain, IP, or Hash) and normalize it.
    Returns a tuple of (InputType, normalized_input)
    """
    input_string = input_string.strip()

    # Check if it's a hash (MD5, SHA-1, or SHA-256)
    hash_patterns = {
        32: re.compile(r'^[a-fA-F0-9]{32}$'),  # MD5
        40: re.compile(r'^[a-fA-F0-9]{40}$'),  # SHA-1
        64: re.compile(r'^[a-fA-F0-9]{64}$')   # SHA-256
    }
    
    if any(pattern.match(input_string) for length, pattern in hash_patterns.items()):
        return InputType.HASH, input_string.lower()

    # Check if it's an IP address
    try:
        ip_address(input_string)
        return InputType.IP, input_string
    except ValueError:
        pass

    # Check if it's a URL
    if '//' in input_string or input_string.startswith('ftp:'):
        parsed = urlparse(input_string)
        if parsed.scheme and parsed.netloc:
            return InputType.URL, input_string
        
    # Check if it's a domain
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if domain_pattern.match(input_string):
        return InputType.DOMAIN, input_string

    # If input contains any path or query parameters, treat as URL
    if '/' in input_string or '?' in input_string:
        return InputType.URL, input_string

    return InputType.UNKNOWN, input_string

def categorize_verdict(category: str, result_type: str) -> str:
    """
    Categorize the verdict based on category and result type
    """
    if category == "malicious":
        if any(keyword in result_type.lower() for keyword in ["phish", "phishing", "scam"]):
            return "phishing"
        return "malicious"
    elif category == "suspicious":
        return "suspicious"
    elif category in ["undetected", "harmless"]:
        return "clean"
    return category

# VirusTotal API functions
async def check_virustotal_url(url: str) -> Dict[str, Any]:
    # Implement your VirusTotal URL scan API call here
    pass

async def check_virustotal_domain(domain: str) -> Dict[str, Any]:
    # Implement your VirusTotal domain report API call here
    pass

async def check_virustotal_ip(ip: str) -> Dict[str, Any]:
    # Implement your VirusTotal IP address report API call here
    pass

async def check_virustotal_file(file_hash: str) -> Dict[str, Any]:
    # Implement your VirusTotal file hash report API call here
    pass
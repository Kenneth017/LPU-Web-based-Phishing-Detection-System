import aiohttp
import asyncio
from typing import Dict, Any, Tuple
from utils import setup_logger
from dotenv import load_dotenv
import os
import base64
from urllib.parse import urlparse
from enum import Enum
import re
from ipaddress import ip_address

# Set up logger
logger = setup_logger(__name__)

# Load environment variables
load_dotenv()

# Get API key and check if it exists
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print(f"API Key loaded in ml_api.py: {'Yes' if VIRUSTOTAL_API_KEY else 'No'}")

if not VIRUSTOTAL_API_KEY:
    logger.error("VIRUSTOTAL_API_KEY not found in environment variables")
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set")

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

class InputType(Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    UNKNOWN = "unknown"

def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding scheme if missing
    """
    if not url.startswith(('http://', 'https://', 'ftp://')):
        if url.startswith('www.'):
            return f"http://{url}"
        return f"http://{url}"
    return url

def detect_input_type(input_string: str) -> Tuple[InputType, str]:
    """
    Detect the type of input (URL, Domain, IP, or Hash) and normalize it.
    Returns a tuple of (InputType, normalized_input)
    """
    try:
        logger.info(f"Detecting input type for: {input_string}")
        
        if input_string is None:
            logger.error("Input string is None")
            return InputType.UNKNOWN, ""

        if not isinstance(input_string, str):
            logger.error(f"Input is not a string, it's a {type(input_string)}")
            return InputType.UNKNOWN, str(input_string)

        input_string = input_string.strip()
        logger.info(f"Stripped input: {input_string}")

        if not input_string:
            logger.warning("Input string is empty after stripping")
            return InputType.UNKNOWN, ""

        # Check if it's a hash (MD5, SHA-1, or SHA-256)
        hash_patterns = {
            32: re.compile(r'^[a-fA-F0-9]{32}$'),  # MD5
            40: re.compile(r'^[a-fA-F0-9]{40}$'),  # SHA-1
            64: re.compile(r'^[a-fA-F0-9]{64}$')   # SHA-256
        }
        
        for length, pattern in hash_patterns.items():
            if pattern.match(input_string):
                logger.info(f"Detected hash of length {length}")
                return InputType.HASH, input_string.lower()

        # Check if it's an IP address
        try:
            ip = ip_address(input_string)
            logger.info(f"Detected IP address: {ip}")
            return InputType.IP, str(ip)
        except ValueError:
            logger.debug("Not an IP address")

        # Parse URL
        parsed = urlparse(input_string)
        logger.debug(f"Parsed URL: {parsed}")
        
        # If it has a scheme, treat as URL
        if parsed.scheme:
            logger.info(f"Detected URL with scheme: {parsed.scheme}")
            return InputType.URL, input_string
        
        # Check for domain pattern
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        if domain_pattern.match(input_string):
            logger.info("Detected domain pattern")
            return InputType.DOMAIN, input_string
        
        # If contains path-like characters, treat as URL
        if any(char in input_string for char in ['/', '?', '&', '=']):
            logger.info("Detected URL-like pattern")
            normalized = f"http://{input_string}" if not input_string.startswith('http') else input_string
            return InputType.URL, normalized
        
        # If starts with www, treat as URL
        if input_string.startswith('www.'):
            logger.info("Detected www. prefix")
            return InputType.URL, f"http://{input_string}"
        
        # If contains dots but no other special characters, treat as domain
        if '.' in input_string:
            logger.info("Detected possible domain")
            return InputType.DOMAIN, input_string

        logger.warning(f"Unable to determine type for input: {input_string}")
        return InputType.UNKNOWN, input_string

    except Exception as e:
        logger.error(f"Unexpected error in detect_input_type: {str(e)}", exc_info=True)
        return InputType.UNKNOWN, input_string

async def vt_request(endpoint: str, method: str = "GET", data: Dict = None) -> Dict[str, Any]:
    """
    Make a request to the VirusTotal API
    """
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    if data:
        headers["content-type"] = "application/x-www-form-urlencoded"
    
    try:
        async with aiohttp.ClientSession() as session:
            if method.upper() == "GET":
                async with session.get(f"{VIRUSTOTAL_API_URL}{endpoint}", 
                                     headers=headers,
                                     raise_for_status=True) as response:
                    return await response.json()
            elif method.upper() == "POST":
                async with session.post(f"{VIRUSTOTAL_API_URL}{endpoint}", 
                                      headers=headers,
                                      data=data,
                                      raise_for_status=True) as response:
                    return await response.json()
    except aiohttp.ClientResponseError as e:
        logger.error(f"VirusTotal API error: {e.status} - {e.message}")
        return {"error": f"VirusTotal API error: {e.status} - {e.message}"}
    except aiohttp.ClientError as e:
        logger.error(f"HTTP error in vt_request: {str(e)}")
        return {"error": f"HTTP error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in vt_request: {str(e)}", exc_info=True)
        return {"error": str(e)}

async def check_virustotal_url(url: str) -> Dict[str, Any]:
    """
    Check a URL using VirusTotal API
    """
    try:
        # First, try to get an existing analysis
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        logger.info(f"Checking VirusTotal for existing analysis of URL: {url}")
        logger.info(f"URL ID: {url_id}")
        
        try:
            result = await vt_request(f"/urls/{url_id}")
            logger.info(f"Initial VirusTotal result: {result}")
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error when requesting VirusTotal API: {str(e)}")
            return {"error": f"HTTP error: {str(e)}"}

        # If the URL hasn't been analyzed yet, submit it for analysis
        if "error" in result and "not found" in str(result["error"]).lower():
            logger.info(f"URL not found in VirusTotal, submitting for analysis: {url}")
            # Submit URL for analysis
            try:
                submission = await vt_request("/urls", method="POST", data={"url": url})
                logger.info(f"Submission result: {submission}")
            except aiohttp.ClientError as e:
                logger.error(f"HTTP error when submitting URL to VirusTotal: {str(e)}")
                return {"error": f"HTTP error during submission: {str(e)}"}

            if "error" not in submission:
                analysis_id = submission["data"]["id"]
                logger.info(f"URL submitted for analysis. Analysis ID: {analysis_id}")
                
                # Wait a moment for analysis to complete
                await asyncio.sleep(3)
                
                # Get the analysis results
                logger.info(f"Fetching analysis results for ID: {analysis_id}")
                try:
                    result = await vt_request(f"/analyses/{analysis_id}")
                except aiohttp.ClientError as e:
                    logger.error(f"HTTP error when fetching analysis results: {str(e)}")
                    return {"error": f"HTTP error fetching results: {str(e)}"}
            else:
                logger.error(f"Error submitting URL for analysis: {submission['error']}")
                return submission
        
        logger.info(f"Final VirusTotal result for URL {url}: {result}")
        return result
    except Exception as e:
        logger.error(f"Error checking URL with VirusTotal: {str(e)}", exc_info=True)
        return {"error": str(e)}

async def check_virustotal_domain(domain: str) -> Dict[str, Any]:
    """
    Check a domain using VirusTotal API
    """
    try:
        return await vt_request(f"/domains/{domain}")
    except Exception as e:
        logger.error(f"Error checking domain with VirusTotal: {str(e)}")
        return {"error": str(e)}

async def check_virustotal_ip(ip: str) -> Dict[str, Any]:
    """
    Check an IP address using VirusTotal API
    """
    try:
        return await vt_request(f"/ip_addresses/{ip}")
    except Exception as e:
        logger.error(f"Error checking IP with VirusTotal: {str(e)}")
        return {"error": str(e)}

async def check_virustotal_file(file_hash: str) -> Dict[str, Any]:
    """
    Check a file hash using VirusTotal API
    """
    try:
        return await vt_request(f"/files/{file_hash}")
    except Exception as e:
        logger.error(f"Error checking file hash with VirusTotal: {str(e)}")
        return {"error": str(e)}

async def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    Check a URL using URLhaus API
    """
    try:
        async with aiohttp.ClientSession() as session:
            data = {"url": url}
            async with session.post(URLHAUS_API_URL, data=data, ssl=False) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Error checking URL with URLhaus: {error_text}")
                    return {"error": "Failed to check URL with URLhaus"}
                return await response.json()
    except Exception as e:
        logger.error(f"Error in check_urlhaus: {str(e)}")
        return {"error": f"Error checking URL with URLhaus: {str(e)}"}

def categorize_verdict(category: str, result_type: str) -> str:
    if category == "malicious":
        if "phish" in result_type.lower():
            return "phishing"
        return "malicious"
    elif category == "suspicious":
        return "suspicious"
    elif category in ["undetected", "harmless"]:
        return "clean"
    return category

async def analyze_input(input_string: str) -> Dict[str, Any]:
    """
    Analyze the input string based on its detected type
    """
    try:
        logger.info(f"Starting analysis for input: {input_string}")
        
        # Detect input type
        input_type, normalized_input = detect_input_type(input_string)
        logger.info(f"Detected input type: {input_type.value} for input: {input_string}")
        logger.info(f"Normalized input: {normalized_input}")

        # Initialize result dictionary
        result = {
            "original_input": input_string,
            "input_type": input_type.value,
            "normalized_input": normalized_input,
            "is_malicious": False,
            "community_score": "0/0",
            "vendor_analysis": [],
            "metadata": {}
        }

        # Get analysis based on input type
        vt_result = None
        urlhaus_result = None

        try:
            if input_type == InputType.URL:
                logger.info(f"Checking URL with VirusTotal: {normalized_input}")
                vt_result = await check_virustotal_url(normalized_input)
                logger.info(f"VirusTotal result: {vt_result}")
                
                # Only check URLhaus for URLs
                urlhaus_result = await check_urlhaus(normalized_input)
                logger.info(f"URLhaus result: {urlhaus_result}")
                
            elif input_type == InputType.DOMAIN:
                logger.info(f"Checking domain with VirusTotal: {normalized_input}")
                vt_result = await check_virustotal_domain(normalized_input)
                logger.info(f"VirusTotal result: {vt_result}")
                
            elif input_type == InputType.IP:
                logger.info(f"Checking IP with VirusTotal: {normalized_input}")
                vt_result = await check_virustotal_ip(normalized_input)
                logger.info(f"VirusTotal result: {vt_result}")
                
            elif input_type == InputType.HASH:
                logger.info(f"Checking hash with VirusTotal: {normalized_input}")
                vt_result = await check_virustotal_file(normalized_input)
                logger.info(f"VirusTotal result: {vt_result}")
                
            else:
                logger.warning(f"Unknown input type for: {input_string}")
                result["error"] = "Unable to determine input type"
                return result

        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}", exc_info=True)
            result["error"] = f"Analysis error: {str(e)}"
            return result

        # Process VirusTotal results
        if vt_result:
            if "error" in vt_result:
                logger.error(f"VirusTotal API error: {vt_result['error']}")
                result["error"] = vt_result["error"]
                return result

            if "data" in vt_result:
                attributes = vt_result["data"]["attributes"]
                
                # Process common attributes
                if "last_analysis_stats" in attributes:
                    stats = attributes["last_analysis_stats"]
                    total_scans = sum(stats.values())
                    malicious = stats.get("malicious", 0)
                    result["community_score"] = f"{malicious}/{total_scans}"
                    result["is_malicious"] = malicious > 0

                # Process vendor results
                if "last_analysis_results" in attributes:
                    for vendor_name, vendor_result in attributes["last_analysis_results"].items():
                        category = vendor_result.get("category", "unknown")
                        result_type = vendor_result.get("result", "unknown")
                        verdict = categorize_verdict(category, result_type)
                        result["vendor_analysis"].append({
                            "name": vendor_name,
                            "verdict": verdict
                        })

                # Add type-specific metadata
                if input_type == InputType.URL:
                    result["metadata"].update({
                        "final_url": attributes.get("last_final_url", normalized_input),
                        "serving_ip": attributes.get("last_http_response_code_ip", "Unknown")
                    })
                elif input_type == InputType.DOMAIN:
                    result["metadata"].update({
                        "creation_date": attributes.get("creation_date"),
                        "registrar": attributes.get("registrar"),
                        "last_dns_records": attributes.get("last_dns_records", [])
                    })
                elif input_type == InputType.IP:
                    result["metadata"].update({
                        "as_owner": attributes.get("as_owner"),
                        "country": attributes.get("country"),
                        "network": attributes.get("network")
                    })
                elif input_type == InputType.HASH:
                    result["metadata"].update({
                        "type_description": attributes.get("type_description"),
                        "size": attributes.get("size"),
                        "file_type": attributes.get("type")
                    })

        # Process URLhaus results if available
        if urlhaus_result and input_type == InputType.URL:
            if "query_status" in urlhaus_result:
                result["metadata"]["urlhaus_status"] = urlhaus_result["query_status"]
            if "threat" in urlhaus_result:
                result["metadata"]["urlhaus_threat"] = urlhaus_result["threat"]
            if "blacklists" in urlhaus_result:
                result["metadata"]["urlhaus_blacklists"] = urlhaus_result["blacklists"]
            
            # Update malicious status if URLhaus detected a threat
            if urlhaus_result.get("threat") and not result["is_malicious"]:
                result["is_malicious"] = True
                if not any(v["verdict"] == "malicious" for v in result["vendor_analysis"]):
                    result["vendor_analysis"].append({
                        "name": "URLhaus",
                        "verdict": "malicious"
                    })

        logger.info(f"Final analysis result: {result}")
        return result

    except Exception as e:
        logger.error(f"Error analyzing input {input_string}: {str(e)}", exc_info=True)
        return {
            "original_input": input_string,
            "input_type": InputType.UNKNOWN.value,
            "error": str(e),
            "is_malicious": False,
            "community_score": "0/0",
            "vendor_analysis": [],
            "metadata": {}
        }
        
__all__ = ['analyze_input']
# api_utils.py
import aiohttp
import asyncio
from typing import Dict, Any
from utils import setup_logger

logger = setup_logger(__name__)

VIRUSTOTAL_API_KEY = "08bdc5bc2c6c892e56023532b6f3ca20e79e31afe6adde12eff59dcda105b78e"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"

async def check_virustotal(url: str) -> Dict[str, Any]:
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    async with aiohttp.ClientSession() as session:
        # First, submit the URL for analysis
        async with session.post(VIRUSTOTAL_API_URL, headers=headers, data={"url": url}) as response:
            if response.status != 200:
                logger.error(f"Error submitting URL to VirusTotal: {await response.text()}")
                return {"error": "Failed to submit URL to VirusTotal"}
            submit_json = await response.json()
            analysis_id = submit_json["data"]["id"]

        # Then, get the analysis results
        analysis_url = f"{VIRUSTOTAL_API_URL}/{analysis_id}"
        async with session.get(analysis_url, headers=headers) as response:
            if response.status != 200:
                logger.error(f"Error getting analysis from VirusTotal: {await response.text()}")
                return {"error": "Failed to get analysis from VirusTotal"}
            return await response.json()

async def check_urlhaus(url: str) -> Dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        async with session.post(URLHAUS_API_URL, data={"url": url}) as response:
            if response.status != 200:
                logger.error(f"Error checking URL with URLhaus: {await response.text()}")
                return {"error": "Failed to check URL with URLhaus"}
            return await response.json()

async def analyze_url(url: str) -> Dict[str, Any]:
    vt_result = await check_virustotal(url)
    urlhaus_result = await check_urlhaus(url)

    # Process and combine results
    is_phishing = False
    confidence = 0.0
    reasons = []

    if "data" in vt_result:
        vt_malicious = vt_result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        vt_suspicious = vt_result["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        if vt_malicious > 0 or vt_suspicious > 0:
            is_phishing = True
            confidence = max(confidence, (vt_malicious + vt_suspicious) / (vt_malicious + vt_suspicious + vt_result["data"]["attributes"]["last_analysis_stats"]["harmless"]))
            reasons.append(f"VirusTotal: {vt_malicious} malicious, {vt_suspicious} suspicious detections")

    if urlhaus_result.get("query_status") == "ok":
        if urlhaus_result.get("threat") != "none":
            is_phishing = True
            confidence = max(confidence, 0.8)  # Assuming high confidence if URLhaus detects a threat
            reasons.append(f"URLhaus: Detected as {urlhaus_result.get('threat')}")

    return {
        "url": url,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "reasons": reasons
    }
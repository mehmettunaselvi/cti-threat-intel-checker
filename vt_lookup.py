import os
import time
import re
import logging
import requests
from dotenv import load_dotenv
from datetime import datetime
from typing import Dict, Any, Optional

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY")

# --- Logging Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- Regex Patterns for IOC Validation ---
SHA256_REGEX = re.compile(r"^[a-f0-9]{64}$")
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")

# --- Custom Exception ---
class VTLookupError(Exception):
    """Custom exception for VirusTotal lookup errors."""
    pass

# --- Helper Functions ---
def _validate_ioc(ioc: str, ioc_type: str) -> None:
    """
    Validates the format of the IOC based on its type.

    Args:
        ioc (str): The Indicator of Compromise (IOC) string.
        ioc_type (str): The type of the IOC ("ip", "hash", "domain").

    Raises:
        ValueError: If ioc_type is invalid or ioc format is incorrect.
    """
    if ioc_type == "hash":
        if not SHA256_REGEX.match(ioc):
            raise ValueError(f"Invalid SHA256 hash format: {ioc}")
    elif ioc_type == "ip":
        if not IPV4_REGEX.match(ioc):
            raise ValueError(f"Invalid IPv4 address format: {ioc}")
    elif ioc_type == "domain":
        if not DOMAIN_REGEX.match(ioc):
            raise ValueError(f"Invalid domain format: {ioc}")
    else:
        raise ValueError(f"Unsupported IOC type: {ioc_type}. Must be 'ip', 'hash', or 'domain'.")

def _get_vt_gui_url(ioc: str, ioc_type: str) -> str:
    """
    Constructs the VirusTotal GUI URL for the given IOC.

    Args:
        ioc (str): The Indicator of Compromise (IOC) string.
        ioc_type (str): The type of the IOC ("ip", "hash", "domain").

    Returns:
        str: The VirusTotal GUI URL.
    """
    if ioc_type == "hash":
        return f"https://www.virustotal.com/gui/file/{ioc}/detection"
    elif ioc_type == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{ioc}/information"
    elif ioc_type == "domain":
        return f"https://www.virustotal.com/gui/domain/{ioc}/information"
    return "" # Should not happen due to _validate_ioc

def _normalize_vt_response(ioc: str, ioc_type: str, vt_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes the raw VirusTotal JSON response into a structured dictionary.

    Args:
        ioc (str): The Indicator of Compromise (IOC) string.
        ioc_type (str): The type of the IOC ("ip", "hash", "domain").
        vt_json (Dict[str, Any]): The raw JSON response from VirusTotal API.

    Returns:
        Dict[str, Any]: The normalized dictionary.
    """
    data = vt_json.get("data", {})
    attributes = data.get("attributes", {})

    last_analysis_stats = attributes.get("last_analysis_stats", {})
    malicious_votes = last_analysis_stats.get("malicious", 0)

    # For files, first_submission_date and last_analysis_date are directly in attributes
    # For IP/Domain, they might be nested differently or not present in the same way.
    # We'll try to get them if available.
    first_submission_date = attributes.get("first_submission_date", None)
    last_analysis_date = attributes.get("last_analysis_date", None)

    # Convert timestamps to int if they exist
    if first_submission_date is not None:
        first_submission_date = int(first_submission_date)
    if last_analysis_date is not None:
        last_analysis_date = int(last_analysis_date)

    return {
        "source": "VirusTotal",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "fetched_at": time.time(),
        "raw": vt_json,
        "vt_summary": {
            "last_analysis_stats": last_analysis_stats,
            "malicious_votes": malicious_votes,
            "first_submission_date": first_submission_date,
            "last_analysis_date": last_analysis_date,
        },
        "links": {
            "vt_url": _get_vt_gui_url(ioc, ioc_type)
        }
    }

# --- Main Function ---
def vt_lookup(ioc: str, ioc_type: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Performs a VirusTotal v3 API lookup for a given IOC.

    Args:
        ioc (str): The Indicator of Compromise (IOC) string (e.g., SHA256 hash, IPv4, domain).
        ioc_type (str): The type of the IOC ("ip", "hash", "domain").
        timeout (int): Request timeout in seconds.

    Returns:
        Dict[str, Any]: A normalized dictionary containing VirusTotal information.

    Raises:
        ValueError: If ioc_type is invalid or ioc format is incorrect.
        VTLookupError: For API errors, network issues, or if VT_API_KEY is missing.
    """
    if not VT_API_KEY:
        raise VTLookupError("VT_API_KEY environment variable is not set.")

    _validate_ioc(ioc, ioc_type)

    endpoint_map = {
        "hash": f"{VT_API_BASE_URL}/files/{ioc}",
        "ip": f"{VT_API_BASE_URL}/ip_addresses/{ioc}",
        "domain": f"{VT_API_BASE_URL}/domains/{ioc}",
    }
    url = endpoint_map.get(ioc_type)
    if not url: # Should be caught by _validate_ioc, but as a safeguard
        raise ValueError(f"Internal error: No endpoint for IOC type '{ioc_type}'.")

    headers = {"x-apikey": VT_API_KEY}
    max_retries = 3
    retry_delay = 1  # seconds
    
    logger.info(f"Starting VirusTotal lookup for {ioc_type}: {ioc}")

    for attempt in range(max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            logger.info(f"Successfully fetched data for {ioc_type}: {ioc}")
            return _normalize_vt_response(ioc, ioc_type, response.json())

        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                logger.warning(f"IOC not found on VirusTotal: {ioc_type}: {ioc}")
                # Return a normalized structure indicating not found
                return {
                    "source": "VirusTotal",
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "fetched_at": time.time(),
                    "raw": response.json() if response.content else {},
                    "vt_summary": {
                        "last_analysis_stats": {},
                        "malicious_votes": 0,
                        "first_submission_date": None,
                        "last_analysis_date": None,
                    },
                    "links": {
                        "vt_url": _get_vt_gui_url(ioc, ioc_type)
                    },
                    "status": "not_found"
                }
            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", retry_delay))
                logger.warning(f"Rate limit hit for {ioc_type}: {ioc}. Retrying in {retry_after}s (Attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    time.sleep(retry_after)
                    retry_delay *= 2 # Exponential backoff for next retry
                else:
                    raise VTLookupError(f"Max retries exceeded for {ioc_type}: {ioc} due to rate limiting.") from e
            elif 500 <= response.status_code < 600:
                logger.warning(f"Server error ({response.status_code}) for {ioc_type}: {ioc}. Retrying in {retry_delay}s (Attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= 2 # Exponential backoff
                else:
                    raise VTLookupError(f"Max retries exceeded for {ioc_type}: {ioc} due to server error ({response.status_code}).") from e
            else:
                raise VTLookupError(f"HTTP error {response.status_code} for {ioc_type}: {ioc}: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.error(f"Network or request error for {ioc_type}: {ioc}: {e}")
            if attempt < max_retries:
                logger.info(f"Retrying in {retry_delay}s (Attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                raise VTLookupError(f"Max retries exceeded for {ioc_type}: {ioc} due to network error.") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred for {ioc_type}: {ioc}: {e}")
            raise VTLookupError(f"An unexpected error occurred during lookup for {ioc_type}: {ioc}.") from e

    # This part should ideally not be reached if max_retries is handled correctly
    raise VTLookupError(f"Failed to lookup {ioc_type}: {ioc} after multiple attempts.")
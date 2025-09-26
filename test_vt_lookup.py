import pytest
import os
import time
from unittest.mock import patch, MagicMock
import requests_mock
import requests

# Assuming vt_lookup.py is in the same directory or importable
from vt_lookup import vt_lookup, VTLookupError, SHA256_REGEX, IPV4_REGEX, DOMAIN_REGEX

# Mock the VT_API_KEY for all tests
@pytest.fixture(autouse=True)
def mock_env_vars():
    with patch.dict(os.environ, {"VT_API_KEY": "test_api_key"}):
        yield

# Test for successful hash lookup
def test_successful_hash_lookup(requests_mock):
    test_hash = "a" * 64
    mock_response_data = {
        "data": {
            "id": test_hash,
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 50,
                    "malicious": 5,
                    "suspicious": 1,
                    "undetected": 10,
                    "timeout": 0
                },
                "first_submission_date": 1600000000,
                "last_analysis_date": 1690000000,
                "meaningless_field": "some_value"
            }
        }
    }
    requests_mock.get(f"https://www.virustotal.com/api/v3/files/{test_hash}", json=mock_response_data, status_code=200)

    result = vt_lookup(test_hash, "hash")

    assert result["source"] == "VirusTotal"
    assert result["ioc"] == test_hash
    assert result["ioc_type"] == "hash"
    assert "fetched_at" in result
    assert result["raw"] == mock_response_data
    assert result["vt_summary"]["malicious_votes"] == 5
    assert result["vt_summary"]["last_analysis_stats"] == mock_response_data["data"]["attributes"]["last_analysis_stats"]
    assert result["vt_summary"]["first_submission_date"] == 1600000000
    assert result["vt_summary"]["last_analysis_date"] == 1690000000
    assert result["links"]["vt_url"] == f"https://www.virustotal.com/gui/file/{test_hash}/detection"
    assert "status" not in result # Should not have status for successful lookup

# Test for IP lookup with rate-limit and retry behavior
def test_rate_limit_and_retry(requests_mock):
    test_ip = "1.1.1.1"
    mock_success_data = {
        "data": {
            "id": test_ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 70,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 5,
                    "timeout": 0
                },
                "first_submission_date": None, # Example: IP might not have this
                "last_analysis_date": 1690000000
            }
        }
    }

    # First request: 429 with Retry-After
    # Second request: Success
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        [
            {'status_code': 429, 'headers': {'Retry-After': '1'}, 'json': {'error': 'rate limit'}},
            {'json': mock_success_data, 'status_code': 200},
        ]
    )

    with patch("time.sleep", return_value=None) as mock_sleep:
        result = vt_lookup(test_ip, "ip", timeout=5) # Use a short timeout for testing

        assert requests_mock.call_count == 2
        mock_sleep.assert_called_once_with(1) # Ensure sleep was called with Retry-After value

        assert result["ioc"] == test_ip
        assert result["vt_summary"]["malicious_votes"] == 0
        assert result["links"]["vt_url"] == f"https://www.virustotal.com/gui/ip-address/{test_ip}/information"

# Test for invalid ioc_type
def test_invalid_ioc_type():
    with pytest.raises(ValueError, match="Unsupported IOC type: unknown"):
        vt_lookup("some_value", "unknown")

# Test for invalid ioc format for a given type
def test_invalid_ioc_format():
    with pytest.raises(ValueError, match="Invalid SHA256 hash format"):
        vt_lookup("not_a_sha256_hash", "hash")

    with pytest.raises(ValueError, match="Invalid IPv4 address format"):
        vt_lookup("999.999.999.999", "ip")

    with pytest.raises(ValueError, match="Invalid domain format"):
        vt_lookup("not a domain", "domain")

# Test for missing API key
def test_missing_api_key():
    with patch('vt_lookup.VT_API_KEY', None):
        with pytest.raises(VTLookupError, match=r"VT_API_KEY environment variable is not set\."):
            vt_lookup("8.8.8.8", "ip")

# Test for IOC not found (404)
def test_ioc_not_found(requests_mock):
    test_domain = "nonexistent-domain.com"
    requests_mock.get(f"https://www.virustotal.com/api/v3/domains/{test_domain}", status_code=404, json={"error": {"code": "NotFoundError"}})

    result = vt_lookup(test_domain, "domain")

    assert result["ioc"] == test_domain
    assert result["ioc_type"] == "domain"
    assert result["status"] == "not_found"
    assert result["vt_summary"]["malicious_votes"] == 0
    assert result["raw"] == {"error": {"code": "NotFoundError"}}

# Test for server error (500) and retry
def test_server_error_and_retry(requests_mock):
    test_ip = "2.2.2.2"
    mock_success_data = {
        "data": {
            "id": test_ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {"malicious": 1},
                "last_analysis_date": 1690000000
            }
        }
    }

    # First request: 500 Internal Server Error
    # Second request: Success
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        [
            {'status_code': 500, 'text': 'Server Error'},
            {'json': mock_success_data, 'status_code': 200},
        ]
    )

    with patch("time.sleep", return_value=None) as mock_sleep:
        result = vt_lookup(test_ip, "ip", timeout=5)

        assert requests_mock.call_count == 2
        mock_sleep.assert_called_once_with(1) # Default retry_delay is 1s

        assert result["ioc"] == test_ip
        assert result["vt_summary"]["malicious_votes"] == 1

# Test for network error and retry
def test_network_error_and_retry(requests_mock):
    test_ip = "3.3.3.3"
    mock_success_data = {
        "data": {
            "id": test_ip,
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "last_analysis_date": 1690000000
            }
        }
    }

    # First request: ConnectionError
    # Second request: Success
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        [
            {'exc': requests.exceptions.ConnectionError},
            {'json': mock_success_data, 'status_code': 200},
        ]
    )

    with patch("time.sleep", return_value=None) as mock_sleep:
        result = vt_lookup(test_ip, "ip", timeout=5)

        assert requests_mock.call_count == 2
        mock_sleep.assert_called_once_with(1) # Default retry_delay is 1s

        assert result["ioc"] == test_ip
        assert result["vt_summary"]["malicious_votes"] == 0

# Test for max retries exceeded (rate limit)
def test_max_retries_rate_limit(requests_mock):
    test_ip = "4.4.4.4"
    # Mock 4 consecutive 429 responses
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        status_code=429, 
        headers={"Retry-After": "1"}, 
        json={"error": {"code": "QuotaExceededError"}}
    )

    with patch("time.sleep", return_value=None):
        with pytest.raises(VTLookupError, match="Max retries exceeded.*rate limiting."):
            vt_lookup(test_ip, "ip", timeout=5)
        assert requests_mock.call_count == 4 # Initial call + 3 retries

# Test for max retries exceeded (server error)
def test_max_retries_server_error(requests_mock):
    test_ip = "5.5.5.5"
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        status_code=500
    )

    with patch("time.sleep", return_value=None):
        with pytest.raises(VTLookupError, match="Max retries exceeded.*server error."):
            vt_lookup(test_ip, "ip", timeout=5)
        assert requests_mock.call_count == 4 # Initial call + 3 retries

# Test for max retries exceeded (network error)
def test_max_retries_network_error(requests_mock):
    test_ip = "6.6.6.6"
    requests_mock.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{test_ip}",
        exc=requests.exceptions.ConnectionError
    )

    with patch("time.sleep", return_value=None):
        with pytest.raises(VTLookupError, match="Max retries exceeded.*network error."):
            vt_lookup(test_ip, "ip", timeout=5)
        assert requests_mock.call_count == 4 # Initial call + 3 retries
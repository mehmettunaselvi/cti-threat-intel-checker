### VirusTotal Lookup

This module provides a wrapper for the VirusTotal v3 API to lookup Indicators of Compromise (IOCs) such as SHA256 hashes, IPv4 addresses, and domains. It includes retry logic for rate limits and normalizes the API response into a consistent dictionary format.

**Setup:**

1.  Obtain a VirusTotal API key.
2.  Add your API key to your `.env` file in the project root:
    ```
    VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
    ```

**Usage Example:**

```python
from vt_lookup import vt_lookup, VTLookupError

try:
    # Lookup an IP address
    ip_result = vt_lookup("8.8.8.8", "ip")
    print("IP Lookup Summary:", ip_result["vt_summary"])
    print("VT URL:", ip_result["links"]["vt_url"])

    # Lookup a SHA256 hash
    hash_result = vt_lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2bd44ce10c0542bb2d164c", "hash")
    print("Hash Lookup Summary:", hash_result["vt_summary"])

    # Lookup a domain
    domain_result = vt_lookup("example.com", "domain")
    print("Domain Lookup Summary:", domain_result["vt_summary"])

except VTLookupError as e:
    print(f"VirusTotal Lookup Error: {e}")
except ValueError as e:
    print(f"Input Validation Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
```
import requests
from dotenv import load_dotenv
import os
from typing import Dict, Optional

load_dotenv()


def enrich_ioc(ioc: str, ioc_type: str = 'ip') -> Dict:
    """Enrich IOC with threat intelligence.
    
    Args:
        ioc: Indicator of compromise (IP, hash, etc.)
        ioc_type: Type of IOC ('ip', 'hash', 'domain')
    
    Returns:
        Dictionary with enrichment data
    """
    if ioc_type == 'ip':
        try:
            url = f"https://www.abuseipdb.com/check/{ioc}/json?key={os.getenv('ABUSEIPDB_KEY')}"
            response = requests.get(url, timeout=5)
            if response.ok:
                return response.json()
        except Exception as e:
            print(f"AbuseIPDB enrichment error: {e}")
    
    elif ioc_type == 'hash':
        try:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            headers = {"x-apikey": os.getenv('VT_API_KEY')}
            response = requests.get(url, headers=headers, timeout=5)
            if response.ok:
                return response.json()
        except Exception as e:
            print(f"VirusTotal enrichment error: {e}")
    
    return {'error': 'Enrichment failed or API key missing'}


def enrich_batch(iocs: list, ioc_type: str = 'ip') -> list:
    """Enrich multiple IOCs.
    
    Args:
        iocs: List of IOCs
        ioc_type: Type of IOCs
    
    Returns:
        List of enriched IOCs
    """
    results = []
    for ioc in iocs:
        enriched = enrich_ioc(ioc, ioc_type)
        results.append({'ioc': ioc, 'enrichment': enriched})
    return results

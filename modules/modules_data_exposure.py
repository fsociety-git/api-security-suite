import requests
import re

def test_data_exposure(endpoint):
    patterns = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "api_key": r"(?i)api[-_]?key\s*[:=]\s*[\w-]{20,}",
        "password": r"(?i)password\s*[:=]\s*\S+"
    }
    response = requests.get(endpoint)
    results = []
    for name, pat in patterns.items():
        matches = re.findall(pat, response.text)
        if matches:
            results.append({"type": name, "matches": matches, "vulnerable": True, "cvss": 9.8, "advice": "Redact sensitive data; use encryption."})
    return {"data_exposure_tests": results}
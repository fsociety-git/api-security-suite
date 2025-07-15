import requests
import time

def test_rate_limit(url, attempts=10):
    results = []
    start = time.time()
    for i in range(attempts):
        response = requests.get(url)
        if response.status_code == 429:
            results.append({"attempt": i, "blocked": True, "cvss": 5.3 if i > 5 else 0, "advice": "Implement exponential backoff."})
            break
        time.sleep(0.1)  # Rapid fire
    elapsed = time.time() - start
    if len(results) == 0:
        results.append({"test": "no_rate_limit", "vulnerable": True, "cvss": 7.5, "advice": "Add rate limiting headers/middleware."})
    return {"rate_limit_tests": results}
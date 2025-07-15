import requests

def test_injection(endpoint, param):
    payloads = {
        "sql": ["' OR '1'='1", "'; DROP TABLE users; --"],
        "nosql": [{"$ne": None}, {"$gt": ""}],
        "command": ["; ls", "&& echo vulnerable"]
    }
    results = []
    for inj_type, pl_list in payloads.items():
        for payload in pl_list:
            params = {param: payload}
            response = requests.get(endpoint, params=params)
            if "syntax error" in response.text.lower() or "vulnerable" in response.text:
                results.append({"type": inj_type, "payload": str(payload), "vulnerable": True, "cvss": 8.8, "advice": "Use prepared statements/param binding."})
            else:
                results.append({"type": inj_type, "payload": str(payload), "vulnerable": False})
    return {"injection_tests": results}

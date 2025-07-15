import requests
import jwt

def test_auth(url, jwt_token=None):
    results = []
    # Missing auth
    response = requests.get(url)
    if response.status_code == 200:
        results.append({"test": "missing_auth", "vulnerable": True, "cvss": 7.5, "advice": "Implement auth checks."})

    # Weak tokens (simple check)
    weak_payloads = ["admin:admin", "token=123"]
    for payload in weak_payloads:
        headers = {"Authorization": f"Basic {payload}"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            results.append({"test": "weak_token", "payload": payload, "vulnerable": True, "cvss": 6.5, "advice": "Use strong, random tokens."})

    # JWT vulns
    if jwt_token:
        try:
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            if decoded.get('alg') == 'none':
                results.append({"test": "jwt_none_alg", "vulnerable": True, "cvss": 9.1, "advice": "Reject 'none' algorithm."})
        except:
            pass

    return {"auth_tests": results}

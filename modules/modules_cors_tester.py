import requests

def test_cors(url, origins_file):
    results = []
    with open(origins_file, 'r') as f:
        origins = [o.strip() for o in f.readlines()]
    for origin in origins:
        headers = {"Origin": origin}
        response = requests.options(url, headers=headers)
        acao = response.headers.get("Access-Control-Allow-Origin")
        if acao == "*" or acao == origin:
            results.append({"origin": origin, "vulnerable": True if acao == "*" else False, "cvss": 6.1, "advice": "Restrict origins; avoid '*'. "})
    return {"cors_tests": results}
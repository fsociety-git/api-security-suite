import requests
import concurrent.futures

def fuzz_single(endpoint, payload):
    params = {"fuzz": payload}
    response = requests.get(endpoint, params=params)
    return {"payload": payload, "status": response.status_code, "anomalous": response.status_code >= 500}

def fuzz_api(endpoint, payloads_file, threads=10):
    with open(payloads_file, 'r') as f:
        payloads = [p.strip() for p in f.readlines()]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(fuzz_single, endpoint, p) for p in payloads]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res["anomalous"]:
                res.update({"vulnerable": True, "cvss": 7.5, "advice": "Validate inputs; handle errors gracefully."})
            results.append(res)
    return {"fuzz_tests": results}

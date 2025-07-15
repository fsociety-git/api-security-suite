import argparse
import concurrent.futures
import yaml
from modules.auth_tester import test_auth
from modules.injection_tester import test_injection
from modules.rate_limit_tester import test_rate_limit
from modules.cors_tester import test_cors
from modules.data_exposure import test_data_exposure
from modules.api_fuzzer import fuzz_api
from utils.report_generator import generate_report

def load_config(config_file):
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def run_test(func, *args):
    return func(*args)

def main():
    parser = argparse.ArgumentParser(description="API Security Testing Suite")
    subparsers = parser.add_subparsers(dest="command")

    # Common args
    for sp in subparsers.choices.values():
        sp.add_argument("--config", default="tests/config.yaml", help="YAML config file")

    # Full scan
    full_parser = subparsers.add_parser("full", help="Run all tests")
    full_parser.add_argument("--threads", default=5, type=int, help="Concurrent threads")
    full_parser.add_argument("--report-format", default="json", help="html,json or both")

    # Auth
    auth_parser = subparsers.add_parser("auth", help="Authentication tests")
    auth_parser.add_argument("--url", help="API URL")
    auth_parser.add_argument("--jwt-token", help="JWT to test")

    # Injection
    inj_parser = subparsers.add_parser("injection", help="Injection tests")
    inj_parser.add_argument("--endpoint", help="Endpoint")
    inj_parser.add_argument("--param", help="Param to inject")

    # Rate Limit
    rl_parser = subparsers.add_parser("rate_limit", help="Rate limit tests")
    rl_parser.add_argument("--url", help="URL")
    rl_parser.add_argument("--attempts", default=10, type=int)

    # CORS
    cors_parser = subparsers.add_parser("cors", help="CORS tests")
    cors_parser.add_argument("--url", help="URL")
    cors_parser.add_argument("--origins", default="payloads/origins.txt")

    # Data Exposure
    de_parser = subparsers.add_parser("data_exposure", help="Data exposure tests")
    de_parser.add_argument("--endpoint", help="Endpoint")

    # Fuzzer
    fuzz_parser = subparsers.add_parser("fuzz", help="API fuzzer")
    fuzz_parser.add_argument("--endpoint", help="Endpoint")
    fuzz_parser.add_argument("--payloads", default="payloads/fuzz.txt")
    fuzz_parser.add_argument("--threads", default=10, type=int)

    args = parser.parse_args()
    config = load_config(args.config)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads if hasattr(args, 'threads') else 5) as executor:
        if args.command == "full":
            futures = [
                executor.submit(run_test, test_auth, config['auth']['url'], config['auth'].get('jwt')),
                executor.submit(run_test, test_injection, config['injection']['endpoint'], config['injection']['param']),
                executor.submit(run_test, test_rate_limit, config['rate_limit']['url'], config['rate_limit']['attempts']),
                executor.submit(run_test, test_cors, config['cors']['url'], config['cors']['origins']),
                executor.submit(run_test, test_data_exposure, config['data_exposure']['endpoint']),
                executor.submit(run_test, fuzz_api, config['fuzz']['endpoint'], config['fuzz']['payloads'], args.threads)
            ]
            for future in concurrent.futures.as_completed(futures):
                results.update(future.result())
        elif args.command == "auth":
            results = test_auth(args.url or config['auth']['url'], args.jwt_token or config['auth'].get('jwt'))
        elif args.command == "injection":
            results = test_injection(args.endpoint or config['injection']['endpoint'], args.param or config['injection']['param'])
        elif args.command == "rate_limit":
            results = test_rate_limit(args.url or config['rate_limit']['url'], args.attempts or config['rate_limit']['attempts'])
        elif args.command == "cors":
            results = test_cors(args.url or config['cors']['url'], args.origins or config['cors']['origins'])
        elif args.command == "data_exposure":
            results = test_data_exposure(args.endpoint or config['data_exposure']['endpoint'])
        elif args.command == "fuzz":
            results = fuzz_api(args.endpoint or config['fuzz']['endpoint'], args.payloads or config['fuzz']['payloads'], args.threads)
        else:
            parser.print_help()
            return

    formats = args.report_format.split(',') if hasattr(args, 'report_format') else ['json']
    generate_report(results, formats)
    print("Tests complete. Reports generated.")

if __name__ == "__main__":
    main()
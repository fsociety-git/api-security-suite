# src/__main__.py
import argparse
import yaml
import json
import sys
from pathlib import Path
from . import APISecurityTester
from .modules import AuthTester, InjectionTester, CORSTester, RateLimitTester, DataExposureTester, APIFuzzer

def load_config(config_file):
    """Load configuration from YAML file"""
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(
        description='API Security Testing Suite - Professional API vulnerability scanner'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('--config', required=True, help='Configuration file path')
    scan_parser.add_argument('--output', default='results.json', help='Output file for results')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run specific test module')
    test_parser.add_argument('module', choices=['auth', 'injection', 'cors', 'ratelimit', 'exposure', 'fuzz'])
    test_parser.add_argument('--url', required=True, help='Target API base URL')
    test_parser.add_argument('--token', help='Authentication token')
    test_parser.add_argument('--endpoints', nargs='+', help='Specific endpoints to test')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report from results')
    report_parser.add_argument('--input', required=True, help='Input results file')
    report_parser.add_argument('--format', choices=['html', 'json', 'pdf'], default='html')
    report_parser.add_argument('--output', default='report.html', help='Output report file')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'test':
        run_test(args)
    elif args.command == 'report':
        generate_report(args)
    else:
        parser.print_help()

def run_scan(args):
    """Run full security scan"""
    config = load_config(args.config)
    
    # Initialize tester
    auth = config.get('authentication', {})
    tester = APISecurityTester(
        base_url=config['target']['base_url'],
        auth_token=auth.get('token'),
        api_key=auth.get('api_key')
    )
    
    # Get endpoints from config
    endpoints = []
    for endpoint_config in config['target'].get('endpoints', []):
        endpoints.append(endpoint_config['path'])
    
    # Run scan
    print(f"[*] Starting security scan on {config['target']['base_url']}")
    results = tester.run_full_scan(endpoints=endpoints)
    
    # Run additional modules if enabled
    if config['tests'].get('cors_testing'):
        print("[*] Testing CORS configuration...")
        cors_tester = CORSTester(tester.client)
        results['vulnerabilities'].extend(cors_tester.run_tests(endpoints))
    
    if config['tests'].get('rate_limit_testing'):
        print("[*] Testing rate limiting...")
        rate_tester = RateLimitTester(tester.client)
        results['vulnerabilities'].extend(rate_tester.run_tests())
    
    if config['tests'].get('data_exposure_testing'):
        print("[*] Testing for data exposure...")
        exposure_tester = DataExposureTester(tester.client)
        results['vulnerabilities'].extend(exposure_tester.run_tests(endpoints))
    
    if config['tests'].get('fuzzing'):
        print("[*] Running fuzzer...")
        fuzzer = APIFuzzer(tester.client)
        results['vulnerabilities'].extend(fuzzer.run_tests(endpoints))
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[*] Scan complete! Found {len(results['vulnerabilities'])} vulnerabilities")
    print(f"[*] Results saved to {args.output}")

def run_test(args):
    """Run specific test module"""
    from .core.http_client import HTTPClient
    
    client = HTTPClient(args.url, auth_token=args.token)
    
    module_map = {
        'auth': AuthTester,
        'injection': InjectionTester,
        'cors': CORSTester,
        'ratelimit': RateLimitTester,
        'exposure': DataExposureTester,
        'fuzz': APIFuzzer
    }
    
    tester_class = module_map[args.module]
    tester = tester_class(client)
    
    print(f"[*] Running {args.module} tests on {args.url}")
    vulnerabilities = tester.run_tests(args.endpoints)
    
    print(f"\n[*] Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']}: {vuln['description']}")
    
    # Save results
    results = {
        'target': args.url,
        'module': args.module,
        'vulnerabilities': vulnerabilities
    }
    
    with open(f'{args.module}_results.json', 'w') as f:
        json.dump(results, f, indent=2)

def generate_report(args):
    """Generate report from results"""
    from .core.report_generator import ReportGenerator
    
    # Load results
    with open(args.input, 'r') as f:
        results = json.load(f)
    
    # Generate report
    generator = ReportGenerator()
    report = generator.generate(results, args.format)
    
    # Save report
    if args.format == 'json':
        with open(args.output, 'w') as f:
            f.write(report)
    else:
        with open(args.output, 'w') as f:
            f.write(report)
    
    print(f"[*] Report generated: {args.output}")

if __name__ == "__main__":
    main()

# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="api-security-suite",
    version="1.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="Comprehensive API Security Testing Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/api-security-suite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0",
        "colorama>=0.4.6",
        "urllib3>=2.0.0",
        "python-jose>=3.3.0",
        "faker>=18.0.0",
        "jinja2>=3.1.2",
        "beautifulsoup4>=4.12.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "api-security-suite=src.__main__:main",
        ],
    },
)

# config/config.yaml
# API Security Suite Configuration

target:
  base_url: "https://api.example.com"
  endpoints:
    - path: "/api/v1/users"
      methods: ["GET", "POST", "PUT", "DELETE"]
      test_params:
        - name: "id"
          type: "integer"
        - name: "username"
          type: "string"
    
    - path: "/api/v1/products"
      methods: ["GET", "POST"]
      test_params:
        - name: "category"
          type: "string"
        - name: "price"
          type: "number"
    
    - path: "/api/v1/search"
      methods: ["GET"]
      test_params:
        - name: "q"
          type: "string"
    
    - path: "/api/v1/login"
      methods: ["POST"]
      body_params:
        - name: "username"
          type: "string"
        - name: "password"
          type: "string"

authentication:
  type: "bearer"  # Options: bearer, basic, api_key, oauth2
  token: "your-bearer-token-here"
  # For API key auth:
  # type: "api_key"
  # api_key: "your-api-key"
  # api_key_header: "X-API-Key"  # Header name for API key
  
  # For Basic auth:
  # type: "basic"
  # username: "user"
  # password: "pass"
  
  # For OAuth2:
  # type: "oauth2"
  # client_id: "your-client-id"
  # client_secret: "your-client-secret"
  # token_url: "https://api.example.com/oauth/token"

tests:
  auth_testing: true
  injection_testing: true
  cors_testing: true
  rate_limit_testing: true
  data_exposure_testing: true
  fuzzing: true
  
  # Test-specific configurations
  injection:
    test_sql: true
    test_nosql: true
    test_command: true
    test_xxe: true
    test_ldap: true
  
  rate_limiting:
    requests_per_test: 100
    concurrent_requests: 10
  
  fuzzing:
    iterations_per_endpoint: 50
    timeout: 30

options:
  timeout: 30  # Request timeout in seconds
  max_concurrent_requests: 10
  verbose: true
  save_requests: true  # Save all requests/responses for analysis
  follow_redirects: false
  verify_ssl: true
  
  # Proxy configuration (optional)
  # proxy:
  #   http: "http://localhost:8080"
  #   https: "http://localhost:8080"

reporting:
  formats: ["html", "json"]  # Generate reports in these formats
  include_request_samples: true
  include_remediation: true
  severity_threshold: "low"  # Only report vulnerabilities of this severity or higher

# CONTRIBUTING.md
# Contributing to API Security Testing Suite

We love your input! We want to make contributing to this project as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code follows PEP 8.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License
When you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project.

## Report bugs using Github's [issues](https://github.com/yourusername/api-security-suite/issues)
We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/yourusername/api-security-suite/issues/new).

## License
By contributing, you agree that your contributions will be licensed under its MIT License.
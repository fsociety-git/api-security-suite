# API Security Testing Suite

A comprehensive toolkit for testing REST API security vulnerabilities during authorized penetration tests and security assessments.

## ⚠️ Legal Notice

This tool is designed for **authorized security testing only**. Always ensure you have explicit written permission before testing any API. Unauthorized testing is illegal and unethical.

## Features

- **Authentication Testing**: Test for weak authentication mechanisms, token vulnerabilities
- **Authorization Testing**: Check for broken access controls, privilege escalation
- **Input Validation**: Test for injection vulnerabilities (SQL, NoSQL, Command injection)
- **Rate Limiting**: Verify rate limiting and anti-automation controls
- **Data Exposure**: Check for sensitive data leaks in responses
- **CORS Testing**: Validate Cross-Origin Resource Sharing policies
- **API Fuzzing**: Automated fuzzing for unexpected inputs
- **SSL/TLS Testing**: Verify secure communication configurations

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/api-security-suite.git
cd api-security-suite

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Project Structure

```
api-security-suite/
├── README.md
├── requirements.txt
├── setup.py
├── config/
│   └── config.yaml
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── http_client.py
│   │   ├── report_generator.py
│   │   └── logger.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── auth_tester.py
│   │   ├── injection_tester.py
│   │   ├── cors_tester.py
│   │   ├── rate_limit_tester.py
│   │   ├── data_exposure_tester.py
│   │   └── fuzzer.py
│   └── utils/
│       ├── __init__.py
│       ├── payloads.py
│       └── parsers.py
├── tests/
│   ├── __init__.py
│   └── test_modules.py
├── reports/
│   └── .gitkeep
└── examples/
    ├── basic_scan.py
    └── config_example.yaml
```

## Quick Start

### Basic Usage

```python
from api_security_suite import APISecurityTester

# Initialize the tester
tester = APISecurityTester(
    base_url="https://api.example.com",
    api_key="your-api-key"  # Or use other auth methods
)

# Run all security tests
results = tester.run_full_scan()

# Generate report
tester.generate_report(results, format="html")
```

### Configuration File

Create a `config.yaml` file:

```yaml
target:
  base_url: "https://api.example.com"
  endpoints:
    - path: "/api/v1/users"
      methods: ["GET", "POST", "PUT", "DELETE"]
    - path: "/api/v1/products"
      methods: ["GET", "POST"]

authentication:
  type: "bearer"  # Options: bearer, basic, api_key, oauth2
  token: "your-token-here"

tests:
  auth_testing: true
  injection_testing: true
  cors_testing: true
  rate_limit_testing: true
  data_exposure_testing: true
  fuzzing: true

options:
  timeout: 30
  max_concurrent_requests: 10
  verbose: true
  save_requests: true
```

## Modules

### Authentication Testing
```python
from api_security_suite.modules import AuthTester

auth_tester = AuthTester(base_url="https://api.example.com")
results = auth_tester.test_authentication_bypass()
```

### Injection Testing
```python
from api_security_suite.modules import InjectionTester

injection_tester = InjectionTester(base_url="https://api.example.com")
results = injection_tester.test_sql_injection(endpoint="/api/users")
```

### Rate Limiting Testing
```python
from api_security_suite.modules import RateLimitTester

rate_tester = RateLimitTester(base_url="https://api.example.com")
results = rate_tester.test_rate_limits(endpoint="/api/login")
```

## Command Line Interface

```bash
# Run full security scan
python -m api_security_suite scan --config config.yaml

# Test specific module
python -m api_security_suite test auth --url https://api.example.com

# Generate report from previous scan
python -m api_security_suite report --input results.json --format pdf
```

## Test Cases Included

### Authentication & Authorization
- Missing authentication
- Weak token generation
- Token prediction
- Session fixation
- Privilege escalation
- JWT vulnerabilities

### Input Validation
- SQL Injection
- NoSQL Injection
- Command Injection
- XSS in API responses
- XXE attacks
- Path traversal

### Business Logic
- Race conditions
- Price manipulation
- Workflow bypass
- Rate limiting bypass

### Data Security
- Sensitive data in responses
- PII exposure
- Excessive data exposure
- Debug information leakage

## Reporting

The suite generates detailed reports including:
- Executive summary
- Vulnerability details with CVSS scores
- Proof of concept requests
- Remediation recommendations
- Compliance mapping (OWASP API Top 10)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


## Disclaimer

This tool is provided for educational and professional security testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this tool.

## Acknowledgments

- OWASP API Security Top 10
- Security community contributors
- Open source security tools that inspired this project

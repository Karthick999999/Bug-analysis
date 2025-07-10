#!/usr/bin/env python3
"""
Test script for AutoRedTeam
Verifies that all modules can be imported and basic functionality works
"""

import sys
import os

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        from autoredteam.crawler import crawl, WebCrawler
        print("✓ crawler.py imported successfully")
    except ImportError as e:
        print(f"✗ Error importing crawler.py: {e}")
        return False
    
    try:
        from autoredteam.scanner import test_sqli, test_xss, VulnerabilityScanner
        print("✓ scanner.py imported successfully")
    except ImportError as e:
        print(f"✗ Error importing scanner.py: {e}")
        return False
    
    try:
        from autoredteam.report import generate_report, VulnerabilityReport
        print("✓ report.py imported successfully")
    except ImportError as e:
        print(f"✗ Error importing report.py: {e}")
        return False
    
    try:
        from autoredteam.model import (
            Vulnerability, VulnerabilityType, RiskLevel, 
            ScanConfig, ScanResult, ConfigManager, PayloadManager
        )
        print("✓ model.py imported successfully")
    except ImportError as e:
        print(f"✗ Error importing model.py: {e}")
        return False
    
    try:
        from autoredteam.main import AutoRedTeam
        print("✓ main.py imported successfully")
    except ImportError as e:
        print(f"✗ Error importing main.py: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of each module"""
    print("\nTesting basic functionality...")
    
    try:
        # Test model functionality
        from autoredteam.model import Vulnerability, VulnerabilityType, RiskLevel, ConfigManager
        
        # Test vulnerability creation
        vuln = Vulnerability(
            url="http://test.com/page.php?id=1",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            risk_level=RiskLevel.HIGH,
            description="Test vulnerability"
        )
        print("✓ Vulnerability model works")
        
        # Test config manager
        config_manager = ConfigManager()
        config = config_manager.load_config()
        print("✓ Config manager works")
        
        # Test payload manager
        from autoredteam.model import PayloadManager
        payload_manager = PayloadManager()
        sqli_payloads = payload_manager.get_payloads(VulnerabilityType.SQL_INJECTION)
        xss_payloads = payload_manager.get_payloads(VulnerabilityType.XSS)
        print(f"✓ Payload manager works ({len(sqli_payloads)} SQLi, {len(xss_payloads)} XSS payloads)")
        
    except Exception as e:
        print(f"✗ Error testing basic functionality: {e}")
        return False
    
    return True

def test_crawler():
    """Test crawler functionality"""
    print("\nTesting crawler...")
    
    try:
        from autoredteam.crawler import WebCrawler
        
        # Test crawler initialization
        crawler = WebCrawler(max_urls=5)
        print("✓ WebCrawler initialized")
        
        # Test URL validation
        is_valid = crawler.is_valid_url("http://test.com/page", "http://test.com")
        print(f"✓ URL validation works: {is_valid}")
        
    except Exception as e:
        print(f"✗ Error testing crawler: {e}")
        return False
    
    return True

def test_scanner():
    """Test scanner functionality"""
    print("\nTesting scanner...")
    
    try:
        from autoredteam.scanner import VulnerabilityScanner
        
        # Test scanner initialization
        scanner = VulnerabilityScanner()
        print("✓ VulnerabilityScanner initialized")
        
        # Test payload lists
        print(f"✓ SQLi payloads: {len(scanner.sqli_payloads)}")
        print(f"✓ XSS payloads: {len(scanner.xss_payloads)}")
        
    except Exception as e:
        print(f"✗ Error testing scanner: {e}")
        return False
    
    return True

def test_report():
    """Test report functionality"""
    print("\nTesting report generation...")
    
    try:
        from autoredteam.report import VulnerabilityReport
        
        # Test report initialization
        report = VulnerabilityReport()
        print("✓ VulnerabilityReport initialized")
        
        # Test report sections
        test_results = [
            {'url': 'http://test.com/page1', 'vuln': 'SQL Injection'},
            {'url': 'http://test.com/page2', 'vuln': 'XSS'}
        ]
        
        summary = report.create_executive_summary(test_results)
        details = report.create_vulnerability_details(test_results)
        recommendations = report.create_recommendations()
        
        print("✓ Report sections created successfully")
        
    except Exception as e:
        print(f"✗ Error testing report: {e}")
        return False
    
    return True

def test_main_scanner():
    """Test main scanner class"""
    print("\nTesting main scanner...")
    
    try:
        from autoredteam.main import AutoRedTeam
        
        # Test scanner initialization
        scanner = AutoRedTeam()
        print("✓ AutoRedTeam initialized")
        
        # Test scan result creation
        from autoredteam.model import ScanResult, ScanConfig
        scan_result = ScanResult(
            target_url="http://test.com",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            total_urls_discovered=5,
            total_urls_tested=5,
            vulnerabilities=[],
            scan_config=ScanConfig()
        )
        
        summary = scan_result.get_summary()
        print("✓ Scan result creation works")
        
    except Exception as e:
        print(f"✗ Error testing main scanner: {e}")
        return False
    
    return True

def main():
    """Run all tests"""
    print("AutoRedTeam - Module Test Suite")
    print("=" * 50)
    
    tests = [
        ("Module Imports", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Crawler", test_crawler),
        ("Scanner", test_scanner),
        ("Report", test_report),
        ("Main Scanner", test_main_scanner)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        if test_func():
            passed += 1
            print(f"✓ {test_name} PASSED")
        else:
            print(f"✗ {test_name} FAILED")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! AutoRedTeam is ready to use.")
        print("\nTo run the scanner:")
        print("  python autoredteam/main.py http://testphp.vulnweb.com")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 
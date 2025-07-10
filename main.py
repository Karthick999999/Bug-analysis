#!/usr/bin/env python3
"""
AutoRedTeam - Automated Vulnerability Scanner
A comprehensive web application security testing tool
"""

import sys
import time
import argparse
from datetime import datetime
from typing import List, Dict

# Import our modules
from autoredteam.crawler import crawl
from autoredteam.scanner import test_sqli, test_xss
from autoredteam.report import generate_report
from autoredteam.model import (
    Vulnerability, VulnerabilityType, RiskLevel, 
    ScanConfig, ScanResult, ConfigManager, PayloadManager
)

class AutoRedTeam:
    """Main AutoRedTeam scanner class"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_manager = ConfigManager(config_file)
        self.payload_manager = PayloadManager()
        self.scan_config = self.config_manager.get_scan_config()
        
    def run_scan(self, target_url: str, max_urls: int | None = None) -> ScanResult:
        """Run a complete vulnerability scan"""
        print("=" * 60)
        print("AutoRedTeam - Vulnerability Scanner")
        print("=" * 60)
        print(f"Target: {target_url}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        start_time = datetime.now()
        
        # Step 1: Crawl the website
        print("\n[1/4] Crawling website...")
        max_urls_to_use = max_urls if max_urls is not None else self.scan_config.max_urls
        discovered_urls = crawl(target_url, max_urls=max_urls_to_use)
        
        if not discovered_urls:
            print("No URLs discovered. Check if the target is accessible.")
            # Return empty scan result instead of None
            return ScanResult(
                target_url=target_url,
                start_time=start_time.isoformat(),
                end_time=datetime.now().isoformat(),
                total_urls_discovered=0,
                total_urls_tested=0,
                vulnerabilities=[],
                scan_config=self.scan_config
            )
        
        print(f"Discovered {len(discovered_urls)} URLs")
        
        # Step 2: Test for vulnerabilities
        print("\n[2/4] Testing for vulnerabilities...")
        vulnerabilities = []
        
        for i, url in enumerate(discovered_urls, 1):
            print(f"Testing URL {i}/{len(discovered_urls)}: {url}")
            
            # Test for SQL Injection
            if self.test_sqli_vulnerability(url):
                vuln = Vulnerability(
                    url=url,
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    risk_level=RiskLevel.HIGH,
                    description="SQL injection vulnerability detected",
                    timestamp=datetime.now().isoformat()
                )
                vulnerabilities.append(vuln)
            
            # Test for XSS
            if self.test_xss_vulnerability(url):
                vuln = Vulnerability(
                    url=url,
                    vulnerability_type=VulnerabilityType.XSS,
                    risk_level=RiskLevel.MEDIUM,
                    description="Cross-site scripting vulnerability detected",
                    timestamp=datetime.now().isoformat()
                )
                vulnerabilities.append(vuln)
            
            # Add delay between requests
            time.sleep(self.scan_config.delay)
        
        # Step 3: Generate report
        print("\n[3/4] Generating report...")
        end_time = datetime.now()
        
        scan_result = ScanResult(
            target_url=target_url,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_urls_discovered=len(discovered_urls),
            total_urls_tested=len(discovered_urls),
            vulnerabilities=vulnerabilities,
            scan_config=self.scan_config
        )
        
        # Step 4: Save results
        print("\n[4/4] Saving results...")
        self.save_results(scan_result)
        
        # Generate PDF report
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        # Convert Vulnerability objects to the format expected by the report generator
        report_data = []
        for v in vulnerabilities:
            vuln_dict = v.to_dict()
            report_data.append({
                'url': vuln_dict['url'],
                'vuln': vuln_dict['vulnerability_type']  # Map vulnerability_type to vuln
            })
        generate_report(report_data, report_filename)
        
        # Print summary
        self.print_summary(scan_result)
        
        return scan_result
    
    def test_sqli_vulnerability(self, url: str) -> bool:
        """Test for SQL injection vulnerability"""
        try:
            return test_sqli(url)
        except Exception as e:
            print(f"Error testing SQL injection on {url}: {e}")
            return False
    
    def test_xss_vulnerability(self, url: str) -> bool:
        """Test for XSS vulnerability"""
        try:
            return test_xss(url)
        except Exception as e:
            print(f"Error testing XSS on {url}: {e}")
            return False
    
    def save_results(self, scan_result: ScanResult):
        """Save scan results to JSON file"""
        import json
        
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(scan_result.to_dict(), f, indent=2)
            print(f"Results saved to: {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def print_summary(self, scan_result: ScanResult):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        
        summary = scan_result.get_summary()
        print(f"Target URL: {scan_result.target_url}")
        print(f"Scan Duration: {scan_result.start_time} to {scan_result.end_time}")
        print(f"URLs Discovered: {scan_result.total_urls_discovered}")
        print(f"URLs Tested: {scan_result.total_urls_tested}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        
        if summary['vulnerability_types']:
            print("\nVulnerability Breakdown:")
            for vuln_type, count in summary['vulnerability_types'].items():
                print(f"  - {vuln_type}: {count}")
        else:
            print("\nNo vulnerabilities detected!")
        
        print("\nReports generated:")
        print("  - JSON results file")
        print("  - PDF vulnerability report")
        print("=" * 60)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AutoRedTeam - Automated Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py http://testphp.vulnweb.com
  python main.py http://example.com --max-urls 100
  python main.py http://target.com --config custom_config.json
        """
    )
    
    parser.add_argument("target_url", help="Target URL to scan")
    parser.add_argument("--max-urls", type=int, default=50, 
                       help="Maximum number of URLs to crawl (default: 50)")
    parser.add_argument("--config", default="config.json",
                       help="Configuration file (default: config.json)")
    parser.add_argument("--delay", type=float, default=1.0,
                       help="Delay between requests in seconds (default: 1.0)")
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = AutoRedTeam(args.config)
        
        # Update scan configuration
        if args.delay != 1.0:
            scanner.scan_config.delay = args.delay
        
        # Run the scan
        result = scanner.run_scan(args.target_url, args.max_urls)
        
        if result:
            print("\nScan completed successfully!")
            sys.exit(0)
        else:
            print("\nScan failed or no results obtained.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # For testing without command line arguments
    if len(sys.argv) == 1:
        print("AutoRedTeam - Vulnerability Scanner")
        print("Usage: python main.py <target_url>")
        print("Example: python main.py http://testphp.vulnweb.com")
        print("\nRunning test scan on demo target...")
        
        scanner = AutoRedTeam()
        result = scanner.run_scan("http://testphp.vulnweb.com", max_urls=10)
        
        if result:
            print("\nTest scan completed successfully!")
        else:
            print("\nTest scan failed.")
    else:
        main()

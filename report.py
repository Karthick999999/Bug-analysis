# report.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import datetime
import os

class VulnerabilityReport:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkred
        )
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        self.normal_style = self.styles['Normal']
        self.code_style = ParagraphStyle(
            'CodeStyle',
            parent=self.styles['Code'],
            fontSize=10,
            fontName='Courier',
            leftIndent=20,
            rightIndent=20,
            backColor=colors.lightgrey
        )
    
    def create_executive_summary(self, results):
        """Create executive summary section"""
        story = []
        
        # Title
        story.append(Paragraph("Executive Summary", self.title_style))
        story.append(Spacer(1, 12))
        
        # Summary statistics
        total_vulns = len(results)
        sqli_count = len([r for r in results if r['vuln'] == 'SQL Injection'])
        xss_count = len([r for r in results if r['vuln'] == 'XSS'])
        
        summary_text = f"""
        This security assessment was conducted on the target application to identify potential vulnerabilities.
        The scan discovered {total_vulns} vulnerabilities across the tested endpoints.
        
        <b>Key Findings:</b>
        • SQL Injection vulnerabilities: {sqli_count}
        • Cross-Site Scripting (XSS) vulnerabilities: {xss_count}
        • Total endpoints tested: {len(set([r['url'] for r in results]))}
        
        <b>Risk Level:</b> {'High' if total_vulns > 0 else 'Low'}
        """
        
        story.append(Paragraph(summary_text, self.normal_style))
        story.append(Spacer(1, 20))
        
        return story
    
    def create_vulnerability_details(self, results):
        """Create detailed vulnerability findings"""
        story = []
        
        story.append(Paragraph("Detailed Findings", self.heading_style))
        story.append(Spacer(1, 12))
        
        if not results:
            story.append(Paragraph("No vulnerabilities were detected during this assessment.", self.normal_style))
            return story
        
        # Group vulnerabilities by type
        vuln_groups = {}
        for result in results:
            vuln_type = result['vuln']
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)
        
        for vuln_type, vulns in vuln_groups.items():
            story.append(Paragraph(f"{vuln_type} Vulnerabilities", self.heading_style))
            story.append(Spacer(1, 12))
            
            # Create table for vulnerabilities
            table_data = [['URL', 'Vulnerability Type', 'Risk Level']]
            
            for vuln in vulns:
                risk_level = "High" if vuln_type == "SQL Injection" else "Medium"
                table_data.append([vuln['url'], vuln['vuln'], risk_level])
            
            table = Table(table_data, colWidths=[3*inch, 2*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Add vulnerability description
            if vuln_type == "SQL Injection":
                description = """
                <b>SQL Injection Vulnerability:</b>
                SQL Injection occurs when user input is not properly sanitized before being used in database queries.
                This can allow attackers to execute arbitrary SQL commands, potentially leading to:
                • Unauthorized data access
                • Data manipulation or deletion
                • Database structure disclosure
                • Complete system compromise
                
                <b>Recommended Mitigation:</b>
                • Use parameterized queries or prepared statements
                • Implement input validation and sanitization
                • Apply the principle of least privilege
                • Use Web Application Firewalls (WAF)
                """
            else:  # XSS
                description = """
                <b>Cross-Site Scripting (XSS) Vulnerability:</b>
                XSS occurs when malicious scripts are injected into web pages viewed by other users.
                This can lead to:
                • Session hijacking
                • Cookie theft
                • Defacement of web pages
                • Malicious redirects
                • Keylogger installation
                
                <b>Recommended Mitigation:</b>
                • Implement proper output encoding
                • Use Content Security Policy (CSP)
                • Validate and sanitize all user inputs
                • Use HttpOnly cookies for sensitive data
                """
            
            story.append(Paragraph(description, self.normal_style))
            story.append(Spacer(1, 20))
        
        return story
    
    def create_recommendations(self):
        """Create security recommendations section"""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.heading_style))
        story.append(Spacer(1, 12))
        
        recommendations = """
        <b>Immediate Actions:</b>
        1. Fix all identified SQL injection vulnerabilities by implementing parameterized queries
        2. Address XSS vulnerabilities through proper input validation and output encoding
        3. Review and update security headers
        4. Implement rate limiting to prevent automated attacks
        
        <b>Long-term Security Measures:</b>
        1. Conduct regular security assessments and penetration testing
        2. Implement a comprehensive security training program for developers
        3. Establish a security incident response plan
        4. Use automated security testing tools in the CI/CD pipeline
        5. Regularly update and patch all software components
        6. Implement logging and monitoring for security events
        
        <b>Best Practices:</b>
        • Follow the OWASP Top 10 guidelines
        • Implement defense in depth
        • Use HTTPS for all communications
        • Regular backup and recovery testing
        • Implement proper access controls
        """
        
        story.append(Paragraph(recommendations, self.normal_style))
        story.append(Spacer(1, 20))
        
        return story
    
    def create_technical_details(self):
        """Create technical details section"""
        story = []
        
        story.append(Paragraph("Technical Details", self.heading_style))
        story.append(Spacer(1, 12))
        
        details = """
        <b>Scan Methodology:</b>
        This assessment utilized automated vulnerability scanning tools to identify common web application vulnerabilities.
        The scan included:
        • URL parameter testing for SQL injection and XSS
        • Form field testing for injection vulnerabilities
        • Error message analysis for vulnerability confirmation
        
        <b>Tools Used:</b>
        • Custom Python-based vulnerability scanner
        • BeautifulSoup for HTML parsing
        • Requests library for HTTP communication
        
        <b>Limitations:</b>
        • Automated scans may not detect all vulnerabilities
        • Some vulnerabilities may require manual testing
        • False positives are possible and should be verified
        • The scan focused on common web vulnerabilities only
        """
        
        story.append(Paragraph(details, self.normal_style))
        story.append(Spacer(1, 20))
        
        return story

def generate_report(results, filename="vulnerability_report.pdf"):
    """Generate a comprehensive vulnerability report"""
    print(f"Generating report: {filename}")
    
    # Create the PDF document
    doc = SimpleDocTemplate(filename, pagesize=A4)
    story = []
    
    # Create report sections
    report = VulnerabilityReport()
    
    # Add report header
    story.append(Paragraph("Vulnerability Assessment Report", report.title_style))
    story.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", report.normal_style))
    story.append(Spacer(1, 30))
    
    # Add executive summary
    story.extend(report.create_executive_summary(results))
    story.append(PageBreak())
    
    # Add vulnerability details
    story.extend(report.create_vulnerability_details(results))
    story.append(PageBreak())
    
    # Add recommendations
    story.extend(report.create_recommendations())
    story.append(PageBreak())
    
    # Add technical details
    story.extend(report.create_technical_details())
    
    # Build the PDF
    doc.build(story)
    print(f"Report generated successfully: {filename}")
    
    return filename

if __name__ == "__main__":
    # Test the report generator
    test_results = [
        {'url': 'http://testphp.vulnweb.com/artists.php?artist=1', 'vuln': 'SQL Injection'},
        {'url': 'http://testphp.vulnweb.com/search.php?q=test', 'vuln': 'XSS'},
        {'url': 'http://testphp.vulnweb.com/login.php', 'vuln': 'SQL Injection'}
    ]
    
    generate_report(test_results, "test_report.pdf")

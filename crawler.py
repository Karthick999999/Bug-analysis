import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from collections import deque
import time

class WebCrawler:
    def __init__(self, max_urls=50, delay=1):
        self.max_urls = max_urls
        self.delay = delay
        self.visited = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def is_valid_url(self, url, base_domain):
        """Check if URL is valid and belongs to the same domain"""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_domain)
            return parsed.netloc == base_parsed.netloc
        except:
            return False
    
    def extract_urls(self, html_content, base_url):
        """Extract all URLs from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        urls = set()
        
        # Find all links
        for link in soup.find_all('a', href=True):
            try:
                href = link.get('href')
                if href and isinstance(href, str):
                    full_url = urljoin(base_url, href)
                    if self.is_valid_url(full_url, base_url):
                        urls.add(full_url)
            except (KeyError, TypeError):
                continue
        # Find forms
        for form in soup.find_all('form'):
            try:
                if hasattr(form, 'get'):
                    action = form.get('action', '')
                    if action and isinstance(action, str):
                        full_url = urljoin(base_url, action)
                        if self.is_valid_url(full_url, base_url):
                            urls.add(full_url)
            except (KeyError, TypeError):
                continue
        
        return urls
    
    def crawl(self, start_url):
        """Crawl the website starting from the given URL"""
        print(f"Starting crawl from: {start_url}")
        
        queue = deque([start_url])
        discovered_urls = set()
        
        while queue and len(discovered_urls) < self.max_urls:
            current_url = queue.popleft()
            
            if current_url in self.visited:
                continue
                
            self.visited.add(current_url)
            
            try:
                print(f"Crawling: {current_url}")
                response = self.session.get(current_url, timeout=10)
                
                if response.status_code == 200:
                    discovered_urls.add(current_url)
                    
                    # Extract new URLs
                    new_urls = self.extract_urls(response.text, current_url)
                    for url in new_urls:
                        if url not in self.visited and url not in discovered_urls:
                            queue.append(url)
                
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"Error crawling {current_url}: {e}")
                continue
        
        print(f"Crawl complete. Found {len(discovered_urls)} URLs")
        return list(discovered_urls)

def crawl(start_url, max_urls=50):
    """Main function to crawl a website"""
    crawler = WebCrawler(max_urls=max_urls)
    return crawler.crawl(start_url)

if __name__ == "__main__":
    # Test the crawler
    test_urls = crawl("http://testphp.vulnweb.com", max_urls=10)
    print("Discovered URLs:")
    for url in test_urls:
        print(f"  - {url}") 
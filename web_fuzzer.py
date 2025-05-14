#!/usr/bin/env python3

import argparse
import concurrent.futures
import requests
import sys
import time
from urllib.parse import urljoin, urlparse
from typing import List, Set
import urllib3
import hashlib
import re
from difflib import SequenceMatcher

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebFuzzer:
    def __init__(self, target_url: str, wordlist: str = None, threads: int = 10, timeout: int = 10):
        # Validate and clean the target URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Referer': target_url
        }
        self.found_urls: Set[str] = set()
        self.errors: Set[str] = set()
        
        # Get baseline responses for comparison
        try:
            print(f"\n[*] Testing connection to {self.target_url}")
            print("[*] SSL certificate verification disabled for testing purposes")
            
            # Get main page response
            self.baseline_response = self.session.get(self.target_url, timeout=self.timeout)
            self.baseline_hash = hashlib.md5(self.baseline_response.content).hexdigest()
            self.baseline_length = len(self.baseline_response.content)
            self.baseline_text = self.baseline_response.text
            
            # Get a definitely non-existent page response
            random_page = self.target_url + "page_that_definitely_does_not_exist_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            self.error_response = self.session.get(random_page, timeout=self.timeout)
            self.error_hash = hashlib.md5(self.error_response.content).hexdigest()
            self.error_length = len(self.error_response.content)
            self.error_text = self.error_response.text
            
            print(f"[+] Successfully connected to target (Status: {self.baseline_response.status_code})")
            print(f"[*] Server: {self.baseline_response.headers.get('Server', 'Unknown')}")
            print(f"[*] Content-Type: {self.baseline_response.headers.get('Content-Type', 'Unknown')}")
            print(f"[*] Baseline response size: {self.baseline_length} bytes")
            print(f"[*] Error page response size: {self.error_length} bytes")
            
            # Calculate similarity between baseline and error page
            similarity = SequenceMatcher(None, self.baseline_text, self.error_text).ratio()
            print(f"[*] Page similarity ratio: {similarity:.2%}")
            
            if similarity > 0.9:
                print("\n[!] Warning: Site appears to use catch-all routing (all pages return very similar content)")
                print("[!] Most results may be false positives")
                
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Error connecting to target: {str(e)}")
            print("[!] Make sure the URL is correct and the site is accessible")
            sys.exit(1)

        # Default wordlist if none provided
        self.wordlist = self._load_default_wordlist() if wordlist is None else self._load_wordlist(wordlist)

    def _load_default_wordlist(self) -> List[str]:
        """Load a default list of common web files and directories."""
        common_paths = [
            # Archive specific paths
            'archive/', 'archives/', 'files/', 'download/', 'downloads/',
            'media/', 'documents/', 'docs/', 'public/', 'shared/',
            'content/', 'data/', 'storage/', 'upload/', 'uploads/',
            'file/', 'view/', 'browse/', 'search/', 'find/',
            'index/', 'list/', 'directory/', 'dir/', 'folder/',
            
            # Common web paths
            'index.html', 'index.php', 'index.asp', 'default.html',
            'home.html', 'home.php', 'main.html', 'main.php',
            'about.html', 'about.php', 'contact.html', 'contact.php',
            'privacy.html', 'privacy.php', 'terms.html', 'terms.php',
            
            # API and endpoints
            'api/', 'api/v1/', 'api/v2/', 'api/docs/', 'swagger/',
            'graphql/', 'graphiql/', 'query/', 'endpoint/',
            'service/', 'services/', 'rest/', 'rpc/',
            
            # User related
            'login/', 'login.php', 'login.html', 'signin/',
            'register/', 'signup/', 'account/', 'profile/',
            'user/', 'users/', 'members/', 'member/',
            'auth/', 'authenticate/', 'logout/', 'signout/',
            
            # Admin and management
            'admin/', 'administrator/', 'moderator/', 'mod/',
            'cp/', 'cpanel/', 'dashboard/', 'manage/',
            'management/', 'control/', 'panel/', 'webadmin/',
            
            # Common file types
            '*.pdf', '*.doc', '*.docx', '*.txt', '*.zip',
            '*.rar', '*.7z', '*.tar.gz', '*.csv', '*.json',
            '*.xml', '*.rss', '*.atom', '*.mp3', '*.mp4',
            
            # Configuration and info
            'robots.txt', 'sitemap.xml', '.htaccess', 'favicon.ico',
            'config.php', 'configuration.php', 'settings.php',
            'info.php', 'phpinfo.php', 'test.php', 'status/',
            
            # Common directories
            'css/', 'js/', 'images/', 'img/', 'assets/',
            'static/', 'media/', 'temp/', 'tmp/', 'cache/',
            'backup/', 'old/', 'new/', 'dev/', 'test/',
            
            # Archive specific files
            'archive.zip', 'backup.zip', 'files.zip', 'download.zip',
            'archive.tar.gz', 'backup.tar.gz', 'files.tar.gz',
            'database.sql', 'db.sql', 'dump.sql', 'backup.sql',
            
            # Common endpoints
            'search.php', 'search.html', 'results.php', 'results.html',
            'browse.php', 'browse.html', 'view.php', 'view.html',
            'download.php', 'upload.php', 'process.php', 'handle.php',
            
            # Specific to content sharing
            'share/', 'sharing/', 'embed/', 'preview/',
            'thumbnail/', 'thumbnails/', 'viewer/', 'read/',
            'stream/', 'play/', 'watch/', 'listen/',
            
            # Error pages
            'error/', '404.html', '403.html', '500.html',
            'error.php', 'error.html', 'errorpage/', 'errors/',
            
            # Specific paths for this type of site
            'words/', 'dictionary/', 'archive/', 'text/',
            'documents/', 'entries/', 'categories/', 'tags/',
            'search/', 'browse/', 'recent/', 'popular/',
            'trending/', 'featured/', 'highlights/', 'collections/'
        ]
        return common_paths

    def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load custom wordlist from file."""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            sys.exit(1)

    def _check_url(self, path: str) -> None:
        """Check if a specific URL path exists."""
        url = urljoin(self.target_url, path)
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Get response characteristics
            content_hash = hashlib.md5(response.content).hexdigest()
            size = len(response.content)
            content_type = response.headers.get('Content-Type', 'Unknown')
            final_url = response.url
            
            # Calculate content similarity with baseline and error pages
            response_text = response.text
            baseline_similarity = SequenceMatcher(None, self.baseline_text, response_text).ratio()
            error_similarity = SequenceMatcher(None, self.error_text, response_text).ratio()
            
            # Look for specific patterns that might indicate a real page
            content_str = response_text.lower()
            
            # Define patterns that would indicate a real page
            real_page_patterns = [
                (r'login.*?password', 'login form'),
                (r'admin.*?dashboard', 'admin panel'),
                (r'upload.*?file', 'file upload'),
                (r'search.*?results?', 'search functionality'),
                (r'error.*?not\s+found', 'custom error page'),
                (r'register.*?account', 'registration form'),
                (r'api.*?documentation', 'API docs'),
                (r'browse.*?files?', 'file browser')
            ]
            
            # Check for pattern matches
            found_patterns = []
            for pattern, desc in real_page_patterns:
                if re.search(pattern, content_str, re.IGNORECASE | re.DOTALL):
                    found_patterns.append(desc)
            
            # Check if this is likely a real page
            is_unique = (
                (baseline_similarity < 0.9 and error_similarity < 0.9) or  # Content is significantly different
                (abs(size - self.baseline_length) > 100 and abs(size - self.error_length) > 100) or  # Size is significantly different
                found_patterns or  # Contains specific functionality patterns
                'application/json' in content_type.lower() or  # API endpoints
                response.status_code in [401, 403] or  # Access denied pages
                final_url != url  # URL was redirected
            )
            
            if response.status_code in [200, 201, 301, 302, 307, 308, 401, 403] and is_unique:
                status_color = "\033[92m" if response.status_code in [200, 201] else "\033[93m"
                status_text = {
                    200: "OK",
                    201: "Created",
                    301: "Moved Permanently",
                    302: "Found",
                    307: "Temporary Redirect",
                    308: "Permanent Redirect",
                    401: "Unauthorized",
                    403: "Forbidden"
                }.get(response.status_code, str(response.status_code))
                
                redirect_info = f" -> {final_url}" if final_url != url else ""
                similarity_info = f"[Similarity: {baseline_similarity:.0%}]"
                pattern_info = f" [{', '.join(found_patterns)}]" if found_patterns else ""
                
                result = f"{url} [Status: {response.status_code} - {status_text}] [Size: {size}] [Type: {content_type}]{redirect_info} {similarity_info}{pattern_info}"
                
                if baseline_similarity > 0.9:
                    result += " [LIKELY FALSE POSITIVE]"
                
                self.found_urls.add(result)
                print(f"{status_color}[+] Found: {result}\033[0m")
                
        except requests.exceptions.ConnectionError:
            self.errors.add(f"Connection error for {url}")
        except requests.exceptions.Timeout:
            self.errors.add(f"Timeout for {url}")
        except requests.exceptions.RequestException as e:
            self.errors.add(f"Error for {url}: {str(e)}")

    def start_scan(self):
        """Start the fuzzing process using a thread pool."""
        parsed_url = urlparse(self.target_url)
        print(f"\n[*] Starting scan on {self.target_url}")
        print(f"[*] Target IP: {parsed_url.netloc}")
        print(f"[*] Using {self.threads} threads")
        print(f"[*] Timeout: {self.timeout} seconds")
        print(f"[*] Loaded {len(self.wordlist)} paths to test")
        print("[*] Press Ctrl+C to stop the scan\n")

        start_time = time.time()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                list(executor.map(self._check_url, self.wordlist))
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        
        end_time = time.time()
        duration = end_time - start_time

        self._print_results(duration)

    def _print_results(self, duration: float):
        """Print scan results."""
        print("\n" + "="*50)
        print("Scan Results:")
        print("="*50)
        
        # Group results by likelihood
        real_pages = []
        possible_pages = []
        false_positives = []
        
        for url in sorted(self.found_urls):
            if "[LIKELY FALSE POSITIVE]" in url:
                false_positives.append(url)
            elif any(pattern in url for pattern in ["login form", "admin panel", "file upload", "search functionality", "custom error page", "registration form", "API docs", "file browser"]):
                real_pages.append(url)
            else:
                possible_pages.append(url)
        
        print(f"\nFound {len(self.found_urls)} paths in {duration:.2f} seconds:\n")
        
        if real_pages:
            print("\n=== High Probability Real Pages ===")
            for url in real_pages:
                print(url)
                
        if possible_pages:
            print("\n=== Possibly Valid Pages ===")
            for url in possible_pages:
                print(url)
                
        if false_positives:
            print("\n=== Likely False Positives ===")
            for url in false_positives:
                print(url)
            
        if self.errors:
            print("\nErrors encountered:")
            for error in sorted(self.errors)[:5]:
                print(f"[!] {error}")
            if len(self.errors) > 5:
                print(f"... and {len(self.errors) - 5} more errors")
        
        print(f"\nScan completed in {duration:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(description='Web Fuzzer - Directory and File Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-w', '--wordlist', help='Path to custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()

    try:
        fuzzer = WebFuzzer(
            args.url,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout
        )
        fuzzer.start_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
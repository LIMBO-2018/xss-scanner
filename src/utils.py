import os
import sys
import datetime
import urllib.parse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class Logger:
    def __init__(self, log_to_file=False, log_file=None):
        self.log_to_file = log_to_file
        self.log_file = log_file or f"xss_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        if self.log_to_file:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
    
    def _log(self, level, message, color):
        """Internal logging method."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # Print to console with color
        print(f"{color}{formatted_message}{Style.RESET_ALL}")
        
        # Write to file if enabled
        if self.log_to_file:
            with open(self.log_file, "a") as f:
                f.write(f"{formatted_message}\n")
    
    def info(self, message):
        """Log an info message."""
        self._log("INFO", message, Fore.BLUE)
    
    def success(self, message):
        """Log a success message."""
        self._log("SUCCESS", message, Fore.GREEN)
    
    def warning(self, message):
        """Log a warning message."""
        self._log("WARNING", message, Fore.YELLOW)
    
    def error(self, message):
        """Log an error message."""
        self._log("ERROR", message, Fore.RED)
    
    def critical(self, message):
        """Log a critical message."""
        self._log("CRITICAL", message, Fore.RED + Style.BRIGHT)


class URLUtils:
    @staticmethod
    def is_valid_url(url):
        """Check if a URL is valid."""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def normalize_url(url):
        """Normalize a URL by ensuring it has a scheme."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    @staticmethod
    def get_domain(url):
        """Extract the domain from a URL."""
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.netloc
    
    @staticmethod
    def get_base_url(url):
        """Get the base URL (scheme + domain)."""
        parsed_url = urllib.parse.urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}"


class FileUtils:
    @staticmethod
    def save_results(results, filename):
        """Save scan results to a file."""
        with open(filename, 'w') as f:
            f.write("XSS Scanner Results\n")
            f.write("=================\n\n")
            
            if not results:
                f.write("No vulnerabilities found.\n")
                return
                
            f.write(f"Found {len(results)} potential XSS vulnerabilities:\n\n")
            
            for i, vuln in enumerate(results, 1):
                f.write(f"Vulnerability #{i}:\n")
                f.write(f"  Type: {vuln['type']}\n")
                
                if vuln['type'] == 'url':
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  Parameter: {vuln['parameter']}\n")
                elif vuln['type'] == 'form':
                    f.write(f"  Form Action: {vuln['action']}\n")
                    f.write(f"  Form Method: {vuln['method']}\n")
                    f.write(f"  Form Input: {vuln['input']}\n")
                elif vuln['type'] == 'js':
                    f.write(f"  URL: {vuln['url']}\n")
                    f.write(f"  JavaScript Parameter: {vuln['parameter']}\n")
                    
                f.write(f"  Payload: {vuln['payload']}\n\n")
    
    @staticmethod
    def read_urls_from_file(filename):
        """Read URLs from a file, one per line."""
        urls = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
        except Exception as e:
            print(f"Error reading file: {str(e)}")
        return urls


class NetworkUtils:
    @staticmethod
    def check_connectivity(url, timeout=5):
        """Check if a URL is reachable."""
        try:
            import requests
            response = requests.head(url, timeout=timeout)
            return True
        except:
            return False



import urllib.parse
import os
import sys
import time
import threading
from colorama import init, Fore, Style, Back

from .utils import Logger, URLUtils, FileUtils

# Initialize colorama
init(autoreset=True)

class Banner:
    @staticmethod
    def show():
        """Display the tool banner."""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{Fore.RED}██╗  ██╗███████╗███████╗{Fore.YELLOW}    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
{Fore.RED}╚██╗██╔╝██╔════╝██╔════╝{Fore.YELLOW}    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
{Fore.RED} ╚███╔╝ ███████╗███████╗{Fore.YELLOW}    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
{Fore.RED} ██╔██╗ ╚════██║╚════██║{Fore.YELLOW}    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
{Fore.RED}██╔╝ ██╗███████║███████║{Fore.YELLOW}    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
{Fore.RED}╚═╝  ╚═╝╚══════╝╚══════╝{Fore.YELLOW}    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                
{Fore.CYAN}[+] {Fore.WHITE}A professional Cross-Site Scripting (XSS) vulnerability scanner
{Fore.CYAN}[+] {Fore.WHITE}Version: 1.0.0
{Fore.CYAN}[+] {Fore.WHITE}Designed for security professionals and penetration testers
{Fore.CYAN}[+] {Fore.WHITE}Works on Termux without root access
        """
        print(banner)


class ProgressSpinner:
    def __init__(self, message="Processing"):
        self.message = message
        self.spinning = False
        self.spinner_chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
        self.spinner_index = 0
        self.thread = None
    
    def spin(self):
        """Spin the spinner."""
        while self.spinning:
            sys.stdout.write(f"\r{self.message} {self.spinner_chars[self.spinner_index]}")
            sys.stdout.flush()
            self.spinner_index = (self.spinner_index + 1) % len(self.spinner_chars)
            time.sleep(0.1)
    
    def start(self):
        """Start the spinner."""
        self.spinning = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the spinner."""
        self.spinning = False
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")
        sys.stdout.flush()


class UI:
    def __init__(self):
        self.logger = Logger()
    
    def show_menu(self):
        """Display the main menu."""
        Banner.show()
        
        print(f"\n{Fore.CYAN}[*] {Fore.WHITE}Select an option:")
        print(f"{Fore.CYAN}[1] {Fore.WHITE}Scan a single URL")
        print(f"{Fore.CYAN}[2] {Fore.WHITE}Scan multiple URLs from a file")
        print(f"{Fore.CYAN}[3] {Fore.WHITE}Advanced scan options")
        print(f"{Fore.CYAN}[4] {Fore.WHITE}About")
        print(f"{Fore.CYAN}[5] {Fore.WHITE}Exit")
        
        choice = input(f"\n{Fore.YELLOW}[>] {Fore.WHITE}Enter your choice (1-5): ")
        return choice
    
    def get_target_url(self):
        """Get target URL from user."""
        while True:
            url = input(f"\n{Fore.YELLOW}[>] {Fore.WHITE}Enter the target URL: ")
            
            if not url:
                self.logger.error("URL cannot be empty. Please try again.")
                continue
                
            # Normalize URL
            url = URLUtils.normalize_url(url)
            
            if not URLUtils.is_valid_url(url):
                self.logger.error("Invalid URL format. Please enter a valid URL.")
                continue
                
            return url
    
    def get_file_path(self, prompt="Enter file path"):
        """Get a file path from user."""
        while True:
            file_path = input(f"\n{Fore.YELLOW}[>] {Fore.WHITE}{prompt}: ")
            
            if not file_path:
                self.logger.error("File path cannot be empty. Please try again.")
                continue
                
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                continue
                
            return file_path
    
    def get_advanced_options(self):
        """Get advanced scan options from user."""
        print(f"\n{Fore.CYAN}[*] {Fore.WHITE}Advanced Scan Options:")
        
        # Number of threads
        while True:
            try:
                threads = int(input(f"{Fore.YELLOW}[>] {Fore.WHITE}Number of threads (1-20, default 5): ") or "5")
                if 1 <= threads <= 20:
                    break
                self.logger.error("Please enter a number between 1 and 20.")
            except ValueError:
                self.logger.error("Please enter a valid number.")
        
        # Request timeout
        while True:
            try:
                timeout = int(input(f"{Fore.YELLOW}[>] {Fore.WHITE}Request timeout in seconds (5-60, default 10): ") or "10")
                if 5 <= timeout <= 60:
                    break
                self.logger.error("Please enter a number between 5 and 60.")
            except ValueError:
                self.logger.error("Please enter a valid number.")
        
        # Delay between requests
        while True:
            try:
                delay = float(input(f"{Fore.YELLOW}[>] {Fore.WHITE}Delay between requests in seconds (0-5, default 0): ") or "0")
                if 0 <= delay <= 5:
                    break
                self.logger.error("Please enter a number between 0 and 5.")
            except ValueError:
                self.logger.error("Please enter a valid number.")
        
        # Use advanced payloads
        use_advanced = input(f"{Fore.YELLOW}[>] {Fore.WHITE}Use advanced payloads? (y/n, default n): ").lower() == 'y'
        
        # Custom User-Agent
        user_agent = input(f"{Fore.YELLOW}[>] {Fore.WHITE}Custom User-Agent (leave empty for default): ") or None
        
        # Enable crawling
        enable_crawl = input(f"{Fore.YELLOW}[>] {Fore.WHITE}Enable site crawling to find more pages? (y/n, default n): ").lower() == 'y'
        
        # Crawl depth
        crawl_depth = 1
        if enable_crawl:
            while True:
                try:
                    crawl_depth = int(input(f"{Fore.YELLOW}[>] {Fore.WHITE}Crawl depth (1-3, default 1): ") or "1")
                    if 1 <= crawl_depth <= 3:
                        break
                    self.logger.error("Please enter a number between 1 and 3.")
                except ValueError:
                    self.logger.error("Please enter a valid number.")
        
        return {
            'threads': threads,
            'timeout': timeout,
            'delay': delay,
            'use_advanced': use_advanced,
            'user_agent': user_agent,
            'enable_crawl': enable_crawl,
            'crawl_depth': crawl_depth
        }
    
    def display_results(self, results):
        """Display scan results."""
        if not results:
            print(f"\n{Fore.GREEN}[+] {Fore.WHITE}No XSS vulnerabilities found.")
            return
            
        print(f"\n{Fore.RED}[!] {Fore.WHITE}Found {len(results)} potential XSS vulnerabilities:")
        
        for i, vuln in enumerate(results, 1):
            print(f"\n{Fore.RED}[Vulnerability #{i}]")
            
            if vuln['type'] == 'url':
                print(f"{Fore.YELLOW}Type: {Fore.WHITE}URL Parameter")
                print(f"{Fore.YELLOW}URL: {Fore.WHITE}{vuln['url']}")
                print(f"{Fore.YELLOW}Parameter: {Fore.WHITE}{vuln['parameter']}")
            elif vuln['type'] == 'form':
                print(f"{Fore.YELLOW}Type: {Fore.WHITE}Form Input")
                print(f"{Fore.YELLOW}Form Action: {Fore.WHITE}{vuln['action']}")
                print(f"{Fore.YELLOW}Form Method: {Fore.WHITE}{vuln['method'].upper()}")
                print(f"{Fore.YELLOW}Form Input: {Fore.WHITE}{vuln['input']}")
            elif vuln['type'] == 'js':
                print(f"{Fore.YELLOW}Type: {Fore.WHITE}JavaScript Parameter")
                print(f"{Fore.YELLOW}URL: {Fore.WHITE}{vuln['url']}")
                print(f"{Fore.YELLOW}Parameter: {Fore.WHITE}{vuln['parameter']}")
                
            print(f"{Fore.YELLOW}Payload: {Fore.WHITE}{vuln['payload']}")
            
            # Show exploitation example
            print(f"{Fore.YELLOW}Exploitation Example: {Fore.WHITE}")
            if vuln['type'] == 'url':
                parsed_url = urllib.parse.urlparse(vuln['url'])
                params = dict(urllib.parse.parse_qsl(parsed_url.query))
                params[vuln['parameter']] = vuln['payload']
                new_query = urllib.parse.urlencode(params)
                exploit_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                print(f"  Visit: {exploit_url}")
            elif vuln['type'] == 'form':
                print(f"  Submit the form at {vuln['action']} with {vuln['input']}={vuln['payload']}")
            elif vuln['type'] == 'js':
                print(f"  Manipulate JavaScript parameter {vuln['parameter']} with value: {vuln['payload']}")
        
        # Ask to save results
        save = input(f"\n{Fore.YELLOW}[>] {Fore.WHITE}Save results to file? (y/n): ").lower() == 'y'
        if save:
            filename = input(f"{Fore.YELLOW}[>] {Fore.WHITE}Enter filename (default: xss_results.txt): ") or "xss_results.txt"
            FileUtils.save_results(results, filename)
            self.logger.success(f"Results saved to {filename}")
    
    def show_about(self):
        """Display information about the tool."""
        Banner.show()
        
        about_text = f"""
{Fore.CYAN}[*] {Fore.WHITE}About XSS Scanner

{Fore.YELLOW}Description:{Fore.WHITE}
  XSS Scanner is a professional-grade tool designed to detect Cross-Site Scripting 
  vulnerabilities in web applications. It features automated scanning capabilities
  and a user-friendly interface.

{Fore.YELLOW}Features:{Fore.WHITE}
  - Scan for XSS vulnerabilities in URL parameters and form inputs
  - Multi-threaded scanning for faster results
  - Advanced payload detection
  - Works on Termux without root access
  - User-friendly interface
  - Detailed reporting

{Fore.YELLOW}Usage:{Fore.WHITE}
  This tool is intended for security professionals, penetration testers, and system
  administrators to test their own systems or systems they have permission to test.
  Unauthorized scanning of websites is illegal and unethical.

{Fore.YELLOW}Disclaimer:{Fore.WHITE}
  This tool should only be used for legitimate security testing with proper authorization.
  The developers are not responsible for any misuse or damage caused by this tool.
        """
        
        print(about_text)
        input(f"\n{Fore.CYAN}[*] {Fore.WHITE}Press Enter to return to the main menu...")


class InputValidator:
    @staticmethod
    def validate_url(url):
        """Validate a URL."""
        if not url:
            return False, "URL cannot be empty"
            
        if not URLUtils.is_valid_url(url):
            return False, "Invalid URL format"
            
        return True, "Valid URL"
    
    @staticmethod
    def validate_file(file_path):
        """Validate a file path."""
        if not file_path:
            return False, "File path cannot be empty"
            
        if not os.path.exists(file_path):
            return False, "File not found"
            
        if not os.path.isfile(file_path):
            return False, "Path is not a file"
            
        return True, "Valid file"



#!/usr/bin/env python3
import os
import sys
import threading
import time
import signal
import urllib.parse
from colorama import init, Fore, Style

from .ui import Banner, UI, ProgressSpinner
from .scanner import XSSScanner
from .utils import Logger, URLUtils, FileUtils, NetworkUtils

# Initialize colorama
init(autoreset=True)

# Global variables
logger = Logger(log_to_file=True)
ui = UI()
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C."""
    global running
    print(f"\n{Fore.YELLOW}[!] {Fore.WHITE}Interrupted by user. Exiting...")
    running = False
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def scan_url(url, options=None):
    """Scan a single URL for XSS vulnerabilities."""
    options = options or {}
    
    # Normalize URL
    url = URLUtils.normalize_url(url)
    
    # Check connectivity
    if not NetworkUtils.check_connectivity(url):
        logger.error(f"Cannot connect to {url}. Please check the URL and try again.")
        return []
    
    # Create scanner
    scanner = XSSScanner(
        target_url=url,
        threads=options.get('threads', 5),
        timeout=options.get('timeout', 10),
        user_agent=options.get('user_agent'),
        delay=options.get('delay', 0)
    )
    
    # Start spinner in a separate thread
    spinner = ProgressSpinner(f"Scanning {URLUtils.get_domain(url)} for XSS vulnerabilities")
    spinner.start()
    
    try:
        # Run the scan
        results = scanner.scan(use_advanced=options.get('use_advanced', False))
        
        # Stop the spinner
        spinner.stop()
        
        # Display results
        ui.display_results(results)
        
        return results
    except Exception as e:
        spinner.stop()
        logger.error(f"Error during scan: {str(e)}")
        return []

def scan_from_file(file_path, options=None):
    """Scan multiple URLs from a file."""
    options = options or {}
    
    try:
        urls = FileUtils.read_urls_from_file(file_path)
    except Exception as e:
        logger.error(f"Error reading file: {str(e)}")
        return []
    
    if not urls:
        logger.error("No URLs found in the file.")
        return []
    
    logger.info(f"Loaded {len(urls)} URLs from {file_path}")
    
    all_results = []
    for i, url in enumerate(urls, 1):
        logger.info(f"Scanning URL {i}/{len(urls)}: {url}")
        results = scan_url(url, options)
        all_results.extend(results)
        
        # Small delay between scans
        if i < len(urls):
            time.sleep(2)
    
    # Summary
    total_vulns = len(all_results)
    logger.info(f"Scan completed. Found {total_vulns} potential vulnerabilities across {len(urls)} URLs.")
    
    return all_results

def main():
    """Main function."""
    global running
    
    while running:
        choice = ui.show_menu()
        
        if choice == '1':  # Scan a single URL
            url = ui.get_target_url()
            if url:
                scan_url(url)
        
        elif choice == '2':  # Scan multiple URLs from a file
            file_path = ui.get_file_path("Enter the path to a file containing URLs (one per line)")
            if file_path:
                scan_from_file(file_path)
        
        elif choice == '3':  # Advanced scan options
            options = ui.get_advanced_options()
            url = ui.get_target_url()
            if url:
                scan_url(url, options)
        
        elif choice == '4':  # About
            ui.show_about()
        
        elif choice == '5':  # Exit
            logger.info("Exiting...")
            running = False
            break
        
        else:
            logger.error("Invalid choice. Please try again.")
        
        # If not exiting, wait for user input before showing menu again
        if running and choice != '4':  # Don't prompt after showing about
            input(f"\n{Fore.CYAN}[*] {Fore.WHITE}Press Enter to continue...")

if __name__ == "__main__":
    main()


import requests
from bs4 import BeautifulSoup
import urllib.parse
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import html

from .payloads import XSSPayloads
from .utils import Logger, URLUtils

class XSSScanner:
    def __init__(self, target_url, threads=5, timeout=10, user_agent=None, cookies=None, delay=0):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.logger = Logger()
        self.vulnerable_points = []
        
        # Default headers
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        self.cookies = cookies or {}
        self.session = requests.Session()
        
    def extract_forms(self, url):
        """Extract all forms from a given URL."""
        try:
            response = self.session.get(url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            self.logger.error(f"Error extracting forms from {url}: {str(e)}")
            return []
    
    def extract_inputs(self, form):
        """Extract all input fields from a form."""
        inputs = []
        # Get all input tags
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', '')
            input_name = input_tag.get('name', '')
            
            # Skip submit, button, image, and hidden inputs
            if input_type.lower() in ('submit', 'button', 'image', 'hidden'):
                continue
                
            if input_name:
                inputs.append(input_name)
                
        # Get all textarea tags
        for textarea in form.find_all('textarea'):
            textarea_name = textarea.get('name', '')
            if textarea_name:
                inputs.append(textarea_name)
                
        # Get all select tags
        for select in form.find_all('select'):
            select_name = select.get('name', '')
            if select_name:
                inputs.append(select_name)
                
        return inputs
    
    def get_form_details(self, form):
        """Extract details from a form including action, method, and inputs."""
        details = {}
        # Get the form action (target url)
        action = form.get('action', '')
        
        # If action is empty or just #, use the current URL
        if not action or action == '#':
            action = self.target_url
        # If action is relative, make it absolute
        elif not action.startswith('http'):
            action = urllib.parse.urljoin(self.target_url, action)
            
        # Get the form method (POST, GET, etc.)
        method = form.get('method', 'get').lower()
        
        # Get all form inputs
        inputs = self.extract_inputs(form)
        
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        
        return details
    
    def extract_url_params(self, url):
        """Extract parameters from URL."""
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        return {k: v[0] for k, v in params.items()}
    
    def extract_all_inputs(self, url):
        """Extract all possible input points from a page."""
        input_points = []
        
        try:
            # Get URL parameters
            url_params = self.extract_url_params(url)
            for param in url_params:
                input_points.append(('url', url, param))
            
            # Get forms and their inputs
            forms = self.extract_forms(url)
            for form in forms:
                form_details = self.get_form_details(form)
                for input_name in form_details['inputs']:
                    input_points.append(('form', form_details, input_name))
            
            # Get links with parameters
            response = self.session.get(url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '?' in href:
                    # Make URL absolute if it's relative
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(url, href)
                    
                    # Extract parameters
                    parsed_url = urllib.parse.urlparse(href)
                    params = urllib.parse.parse_qs(parsed_url.query)
                    
                    for param in params:
                        input_points.append(('url', href, param))
            
            # Look for custom parameters in JavaScript
            js_params = self.extract_js_params(response.text)
            for param in js_params:
                input_points.append(('js', url, param))
                
            return input_points
        
        except Exception as e:
            self.logger.error(f"Error extracting inputs from {url}: {str(e)}")
            return input_points
    
    def extract_js_params(self, html_content):
        """Extract potential parameter names from JavaScript code."""
        # Look for common patterns in JavaScript that might indicate parameters
        param_patterns = [
            r'(?:get|post|ajax|fetch)\s*\(\s*[\'"]([^\'"]+)[\'"]',  # API endpoints
            r'(?:var|let|const)\s+(\w+)\s*=\s*(?:getParameter|getUrlParameter|urlParam)',  # URL parameter getters
            r'params\[[\'"](\w+)[\'"]\]',  # params object access
            r'data\[[\'"](\w+)[\'"]\]',    # data object access
            r'\.val\(\)\s*(?:\.trim\(\))?\s*(?:\.toLowerCase\(\))?',  # jQuery value getters
        ]
        
        params = set()
        for pattern in param_patterns:
            matches = re.findall(pattern, html_content)
            params.update(matches)
        
        return list(params)
    
    def test_xss_in_url(self, url, param, payload):
        """Test for XSS in URL parameters."""
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # Skip if parameter doesn't exist
        if param not in params:
            return False
            
        # Create a copy of params and modify the target parameter
        new_params = {k: v[0] for k, v in params.items()}
        new_params[param] = payload
        
        # Rebuild the query string
        new_query = urllib.parse.urlencode(new_params)
        
        # Rebuild the URL
        new_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        try:
            # Add a small delay to avoid overwhelming the server
            if self.delay > 0:
                time.sleep(self.delay)
                
            response = self.session.get(new_url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            
            # Check if the payload is reflected in the response
            return self.check_xss_reflection(response.text, payload)
            
        except Exception as e:
            self.logger.error(f"Error testing URL parameter {param}: {str(e)}")
            
        return False
    
    def test_xss_in_form(self, form_details, input_name, payload):
        """Test for XSS in form inputs."""
        action = form_details['action']
        method = form_details['method']
        inputs = form_details['inputs']
        
        # Create data to submit
        data = {}
        for input_field in inputs:
            # Use the payload only for the target input
            if input_field == input_name:
                data[input_field] = payload
            else:
                # Use a generic value for other inputs
                data[input_field] = "test123"
            
        try:
            # Add a small delay to avoid overwhelming the server
            if self.delay > 0:
                time.sleep(self.delay)
                
            if method == 'post':
                response = self.session.post(
                    action, 
                    data=data, 
                    headers=self.headers, 
                    cookies=self.cookies,
                    timeout=self.timeout
                )
            else:  # GET
                response = self.session.get(
                    action, 
                    params=data, 
                    headers=self.headers, 
                    cookies=self.cookies,
                    timeout=self.timeout
                )
                
            # Check if the payload is reflected in the response
            return self.check_xss_reflection(response.text, payload)
            
        except Exception as e:
            self.logger.error(f"Error testing form input {input_name} at {action}: {str(e)}")
            
        return False
    
    def test_xss_in_js(self, url, param, payload):
        """Test for XSS in JavaScript parameters."""
        # This is a simplified approach - in a real-world scenario, 
        # you might need to analyze the JavaScript more deeply
        try:
            # Try adding the parameter to the URL
            parsed_url = urllib.parse.urlparse(url)
            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
            query_params[param] = payload
            
            new_query = urllib.parse.urlencode(query_params)
            new_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Add a small delay to avoid overwhelming the server
            if self.delay > 0:
                time.sleep(self.delay)
                
            response = self.session.get(new_url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            
            # Check if the payload is reflected in the response
            return self.check_xss_reflection(response.text, payload)
            
        except Exception as e:
            self.logger.error(f"Error testing JavaScript parameter {param}: {str(e)}")
            
        return False
    
    def check_xss_reflection(self, response_text, payload):
        """
        Check if a payload is reflected in the response in a way that might execute.
        This is a more sophisticated check than just looking for the payload string.
        """
        # First, check for exact payload reflection
        if payload in response_text:
            return True
            
        # Check for HTML-encoded payload
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text and encoded_payload != payload:
            return False  # If it's properly encoded, it's likely safe
            
        # Check for partial encoding (which might still be exploitable)
        if any(char in payload for char in '<>"\'&') and any(part in response_text for part in payload.split()):
            # Look for script tags or event handlers that might have been injected
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check for injected script tags
            for script in soup.find_all('script'):
                script_content = script.string or ""
                if any(part in script_content for part in payload.split()):
                    return True
            
            # Check for injected event handlers
            for tag in soup.find_all():
                for attr in tag.attrs:
                    if attr.startswith('on') and any(part in tag[attr] for part in payload.split()):
                        return True
            
            # Check for injected attributes that might execute JavaScript
            for tag in soup.find_all():
                if tag.has_attr('src') and 'javascript:' in tag['src']:
                    return True
                if tag.has_attr('href') and 'javascript:' in tag['href']:
                    return True
                    
        # Check for DOM-based XSS patterns
        dom_patterns = [
            r'document\.write\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'new\s+Function\s*\(',
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text) and any(part in response_text for part in payload.split()):
                return True
                
        return False
    
    def test_payload(self, target_type, target_details, payload):
        """Test a specific payload against a target."""
        if target_type == 'url':
            url, param = target_details
            is_vulnerable = self.test_xss_in_url(url, param, payload)
            if is_vulnerable:
                self.vulnerable_points.append({
                    'type': 'url',
                    'url': url,
                    'parameter': param,
                    'payload': payload
                })
                return True
        elif target_type == 'form':
            form_details, input_name = target_details
            is_vulnerable = self.test_xss_in_form(form_details, input_name, payload)
            if is_vulnerable:
                self.vulnerable_points.append({
                    'type': 'form',
                    'action': form_details['action'],
                    'method': form_details['method'],
                    'input': input_name,
                    'payload': payload
                })
                return True
        elif target_type == 'js':
            url, param = target_details
            is_vulnerable = self.test_xss_in_js(url, param, payload)
            if is_vulnerable:
                self.vulnerable_points.append({
                    'type': 'js',
                    'url': url,
                    'parameter': param,
                    'payload': payload
                })
                return True
        return False
    
    def scan(self, use_advanced=False):
        """Scan the target for XSS vulnerabilities."""
        self.logger.info(f"Starting XSS scan on {self.target_url}")
        
        # Get payloads
        payloads = XSSPayloads.get_payloads()
        if use_advanced:
            payloads.extend(XSSPayloads.get_advanced_payloads())
            
        # Get context-specific payloads
        context_payloads = XSSPayloads.get_context_specific_payloads()
        
        # Extract all input points
        input_points = self.extract_all_inputs(self.target_url)
        
        if not input_points:
            self.logger.warning(f"No input points found on {self.target_url}")
            # Try to crawl the site to find more pages with inputs
            self.logger.info("Attempting to crawl the site for more pages...")
            additional_urls = self.crawl_site(self.target_url, depth=1)
            
            for url in additional_urls:
                input_points.extend(self.extract_all_inputs(url))
        
        if not input_points:
            self.logger.warning("Still no input points found. The site might not have any injectable parameters.")
            return []
            
        self.logger.info(f"Found {len(input_points)} potential input points to test")
        
        # Prepare all test cases
        test_cases = []
        
        for point_type, *details in input_points:
            # Select appropriate payloads based on the input type
            if point_type == 'url':
                point_payloads = payloads + context_payloads['url']
            elif point_type == 'form':
                point_payloads = payloads + context_payloads['attribute']
            elif point_type == 'js':
                point_payloads = payloads + context_payloads['javascript']
            else:
                point_payloads = payloads
                
            for payload in point_payloads:
                if point_type == 'form':
                    form_details, input_name = details
                    test_cases.append((point_type, (form_details, input_name), payload))
                else:
                    url, param = details
                    test_cases.append((point_type, (url, param), payload))
                
        # Shuffle test cases to distribute load
        random.shuffle(test_cases)
        
        # Run tests in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(tqdm(
                executor.map(lambda x: self.test_payload(x[0], x[1], x[2]), test_cases),
                total=len(test_cases),
                desc="Testing XSS payloads",
                unit="test"
            ))
            
        # Return results
        return self.vulnerable_points
    
    def crawl_site(self, url, depth=1):
        """Simple crawler to find more pages on the site."""
        if depth <= 0:
            return []
            
        visited = set()
        to_visit = {url}
        found_urls = set()
        
        while to_visit and depth > 0:
            current_url = to_visit.pop()
            if current_url in visited:
                continue
                
            visited.add(current_url)
            found_urls.add(current_url)
            
            try:
                response = self.session.get(current_url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                base_url = URLUtils.get_base_url(current_url)
                
                # Find all links
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    
                    # Skip empty links, anchors, and non-HTTP protocols
                    if not href or href.startswith('#') or href.startswith('javascript:'):
                        continue
                        
                    # Make URL absolute if it's relative
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(current_url, href)
                        
                    # Only follow links to the same domain
                    if URLUtils.get_domain(href) == URLUtils.get_domain(base_url):
                        to_visit.add(href)
                        
            except Exception as e:
                self.logger.error(f"Error crawling {current_url}: {str(e)}")
                
            depth -= 1
            
        return list(found_urls)



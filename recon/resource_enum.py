"""
RedAmon - Resource Enumeration Module
=====================================
Comprehensive endpoint discovery and classification.
Discovers all endpoints (GET, POST, APIs) and organizes them by base URL.

Features:
- Katana crawling for endpoint discovery
- HTML form parsing for POST endpoints
- Parameter extraction and classification
- Endpoint categorization (auth, file_access, api, dynamic, static, admin)
- Parameter type detection (id, file, search, auth params)

Pipeline: http_probe -> resource_enum -> vuln_scan
"""

import json
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from html.parser import HTMLParser
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    USE_TOR_FOR_RECON,
    # Katana crawler settings
    KATANA_DOCKER_IMAGE,
    KATANA_DEPTH,
    KATANA_MAX_URLS,
    KATANA_RATE_LIMIT,
    KATANA_TIMEOUT,
    KATANA_JS_CRAWL,
    KATANA_PARAMS_ONLY,
    KATANA_SCOPE,
    KATANA_CUSTOM_HEADERS,
    KATANA_EXCLUDE_PATTERNS,
)


# =============================================================================
# HTML Form Parser
# =============================================================================

class FormParser(HTMLParser):
    """Parse HTML to extract form elements and their inputs."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.in_form = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'form':
            self.in_form = True
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'enctype': attrs_dict.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': []
            }

        elif self.in_form and tag == 'input':
            input_info = {
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', ''),
                'required': 'required' in attrs_dict,
                'placeholder': attrs_dict.get('placeholder', '')
            }
            if input_info['name']:  # Only add inputs with names
                self.current_form['inputs'].append(input_info)

        elif self.in_form and tag == 'textarea':
            input_info = {
                'name': attrs_dict.get('name', ''),
                'type': 'textarea',
                'value': '',
                'required': 'required' in attrs_dict
            }
            if input_info['name']:
                self.current_form['inputs'].append(input_info)

        elif self.in_form and tag == 'select':
            input_info = {
                'name': attrs_dict.get('name', ''),
                'type': 'select',
                'value': '',
                'required': 'required' in attrs_dict
            }
            if input_info['name']:
                self.current_form['inputs'].append(input_info)

        elif self.in_form and tag == 'button':
            btn_type = attrs_dict.get('type', 'submit')
            if btn_type == 'submit' and attrs_dict.get('name'):
                input_info = {
                    'name': attrs_dict.get('name', ''),
                    'type': 'submit',
                    'value': attrs_dict.get('value', '')
                }
                self.current_form['inputs'].append(input_info)

    def handle_endtag(self, tag):
        if tag == 'form' and self.in_form:
            self.in_form = False
            if self.current_form:
                self.forms.append(self.current_form)
            self.current_form = None


def parse_forms_from_html(html_content: str, base_url: str) -> List[Dict]:
    """
    Parse HTML content to extract form information.

    Args:
        html_content: Raw HTML string
        base_url: Base URL for resolving relative form actions

    Returns:
        List of form dictionaries with action, method, and inputs
    """
    if not html_content:
        return []

    try:
        parser = FormParser()
        parser.feed(html_content)

        forms = []
        for form in parser.forms:
            # Resolve relative action URLs
            action = form['action']
            if action:
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(base_url, action)
            else:
                action = base_url  # Form submits to current URL

            form['action'] = action
            form['found_at'] = base_url
            forms.append(form)

        return forms
    except Exception:
        return []


# =============================================================================
# Parameter Classification
# =============================================================================

# Parameter name patterns for classification
PARAM_PATTERNS = {
    'id_params': [
        r'^id$', r'_id$', r'Id$', r'^uid$', r'^pid$', r'^aid$', r'^cid$',
        r'^user_?id$', r'^product_?id$', r'^item_?id$', r'^post_?id$',
        r'^article_?id$', r'^page_?id$', r'^cat_?id$', r'^category_?id$',
        r'^artist$', r'^cat$', r'^pic$', r'^num$', r'^no$', r'^index$'
    ],
    'file_params': [
        r'^file$', r'^filename$', r'^path$', r'^filepath$', r'^download$',
        r'^include$', r'^require$', r'^read$', r'^load$', r'^src$',
        r'^template$', r'^page$', r'^doc$', r'^document$', r'^img$',
        r'^image$', r'^attachment$'
    ],
    'search_params': [
        r'^q$', r'^query$', r'^search$', r'^s$', r'^keyword$', r'^term$',
        r'^find$', r'^filter$', r'^text$', r'^input$'
    ],
    'auth_params': [
        r'^user$', r'^username$', r'^login$', r'^email$', r'^mail$',
        r'^password$', r'^passwd$', r'^pass$', r'^pwd$', r'^token$',
        r'^auth$', r'^key$', r'^apikey$', r'^api_key$', r'^secret$',
        r'^session$', r'^cookie$'
    ],
    'redirect_params': [
        r'^url$', r'^redirect$', r'^return$', r'^next$', r'^goto$',
        r'^target$', r'^dest$', r'^destination$', r'^continue$', r'^ref$',
        r'^callback$', r'^returnurl$', r'^return_url$'
    ],
    'command_params': [
        r'^cmd$', r'^command$', r'^exec$', r'^execute$', r'^run$',
        r'^shell$', r'^system$', r'^ping$', r'^host$', r'^ip$'
    ]
}


def classify_parameter(param_name: str) -> str:
    """Classify a parameter name into a category."""
    param_lower = param_name.lower()

    for category, patterns in PARAM_PATTERNS.items():
        for pattern in patterns:
            if re.match(pattern, param_lower, re.IGNORECASE):
                return category

    return 'other'


def infer_parameter_type(param_name: str, sample_values: List[str]) -> str:
    """Infer the data type of a parameter from its name and sample values."""
    param_lower = param_name.lower()

    # Check sample values first
    if sample_values:
        # Check if all values are numeric
        all_numeric = all(
            v.isdigit() or (v.startswith('-') and v[1:].isdigit())
            for v in sample_values if v
        )
        if all_numeric:
            return 'integer'

        # Check if values look like file paths
        if any('/' in v or '\\' in v or '.' in v for v in sample_values if v):
            if any(v.endswith(('.jpg', '.png', '.gif', '.pdf', '.txt', '.html', '.php', '.js'))
                   for v in sample_values if v):
                return 'path'

        # Check if values look like emails
        if any('@' in v and '.' in v for v in sample_values if v):
            return 'email'

        # Check if values look like URLs
        if any(v.startswith(('http://', 'https://')) for v in sample_values if v):
            return 'url'

    # Infer from parameter name
    if any(p in param_lower for p in ['id', 'num', 'count', 'page', 'limit', 'offset', 'size']):
        return 'integer'
    if any(p in param_lower for p in ['file', 'path', 'dir', 'template', 'include']):
        return 'path'
    if any(p in param_lower for p in ['email', 'mail']):
        return 'email'
    if any(p in param_lower for p in ['url', 'link', 'redirect', 'callback']):
        return 'url'
    if any(p in param_lower for p in ['date', 'time', 'timestamp']):
        return 'datetime'
    if any(p in param_lower for p in ['bool', 'flag', 'enabled', 'active', 'is_']):
        return 'boolean'

    return 'string'


# =============================================================================
# Endpoint Classification
# =============================================================================

def classify_endpoint(path: str, methods: List[str], params: Dict) -> str:
    """
    Classify an endpoint into a category based on path, methods, and parameters.

    Categories:
    - authentication: login, signup, logout, auth-related
    - file_access: file download, image serving, document access
    - api: REST API endpoints
    - admin: admin panels, dashboards
    - dynamic: PHP/ASP/JSP pages with parameters
    - static: HTML, CSS, JS, images
    - upload: file upload endpoints
    - search: search functionality
    """
    path_lower = path.lower()

    # Check for authentication endpoints
    auth_patterns = ['/login', '/signin', '/signup', '/register', '/logout', '/signout',
                     '/auth', '/oauth', '/password', '/reset', '/forgot', '/session',
                     '/token', '/jwt', '/sso']
    if any(p in path_lower for p in auth_patterns):
        return 'authentication'

    # Check for admin endpoints
    admin_patterns = ['/admin', '/dashboard', '/panel', '/manage', '/control',
                      '/backend', '/cms', '/wp-admin', '/administrator']
    if any(p in path_lower for p in admin_patterns):
        return 'admin'

    # Check for API endpoints
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
                    '/json', '/xml', '/rpc']
    if any(p in path_lower for p in api_patterns):
        return 'api'

    # Check for file access endpoints
    file_patterns = ['/download', '/file', '/image', '/img', '/media', '/upload',
                     '/attachment', '/document', '/doc', '/pdf', '/export']
    if any(p in path_lower for p in file_patterns):
        # Check if it's upload vs download
        if any(p in path_lower for p in ['/upload', '/import']):
            return 'upload'
        return 'file_access'

    # Check for search endpoints
    search_patterns = ['/search', '/find', '/query', '/filter', '/browse']
    if any(p in path_lower for p in search_patterns):
        return 'search'

    # Check body params for auth indicators
    body_params = params.get('body', [])
    body_param_names = [p.get('name', '').lower() for p in body_params]
    if any(p in body_param_names for p in ['username', 'password', 'email', 'login']):
        return 'authentication'

    # Check for static files
    static_extensions = ['.html', '.htm', '.css', '.js', '.txt', '.xml', '.json',
                        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
                        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip']
    if any(path_lower.endswith(ext) for ext in static_extensions):
        return 'static'

    # Check for dynamic pages (with query params)
    dynamic_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl']
    if any(path_lower.endswith(ext) for ext in dynamic_extensions):
        return 'dynamic'

    # If has query params, likely dynamic
    if params.get('query'):
        return 'dynamic'

    # Default
    return 'other'


# =============================================================================
# Docker Helpers
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed and accessible."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def pull_katana_docker_image() -> bool:
    """Pull the Katana Docker image if not present."""
    try:
        print(f"    [*] Pulling Katana image: {KATANA_DOCKER_IMAGE}...")
        result = subprocess.run(
            ["docker", "pull", KATANA_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


# =============================================================================
# Katana Crawler
# =============================================================================

def run_katana_crawler(target_urls: List[str], use_proxy: bool = False) -> Tuple[List[str], Dict[str, str]]:
    """
    Run Katana crawler to discover all endpoints.

    Args:
        target_urls: Base URLs to crawl
        use_proxy: Whether to use Tor proxy

    Returns:
        Tuple of (discovered_urls, url_to_response_body)
    """
    print(f"\n[*] Running Katana crawler for endpoint discovery...")
    print(f"    Crawl depth: {KATANA_DEPTH}")
    print(f"    Max URLs: {KATANA_MAX_URLS}")
    print(f"    Rate limit: {KATANA_RATE_LIMIT} req/s")
    print(f"    Params only: {KATANA_PARAMS_ONLY}")

    discovered_urls = set()

    for base_url in target_urls:
        if not base_url.startswith(('http://', 'https://')):
            continue

        # Build Katana command
        cmd = ["docker", "run", "--rm"]

        if use_proxy:
            cmd.extend(["--network", "host"])

        cmd.extend(["-v", "/tmp:/tmp"])

        cmd.extend([
            KATANA_DOCKER_IMAGE,
            "-u", base_url,
            "-d", str(KATANA_DEPTH),
            "-silent",
            "-nc",
            "-rl", str(KATANA_RATE_LIMIT),
            "-timeout", str(KATANA_TIMEOUT),
            "-fs", KATANA_SCOPE,
        ])

        # JavaScript crawling
        if KATANA_JS_CRAWL:
            cmd.append("-jc")

        # Custom headers
        if KATANA_CUSTOM_HEADERS:
            for header in KATANA_CUSTOM_HEADERS:
                cmd.extend(["-H", header])

        # Proxy for Tor
        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=KATANA_TIMEOUT + 60
            )

            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    url = line.strip()
                    if url:
                        # Skip URLs matching exclude patterns
                        url_lower = url.lower()
                        if any(pattern.lower() in url_lower for pattern in KATANA_EXCLUDE_PATTERNS):
                            continue

                        # Apply KATANA_PARAMS_ONLY filter
                        if KATANA_PARAMS_ONLY:
                            if '?' in url and '=' in url:
                                discovered_urls.add(url)
                        else:
                            discovered_urls.add(url)

                        if len(discovered_urls) >= KATANA_MAX_URLS:
                            break

        except subprocess.TimeoutExpired:
            print(f"    [!] Katana timeout for {base_url}")
        except Exception as e:
            print(f"    [!] Katana error for {base_url}: {e}")

        if len(discovered_urls) >= KATANA_MAX_URLS:
            break

    urls_list = sorted(list(discovered_urls))
    print(f"    [+] Katana discovered {len(urls_list)} URLs")

    return urls_list, {}


def fetch_forms_from_urls(urls: List[str], use_proxy: bool = False, max_urls: int = 50) -> List[Dict]:
    """
    Fetch HTML from URLs and extract forms.

    Args:
        urls: URLs to fetch (will filter to HTML pages only)
        use_proxy: Whether to use Tor proxy
        max_urls: Maximum URLs to fetch for form extraction

    Returns:
        List of form dictionaries
    """
    import urllib.request
    import ssl

    all_forms = []

    # Filter to likely HTML pages (exclude static files)
    static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
                         '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip',
                         '.mp3', '.mp4', '.webp', '.xml', '.json', '.txt']

    html_urls = []
    for url in urls:
        url_lower = url.lower().split('?')[0]  # Remove query params for extension check
        if not any(url_lower.endswith(ext) for ext in static_extensions):
            html_urls.append(url)

    # Limit to avoid too many requests
    html_urls = html_urls[:max_urls]

    if not html_urls:
        return all_forms

    print(f"    [*] Fetching HTML from {len(html_urls)} URLs to extract forms...")

    # Create SSL context that doesn't verify certificates (for testing)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Setup proxy if needed
    if use_proxy:
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        })
        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl_context))
    else:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))

    for url in html_urls:
        try:
            request = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            )
            response = opener.open(request, timeout=10)
            content_type = response.headers.get('Content-Type', '')

            # Only process HTML responses
            if 'text/html' in content_type:
                html_content = response.read().decode('utf-8', errors='ignore')
                forms = parse_forms_from_html(html_content, url)
                all_forms.extend(forms)

        except Exception:
            continue

    print(f"    [+] Extracted {len(all_forms)} forms from HTML pages")
    return all_forms


# =============================================================================
# Endpoint Organization
# =============================================================================

def organize_endpoints(
    discovered_urls: List[str],
    use_proxy: bool = False
) -> Dict:
    """
    Organize discovered URLs into structured endpoint data.

    Args:
        discovered_urls: List of URLs discovered by Katana
        use_proxy: Whether to use Tor proxy for form fetching

    Returns:
        Structured endpoint data organized by base URL
    """
    # Track endpoints by base URL
    by_base_url = {}  # base_url -> {path -> endpoint_info}

    # Fetch forms directly from discovered URLs (since http_probe doesn't keep body)
    all_forms = fetch_forms_from_urls(discovered_urls, use_proxy=use_proxy, max_urls=100)

    # Process each discovered URL
    for url in discovered_urls:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme or 'http'
            host = parsed.netloc
            path = parsed.path or '/'
            query_string = parsed.query

            base_url = f"{scheme}://{host}"

            # Initialize base URL entry
            if base_url not in by_base_url:
                by_base_url[base_url] = {}

            # Initialize endpoint entry
            if path not in by_base_url[base_url]:
                by_base_url[base_url][path] = {
                    'path': path,
                    'methods': ['GET'],
                    'parameters': {
                        'query': [],
                        'body': [],
                        'path': []
                    },
                    'sample_urls': [],
                    'urls_found': 0
                }

            endpoint = by_base_url[base_url][path]
            endpoint['urls_found'] += 1

            # Keep sample URLs (max 3)
            if len(endpoint['sample_urls']) < 3:
                endpoint['sample_urls'].append(url)

            # Parse query parameters
            if query_string:
                params = parse_qs(query_string, keep_blank_values=True)
                for param_name, param_values in params.items():
                    # Check if param already exists
                    existing_param = next(
                        (p for p in endpoint['parameters']['query'] if p['name'] == param_name),
                        None
                    )

                    if existing_param:
                        # Add new sample values
                        for val in param_values:
                            if val and val not in existing_param['sample_values']:
                                existing_param['sample_values'].append(val)
                                if len(existing_param['sample_values']) >= 5:
                                    break
                    else:
                        # Create new parameter entry
                        sample_values = [v for v in param_values if v][:5]
                        param_info = {
                            'name': param_name,
                            'type': infer_parameter_type(param_name, sample_values),
                            'sample_values': sample_values,
                            'category': classify_parameter(param_name)
                        }
                        endpoint['parameters']['query'].append(param_info)

        except Exception as e:
            continue

    # Process forms fetched from HTML pages
    for form in all_forms:
        # Add form as endpoint
        action_url = form['action']
        parsed = urlparse(action_url)
        scheme = parsed.scheme or 'http'
        host = parsed.netloc
        path = parsed.path or '/'
        base_url = f"{scheme}://{host}"
        method = form['method']

        if base_url not in by_base_url:
            by_base_url[base_url] = {}

        if path not in by_base_url[base_url]:
            by_base_url[base_url][path] = {
                'path': path,
                'methods': [],
                'parameters': {
                    'query': [],
                    'body': [],
                    'path': []
                },
                'sample_urls': [action_url],
                'urls_found': 1
            }

        endpoint = by_base_url[base_url][path]

        # Add method if not present
        if method not in endpoint['methods']:
            endpoint['methods'].append(method)

        # Add body parameters from form inputs
        for input_field in form['inputs']:
            if input_field['type'] in ['submit', 'button', 'hidden', 'image']:
                continue

            existing_param = next(
                (p for p in endpoint['parameters']['body'] if p['name'] == input_field['name']),
                None
            )

            if not existing_param:
                param_info = {
                    'name': input_field['name'],
                    'type': infer_parameter_type(input_field['name'], []),
                    'input_type': input_field['type'],
                    'required': input_field.get('required', False),
                    'category': classify_parameter(input_field['name'])
                }
                endpoint['parameters']['body'].append(param_info)

    # Add classification and finalize endpoints structure
    endpoints_by_base = {}

    for base_url, paths in by_base_url.items():
        endpoints_by_base[base_url] = {
            'base_url': base_url,
            'endpoints': {},
            'summary': {
                'total_endpoints': 0,
                'total_parameters': 0,
                'methods': {},
                'categories': {}
            }
        }

        for path, endpoint in paths.items():
            # Classify endpoint
            category = classify_endpoint(path, endpoint['methods'], endpoint['parameters'])
            endpoint['category'] = category

            # Count parameters
            query_count = len(endpoint['parameters']['query'])
            body_count = len(endpoint['parameters']['body'])
            path_count = len(endpoint['parameters']['path'])
            total_params = query_count + body_count + path_count

            endpoint['parameter_count'] = {
                'query': query_count,
                'body': body_count,
                'path': path_count,
                'total': total_params
            }

            # Remove sample_urls from final output to save space (keep in endpoints)
            endpoints_by_base[base_url]['endpoints'][path] = endpoint

            # Update summary
            endpoints_by_base[base_url]['summary']['total_endpoints'] += 1
            endpoints_by_base[base_url]['summary']['total_parameters'] += total_params

            for method in endpoint['methods']:
                endpoints_by_base[base_url]['summary']['methods'][method] = \
                    endpoints_by_base[base_url]['summary']['methods'].get(method, 0) + 1

            endpoints_by_base[base_url]['summary']['categories'][category] = \
                endpoints_by_base[base_url]['summary']['categories'].get(category, 0) + 1

    return {
        'by_base_url': endpoints_by_base,
        'forms': all_forms
    }


# =============================================================================
# Main Function
# =============================================================================

def run_resource_enum(recon_data: dict, output_file: Optional[Path] = None) -> dict:
    """
    Run resource enumeration to discover and classify all endpoints.

    Args:
        recon_data: Reconnaissance data from previous modules
        output_file: Optional path to save incremental results

    Returns:
        Updated recon_data with resource_enum results
    """
    print("\n" + "=" * 70)
    print("         RedAmon - Resource Enumeration")
    print("=" * 70)

    # Check Docker
    if not is_docker_installed():
        print("[!] Docker not found. Please install Docker.")
        return recon_data

    if not is_docker_running():
        print("[!] Docker daemon is not running.")
        return recon_data

    # Pull Katana image
    pull_katana_docker_image()

    # Check Tor status
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            use_proxy = True
            print(f"  [*] Anonymous mode: Using Tor SOCKS proxy")
        else:
            print("  [!] Tor not running, falling back to direct connection")

    # Get target URLs from http_probe
    http_probe_data = recon_data.get('http_probe', {})
    target_urls = []

    by_url = http_probe_data.get('by_url', {})
    for url, url_data in by_url.items():
        status_code = url_data.get('status_code')
        if status_code and status_code < 500:
            target_urls.append(url)

    if not target_urls:
        # Fallback to DNS data
        dns_data = recon_data.get('dns', {})
        subdomains = dns_data.get('subdomains', {})
        for subdomain, sub_data in subdomains.items():
            if sub_data.get('has_records'):
                target_urls.append(f"http://{subdomain}")
                target_urls.append(f"https://{subdomain}")

    if not target_urls:
        print("[!] No target URLs found")
        return recon_data

    print(f"  Target URLs: {len(target_urls)}")
    print(f"  Crawl depth: {KATANA_DEPTH}")
    print(f"  Max URLs: {KATANA_MAX_URLS}")
    print("=" * 70 + "\n")

    start_time = datetime.now()

    # Run Katana crawler
    discovered_urls, _ = run_katana_crawler(target_urls, use_proxy)

    # Organize endpoints
    print("\n[*] Organizing and classifying endpoints...")
    organized_data = organize_endpoints(discovered_urls, use_proxy=use_proxy)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Build result structure
    resource_enum_result = {
        'scan_metadata': {
            'scan_timestamp': start_time.isoformat(),
            'scan_duration_seconds': duration,
            'docker_image': KATANA_DOCKER_IMAGE,
            'crawl_depth': KATANA_DEPTH,
            'max_urls': KATANA_MAX_URLS,
            'rate_limit': KATANA_RATE_LIMIT,
            'js_crawl': KATANA_JS_CRAWL,
            'params_only': KATANA_PARAMS_ONLY,
            'proxy_used': use_proxy,
            'target_urls_count': len(target_urls),
            'discovered_urls_count': len(discovered_urls)
        },
        'discovered_urls': sorted(discovered_urls),
        'by_base_url': organized_data['by_base_url'],
        'forms': organized_data['forms'],
        'summary': {
            'total_base_urls': len(organized_data['by_base_url']),
            'total_endpoints': sum(
                data['summary']['total_endpoints']
                for data in organized_data['by_base_url'].values()
            ),
            'total_parameters': sum(
                data['summary']['total_parameters']
                for data in organized_data['by_base_url'].values()
            ),
            'total_forms': len(organized_data['forms']),
            'methods': {},
            'categories': {}
        }
    }

    # Aggregate methods and categories across all base URLs
    for base_data in organized_data['by_base_url'].values():
        for method, count in base_data['summary']['methods'].items():
            resource_enum_result['summary']['methods'][method] = \
                resource_enum_result['summary']['methods'].get(method, 0) + count
        for category, count in base_data['summary']['categories'].items():
            resource_enum_result['summary']['categories'][category] = \
                resource_enum_result['summary']['categories'].get(category, 0) + count

    # Add to recon_data
    recon_data['resource_enum'] = resource_enum_result

    # Save incrementally
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(recon_data, f, indent=2)

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[+] RESOURCE ENUMERATION COMPLETE")
    print(f"[+] Duration: {duration:.2f} seconds")
    print(f"[+] URLs discovered: {len(discovered_urls)}")
    print(f"[+] Base URLs: {resource_enum_result['summary']['total_base_urls']}")
    print(f"[+] Endpoints: {resource_enum_result['summary']['total_endpoints']}")
    print(f"[+] Parameters: {resource_enum_result['summary']['total_parameters']}")
    print(f"[+] Forms (POST): {resource_enum_result['summary']['total_forms']}")

    # Methods breakdown
    methods = resource_enum_result['summary']['methods']
    if methods:
        print(f"\n[+] HTTP Methods:")
        for method, count in sorted(methods.items()):
            print(f"    {method}: {count}")

    # Categories breakdown
    categories = resource_enum_result['summary']['categories']
    if categories:
        print(f"\n[+] Endpoint Categories:")
        for category, count in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"    {category}: {count}")

    print(f"{'=' * 70}")

    return recon_data


if __name__ == "__main__":
    # Test with a sample recon file
    import sys

    if len(sys.argv) > 1:
        recon_file = Path(sys.argv[1])
        if recon_file.exists():
            with open(recon_file, 'r') as f:
                recon_data = json.load(f)

            result = run_resource_enum(recon_data, output_file=recon_file)
            print(f"\n[+] Results saved to: {recon_file}")
        else:
            print(f"[!] File not found: {recon_file}")
    else:
        print("Usage: python resource_enum.py <recon_file.json>")

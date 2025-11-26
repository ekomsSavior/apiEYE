#!/usr/bin/env python3
"""
Bug Bounty API Discovery Scanner
Handles Cloudflare, CDNs, and domain-based targets
"""

import requests
import sys
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from urllib.parse import urlparse
import random

# Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# User agents to rotate (appear more legitimate)
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
]

def print_banner():
    banner = f"""
{Colors.CYAN}{'v'*60}
  API Discovery Scanner
  by:ek0ms savi0r
{'v'*60}{Colors.RESET}
"""
    print(banner)

def get_random_headers():
    """Generate realistic browser headers to bypass basic filters"""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }

def detect_api(response_text, headers, url):
    """Enhanced API detection"""
    response_lower = response_text.lower()
    content_type = headers.get('content-type', '').lower()
    
    # Check for Cloudflare blocks
    if 'cloudflare' in response_lower and ('challenge' in response_lower or 'attention required' in response_lower):
        return False, "Cloudflare Block"
    
    # REST/JSON Detection
    if 'application/json' in content_type:
        return True, "REST/JSON"
    
    if any(indicator in response_lower for indicator in ['{"', '"data":', '"api":', '"response":', '"result":']):
        return True, "REST/JSON"
    
    # GraphQL Detection
    if 'graphql' in response_lower or '"query"' in response_lower or 'graphiql' in response_lower:
        return True, "GraphQL"
    
    # SOAP/XML Detection
    if 'xml' in content_type or '<?xml' in response_text or 'soap:envelope' in response_lower:
        return True, "SOAP/XML"
    
    # API Documentation
    if any(doc in response_lower for doc in ['swagger', 'openapi', 'api documentation', 'api docs', 'redoc']):
        return True, "API Documentation"
    
    # Common API frameworks
    if any(framework in response_lower for framework in ['fastapi', 'django rest', 'express', 'flask-restful']):
        return True, "API Framework"
    
    # Check server headers
    server = headers.get('server', '').lower()
    if any(api_server in server for api_server in ['fastapi', 'werkzeug', 'gunicorn']):
        return True, "API Server"
    
    return False, None

def scan_domain_path(domain, path, timeout=10, delay=0):
    """
    Scan a domain with a specific path
    
    Args:
        domain: Target domain (e.g., api.example.com)
        path: Path to test (e.g., /v1/users)
        timeout: Request timeout
        delay: Delay between requests (rate limiting)
    """
    if delay > 0:
        time.sleep(delay)
    
    # Try both HTTP and HTTPS
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}{path}"
        
        result = {
            'url': url,
            'domain': domain,
            'path': path,
            'scheme': scheme,
            'is_api': False,
            'api_type': None,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=get_random_headers(),
                verify=True  # Verify SSL
            )
            
            is_api, api_type = detect_api(response.text, response.headers, url)
            
            if is_api:
                result['is_api'] = True
                result['api_type'] = api_type
                result['status_code'] = response.status_code
                result['server'] = response.headers.get('server', 'Unknown')
                result['cloudflare'] = 'cf-ray' in response.headers
                
                cloudflare_note = " [CF]" if result['cloudflare'] else ""
                print(f"{Colors.GREEN}[+] API Found: {url} - {api_type}{cloudflare_note}{Colors.RESET}")
                
                return result
                
        except requests.exceptions.SSLError:
            continue  # Try HTTP if HTTPS fails
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue
    
    return None

def generate_api_paths():
    """Generate common API paths to test"""
    return [
        '/',
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/v3',
        '/v1',
        '/v2',
        '/v3',
        '/rest',
        '/rest/v1',
        '/graphql',
        '/api/graphql',
        '/swagger',
        '/api/swagger',
        '/swagger.json',
        '/api/swagger.json',
        '/openapi.json',
        '/api-docs',
        '/docs',
        '/api/docs',
        '/redoc',
        '/api/redoc',
        '/health',
        '/api/health',
        '/status',
        '/api/status',
        '/version',
        '/api/version',
        '/users',
        '/api/users',
        '/auth',
        '/api/auth',
        '/login',
        '/api/login',
    ]

def load_targets_from_file(filename):
    """Load domains from file (one per line)"""
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return domains
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {filename}{Colors.RESET}")
        return []

def save_results(results, output_file="data/bugbounty_apis.txt"):
    """Save results with bug bounty specific format"""
    os.makedirs('data', exist_ok=True)
    
    # Text format
    with open(output_file, 'a') as f:
        for result in results:
            if result and result.get('is_api'):
                cf = " (Cloudflare)" if result.get('cloudflare') else ""
                f.write(f"{result['url']} | {result['api_type']} | "
                       f"Status: {result.get('status_code', 'N/A')}{cf}\n")
    
    # JSON format
    json_file = output_file.replace('.txt', '.json')
    existing = []
    
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as f:
                existing = json.load(f)
        except:
            existing = []
    
    existing.extend([r for r in results if r and r.get('is_api')])
    
    with open(json_file, 'w') as f:
        json.dump(existing, f, indent=2)

def main():
    print_banner()
    
    print(f"{Colors.YELLOW}Bug Bounty Mode - Scan authorized targets only!{Colors.RESET}\n")
    
    # Get input method
    print("How do you want to provide targets?")
    print("1. Enter domains manually")
    print("2. Load from file (domains.txt)")
    
    try:
        choice = input(f"{Colors.CYAN}Choice (1/2): {Colors.RESET}").strip()
        
        domains = []
        
        if choice == '2':
            filename = input(f"{Colors.CYAN}File path (default: domains.txt): {Colors.RESET}").strip() or "domains.txt"
            domains = load_targets_from_file(filename)
            if not domains:
                print(f"{Colors.RED}[!] No domains loaded. Exiting.{Colors.RESET}")
                sys.exit(1)
        else:
            print(f"\n{Colors.CYAN}Enter target domains (one per line, empty line to finish):{Colors.RESET}")
            print("Example: api.example.com")
            while True:
                domain = input("> ").strip()
                if not domain:
                    break
                # Clean domain
                domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                domains.append(domain)
        
        if not domains:
            print(f"{Colors.RED}[!] No domains provided{Colors.RESET}")
            sys.exit(1)
        
        # Get scan configuration
        print(f"\n{Colors.CYAN}Scan Configuration:{Colors.RESET}")
        threads = int(input("Number of threads (recommended: 5-10 for bug bounty): ") or "5")
        delay = float(input("Delay between requests in seconds (0.5-2 recommended): ") or "1")
        
        # Custom paths?
        use_custom = input("Use custom paths? (y/n, default: n): ").strip().lower() == 'y'
        
        if use_custom:
            print("Enter custom paths (one per line, empty to finish):")
            custom_paths = []
            while True:
                path = input("> ").strip()
                if not path:
                    break
                if not path.startswith('/'):
                    path = '/' + path
                custom_paths.append(path)
            paths = custom_paths if custom_paths else generate_api_paths()
        else:
            paths = generate_api_paths()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Cancelled{Colors.RESET}")
        sys.exit(0)
    
    # Generate all targets
    targets = [(domain, path) for domain in domains for path in paths]
    
    print(f"\n{Colors.BOLD}Scan Summary:{Colors.RESET}")
    print(f"  • Domains: {len(domains)}")
    print(f"  • Paths per domain: {len(paths)}")
    print(f"  • Total targets: {len(targets)}")
    print(f"  • Threads: {threads}")
    print(f"  • Delay: {delay}s per request")
    print(f"  • Estimated time: ~{(len(targets) * delay / threads / 60):.1f} minutes")
    
    print(f"\n{Colors.YELLOW}Starting scan... (This may take a while){Colors.RESET}\n")
    
    start_time = time.time()
    results = []
    completed = 0
    
    # Scan with thread pool and rate limiting
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(scan_domain_path, domain, path, 10, delay): (domain, path)
            for domain, path in targets
        }
        
        for future in as_completed(future_to_target):
            result = future.result()
            if result:
                results.append(result)
            
            completed += 1
            
            if completed % 10 == 0:
                progress = (completed / len(targets)) * 100
                print(f"{Colors.BLUE}[*] Progress: {completed}/{len(targets)} ({progress:.1f}%){Colors.RESET}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Save results
    if results:
        save_results(results)
        print(f"\n{Colors.GREEN}[+] Results saved to data/bugbounty_apis.txt and .json{Colors.RESET}")
    
    # Summary
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  Scan Complete!")
    print(f"{'='*60}{Colors.RESET}")
    print(f"  • Time: {duration:.2f} seconds ({duration/60:.1f} minutes)")
    print(f"  • Targets scanned: {len(targets)}")
    print(f"  • APIs discovered: {len(results)}")
    print(f"  • Cloudflare detected: {sum(1 for r in results if r.get('cloudflare'))}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    # Display results
    if results:
        print(f"{Colors.BOLD}Discovered APIs:{Colors.RESET}")
        for r in results:
            cf = " [Cloudflare]" if r.get('cloudflare') else ""
            print(f"  {Colors.GREEN}►{Colors.RESET} {r['url']} - {r['api_type']}{cf}")
    else:
        print(f"{Colors.YELLOW}[!] No APIs found. Try:{Colors.RESET}")
        print("  • Check if domains are correct")
        print("  • Try adding more paths")
        print("  • Increase timeout")
        print("  • Check if you're getting blocked (429 errors)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted{Colors.RESET}")
        sys.exit(0)

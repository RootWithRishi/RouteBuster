#!/usr/bin/env python3
"""
RouteBuster - Terminal-Based Directory/Route Enumeration Tool
Lightweight version - zero external dependencies
For authorized penetration testing only
"""

import os
import sys
import time
import re
import json
import socket
import ssl
import signal
import threading
import queue
import urllib.parse
from datetime import datetime
from typing import List, Optional, Tuple, Dict

# ============ TERMINAL COLORS ============
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLINK = '\033[5m'

# ============ DISCLAIMER ============
DISCLAIMER = f"""
{Color.RED}{Color.BOLD}{'═'*65}{Color.RESET}

{Color.YELLOW}{Color.BOLD}⚠  LEGAL NOTICE & DISCLAIMER  ⚠{Color.RESET}

{Color.WHITE}This tool is for AUTHORIZED security testing ONLY.{Color.RESET}

By proceeding, you CERTIFY under penalty of perjury that:

  {Color.GREEN}✓{Color.RESET} You have EXPLICIT WRITTEN AUTHORIZATION to test
    the target system(s)
  {Color.GREEN}✓{Color.RESET} You are the OWNER of the target system(s) OR
    have a valid penetration testing contract
  {Color.GREEN}✓{Color.RESET} You accept FULL LEGAL RESPONSIBILITY
  {Color.GREEN}✓{Color.RESET} You understand UNAUTHORIZED ACCESS is illegal
    under CFAA and similar laws worldwide

{Color.RED}{Color.BOLD}⚠  UNAUTHORIZED USE = FEDERAL CRIME  ⚠{Color.RESET}
{Color.WHITE}Penalties include up to 20 years imprisonment and
fines up to $500,000+{Color.RESET}

{Color.RED}{Color.BOLD}{'═'*65}{Color.RESET}
"""

def show_disclaimer() -> bool:
    """Show disclaimer and get user consent."""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(DISCLAIMER)
    
    while True:
        choice = input(f"\n{Color.CYAN}[?] Do you accept these terms? (yes/no): {Color.RESET}").strip().lower()
        if choice in ['yes', 'y']:
            os.system('clear' if os.name == 'posix' else 'cls')
            return True
        elif choice in ['no', 'n']:
            print(f"\n{Color.RED}[!] Exiting. This tool is for authorized use only.{Color.RESET}")
            print(f"{Color.YELLOW}[*] Obtain written authorization before testing any system.{Color.RESET}")
            sys.exit(0)
        else:
            print(f"{Color.YELLOW}[!] Please type 'yes' or 'no'{Color.RESET}")

# ============ HTTP ENGINE (Pure Socket - No Dependencies) ============
class HTTPEngine:
    """Pure socket-based HTTP client - no requests library needed."""
    
    @staticmethod
    def request(url: str, method: str = 'GET', headers: Dict = None, 
                timeout: int = 10, verify_ssl: bool = False) -> Tuple[int, int, Dict]:
        """Make HTTP request using raw sockets."""
        headers = headers or {}
        
        # Set default headers
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        if 'Accept' not in headers:
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        if 'Accept-Language' not in headers:
            headers['Accept-Language'] = 'en-US,en;q=0.5'
        if 'Connection' not in headers:
            headers['Connection'] = 'close'
        
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect with SSL if needed
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE if not verify_ssl else ssl.CERT_REQUIRED
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            
            # Build HTTP request
            header_lines = [f"{method} {path} HTTP/1.1"]
            header_lines.append(f"Host: {host}")
            for key, value in headers.items():
                header_lines.append(f"{key}: {value}")
            header_lines.append('')  # End of headers
            header_str = '\r\n'.join(header_lines) + '\r\n'
            
            sock.send(header_str.encode())
            
            # Read response
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            sock.close()
            
            # Parse response
            response_text = response.decode('utf-8', errors='replace')
            header_part, _, body = response_text.partition('\r\n\r\n')
            
            # Parse status code
            status_line = header_part.split('\r\n')[0] if header_part else ''
            status_code = 0
            if status_line:
                match = re.search(r'HTTP/\d\.\d\s+(\d+)', status_line)
                if match:
                    status_code = int(match.group(1))
            
            # Parse response headers
            resp_headers = {}
            for line in header_part.split('\r\n')[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    resp_headers[k.strip().lower()] = v.strip()
            
            return status_code, len(body.encode('utf-8')), resp_headers
        
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            return 0, 0, {}
        except Exception:
            return 0, 0, {}

# ============ SCAN ENGINE ============
STATUS_LABELS = {
    200: 'OK', 201: 'Created', 204: 'No Content',
    301: 'Moved', 302: 'Found', 303: 'See Other', 307: 'Temp Redirect', 308: 'Perm Redirect',
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
    405: 'Method Not Allowed', 500: 'Server Error', 502: 'Bad Gateway', 503: 'Unavailable',
}

class ScanResult:
    def __init__(self, url: str, path: str, status: int, size: int, method: str):
        self.url = url
        self.path = path
        self.status = status
        self.size = size
        self.method = method
        self.time = datetime.now().strftime('%H:%M:%S')

class RouteBuster:
    """Main route enumeration engine."""
    
    def __init__(self):
        self.results: List[ScanResult] = []
        self.total = 0
        self.completed = 0
        self.running = False
        self.start_time = 0.0
        
    def scan(self, base_url: str, wordlist: List[str], extensions: List[str],
             threads: int = 20, timeout: int = 10, delay: float = 0.0,
             method: str = 'GET', recursive: bool = False, max_depth: int = 2,
             min_size: int = 0, user_agent_rotate: bool = False) -> List[ScanResult]:
        """Run the route scan."""
        self.results = []
        self.total = len(wordlist) * len(extensions)
        self.completed = 0
        self.running = True
        self.start_time = time.time()
        
        req_queue = queue.Queue()
        result_queue = queue.Queue()
        
        # Build request queue
        for word in wordlist:
            word = word.strip()
            if not word or word.startswith('#'):
                self.total -= len(extensions)
                continue
            for ext in extensions:
                path = word + ext
                full_url = f"{base_url}/{path}"
                req_queue.put((path, full_url))
        
        print(f"\n{Color.CYAN}[*] Target:{Color.RESET} {base_url}")
        print(f"{Color.CYAN}[*] Requests:{Color.RESET} {self.total:,}")
        print(f"{Color.CYAN}[*] Threads:{Color.RESET} {threads}")
        print(f"{Color.CYAN}[*] Extensions:{Color.RESET} {', '.join(extensions) if extensions[0] else '(none)'}")
        
        if recursive:
            print(f"{Color.CYAN}[*] Recursive:{Color.RESET} Yes (max depth: {max_depth})")
        
        print(f"\n{Color.DIM}{'─'*65}{Color.RESET}")
        print(f"{Color.BOLD}{'  STATUS':<10} {'SIZE':<12} {'ROUTE':<40}{Color.RESET}")
        print(f"{Color.DIM}{'─'*65}{Color.RESET}")
        
        # Worker function
        ua_index = [0]
        
        def worker():
            while self.running and not req_queue.empty():
                try:
                    path, full_url = req_queue.get_nowait()
                except queue.Empty:
                    break
                
                # User-Agent rotation
                req_headers = {}
                if user_agent_rotate:
                    uas = [
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/119.0',
                        'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Firefox/119.0',
                        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) Mobile/15E148',
                    ]
                    ua_index[0] = (ua_index[0] + 1) % len(uas)
                    req_headers['User-Agent'] = uas[ua_index[0]]
                
                # Make request
                status, size, _ = HTTPEngine.request(full_url, method, req_headers, timeout)
                
                self.completed += 1
                
                if status and status not in [404, 400, 0]:
                    if size >= min_size:
                        result = ScanResult(full_url, path, status, size, method)
                        result_queue.put(result)
                
                if delay > 0:
                    time.sleep(delay)
                
                # Show progress
                if self.completed % 50 == 0 or self.completed == self.total:
                    pct = int((self.completed / self.total) * 100) if self.total > 0 else 0
                    print(f"{Color.DIM}[*] Progress: {self.completed}/{self.total} ({pct}%){Color.RESET}")
            
            result_queue.put(None)  # Thread done
        
        # Start threads
        active_threads = min(threads, self.total, 50)
        thread_list = []
        for _ in range(active_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            thread_list.append(t)
        
        # Collect results
        done_count = 0
        while done_count < active_threads:
            try:
                result = result_queue.get(timeout=1)
                if result is None:
                    done_count += 1
                else:
                    self.results.append(result)
                    # Print found result
                    color = Color.GREEN if result.status == 200 else (Color.YELLOW if 300 <= result.status < 400 else Color.RED)
                    status_str = f"{result.status} {STATUS_LABELS.get(result.status, '')}"
                    size_str = self.format_size(result.size)
                    print(f"  {color}[{result.status}]{Color.RESET}  {Color.WHITE}{size_str:<12}{Color.RESET} {result.path}")
            except queue.Empty:
                if not self.running:
                    break
        
        # Wait for threads
        for t in thread_list:
            t.join(timeout=5)
        
        self.running = False
        elapsed = time.time() - self.start_time
        
        print(f"\n{Color.DIM}{'─'*65}{Color.RESET}")
        print(f"\n{Color.GREEN}[✓] Scan complete!{Color.RESET}")
        print(f"{Color.WHITE}  Time: {self.format_time(elapsed)}{Color.RESET}")
        print(f"{Color.WHITE}  Found: {len(self.results)} items{Color.RESET}")
        
        # Recursive scan
        if recursive and max_depth > 0:
            dirs = [r for r in self.results if r.status == 200 and not r.path.endswith(('.php','.asp','.aspx','.jsp','.html','.htm','.txt','.xml','.json','.bak','.zip','.sql','.old','.tar.gz'))]
            if dirs:
                print(f"\n{Color.YELLOW}[*] Starting recursive scan ({len(dirs)} directories)...{Color.RESET}")
                for d in dirs[:5]:  # Limit recursion to first 5 dirs
                    sub_results = self.scan(d.url, wordlist, [''],
                        threads, timeout, delay, method, True, max_depth - 1,
                        min_size, user_agent_rotate)
                    self.results.extend(sub_results)
        
        return self.results
    
    @staticmethod
    def format_size(size: int) -> str:
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f}KB"
        else:
            return f"{size/(1024*1024):.1f}MB"
    
    @staticmethod
    def format_time(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{int(seconds//60)}m {int(seconds%60)}s"
        else:
            return f"{int(seconds//3600)}h {int((seconds%3600)//60)}m"

# ============ INTERACTIVE MENU ============
def print_banner():
    """Display the tool banner."""
    print(f"""{Color.RED}{Color.BOLD}
    ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗ ██╗   ██╗███████╗████████╗
    ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
    ██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝██║   ██║███████╗   ██║   
    ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║   
    ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██████╔╝╚██████╔╝███████║   ██║   
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   
{Color.RESET}
{Color.CYAN}  Lite Edition  •  Terminal-Based  •  Zero Dependencies{Color.RESET}
{Color.DIM}  Authorized Route & Directory Enumeration Tool{Color.RESET}
    """)

def print_results_summary(results: List[ScanResult]):
    """Display results summary."""
    if not results:
        print(f"\n{Color.YELLOW}[!] No interesting routes found.{Color.RESET}")
        return
    
    print(f"\n{Color.CYAN}{'═'*65}{Color.RESET}")
    print(f"{Color.BOLD}{Color.WHITE}  RESULTS SUMMARY ({len(results)} routes){Color.RESET}")
    print(f"{Color.CYAN}{'═'*65}{Color.RESET}")
    
    # Group by status
    by_status = {}
    for r in results:
        by_status.setdefault(r.status, []).append(r)
    
    for status in sorted(by_status.keys()):
        items = by_status[status]
        color = Color.GREEN if status == 200 else (Color.YELLOW if 300 <= status < 400 else Color.RED)
        print(f"\n{color}[{status}] {STATUS_LABELS.get(status, '')} ({len(items)} items){Color.RESET}")
        for r in items[:10]:  # Show top 10 per status
            print(f"  {Color.WHITE}{r.path:<50} {Color.DIM}{RouteBuster.format_size(r.size)}{Color.RESET}")
        if len(items) > 10:
            print(f"  {Color.DIM}... and {len(items) - 10} more{Color.RESET}")
    
    print(f"\n{Color.CYAN}{'═'*65}{Color.RESET}")

# ============ MAIN ============
def main():
    """Main program entry."""
    # Handle Ctrl+C
    def signal_handler(sig, frame):
        print(f"\n{Color.YELLOW}[!] Interrupted by user{Color.RESET}")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Show disclaimer
    show_disclaimer()
    
    # Create engine
    engine = RouteBuster()
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print_banner()
        
        # ============ CONFIGURATION ============
        print(f"{Color.CYAN}{'═'*65}{Color.RESET}")
        print(f"{Color.BOLD}{Color.WHITE}  SCAN CONFIGURATION{Color.RESET}")
        print(f"{Color.CYAN}{'═'*65}{Color.RESET}")
        
        # 1. Target URL
        default_url = "https://example.com"
        url = input(f"\n{Color.GREEN}[1]{Color.RESET} Target URL [{Color.DIM}{default_url}{Color.RESET}]: ").strip()
        if not url:
            url = default_url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url = url.rstrip('/')
        
        # 2. Wordlist
        wordlist_paths = [
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt',
            '/usr/share/wordlists/wfuzz/general/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            './common.txt',
        ]
        
        default_wl = ''
        for p in wordlist_paths:
            if os.path.exists(p):
                default_wl = p
                break
        
        wl_path = input(f"{Color.GREEN}[2]{Color.RESET} Wordlist path [{Color.DIM}{default_wl or 'enter path'}{Color.RESET}]: ").strip()
        if not wl_path:
            wl_path = default_wl
        
        if not wl_path or not os.path.exists(wl_path):
            print(f"{Color.RED}[!] Wordlist not found!{Color.RESET}")
            print(f"{Color.YELLOW}  Create a simple wordlist or use a full path.{Color.RESET}")
            
            fallback = input(f"{Color.CYAN}[?] Use built-in mini wordlist? (y/n): {Color.RESET}").strip().lower()
            if fallback.startswith('y'):
                # Create minimal built-in wordlist
                wl_path = '/tmp/routebuster_mini.txt'
                with open(wl_path, 'w') as f:
                    f.write('\n'.join([
                        'admin','login','wp-admin','administrator','backup','config',
                        'css','images','img','js','assets','uploads','files','download',
                        'api','v1','v2','graphql','test','dev','staging','phpmyadmin',
                        '.git','.env','robots.txt','sitemap.xml','index','index.php',
                        'dashboard','panel','cms','server-status','server-info',
                    ]))
                print(f"{Color.GREEN}[+] Created mini wordlist at {wl_path}{Color.RESET}")
            else:
                print(f"{Color.RED}[!] Cannot proceed without wordlist. Exiting.{Color.RESET}")
                sys.exit(1)
        
        # 3. Extensions
        default_exts = "php,asp,aspx,jsp,html,txt,bak,zip,sql"
        ext_input = input(f"{Color.GREEN}[3]{Color.RESET} Extensions (comma-sep) [{Color.DIM}{default_exts}{Color.RESET}]: ").strip()
        if not ext_input:
            ext_input = default_exts
        extensions = ['.' + e.strip() if not e.strip().startswith('.') and e.strip() else e.strip() for e in ext_input.split(',')]
        extensions = [e for e in extensions if e]  # Remove empties
        if not extensions:
            extensions = ['']
        
        # 4. Threads
        threads_input = input(f"{Color.GREEN}[4]{Color.RESET} Threads [{Color.DIM}20{Color.RESET}]: ").strip()
        threads = int(threads_input) if threads_input.isdigit() else 20
        threads = max(1, min(100, threads))
        
        # 5. Timeout
        timeout_input = input(f"{Color.GREEN}[5]{Color.RESET} Timeout (s) [{Color.DIM}10{Color.RESET}]: ").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else 10
        
        # 6. Method
        method_input = input(f"{Color.GREEN}[6]{Color.RESET} HTTP method [{Color.DIM}GET{Color.RESET}]: ").strip().upper()
        method = method_input if method_input in ['GET', 'HEAD', 'POST'] else 'GET'
        
        # 7. Options
        print(f"\n{Color.DIM}  Advanced options (press Enter for defaults):{Color.RESET}")
        
        delay_input = input(f"{Color.DIM}  Delay between requests (s) [{Color.DIM}0{Color.RESET}]: {Color.RESET}").strip()
        delay = float(delay_input) if delay_input else 0.0
        
        min_size_input = input(f"{Color.DIM}  Min content size [{Color.DIM}0{Color.RESET}]: {Color.RESET}").strip()
        min_size = int(min_size_input) if min_size_input.isdigit() else 0
        
        recursive_input = input(f"{Color.DIM}  Recursive scan? (y/n) [{Color.DIM}n{Color.RESET}]: {Color.RESET}").strip().lower()
        recursive = recursive_input.startswith('y')
        
        max_depth = 2
        if recursive:
            depth_input = input(f"{Color.DIM}  Max recursion depth [{Color.DIM}2{Color.RESET}]: {Color.RESET}").strip()
            max_depth = int(depth_input) if depth_input.isdigit() else 2
        
        rotate_ua_input = input(f"{Color.DIM}  Rotate User-Agent? (y/n) [{Color.DIM}y{Color.RESET}]: {Color.RESET}").strip().lower()
        rotate_ua = not rotate_ua_input.startswith('n')
        
        # ============ SUMMARY ============
        print(f"\n{Color.CYAN}{'═'*65}{Color.RESET}")
        print(f"{Color.BOLD}{Color.WHITE}  SCAN SUMMARY{Color.RESET}")
        print(f"{Color.CYAN}{'═'*65}{Color.RESET}")
        print(f"{Color.WHITE}  URL:        {Color.GREEN}{url}{Color.RESET}")
        print(f"{Color.WHITE}  Wordlist:   {Color.YELLOW}{os.path.basename(wl_path)}{Color.RESET} ({sum(1 for _ in open(wl_path))} lines)")
        print(f"{Color.WHITE}  Extensions: {Color.CYAN}{', '.join(extensions)}{Color.RESET}")
        print(f"{Color.WHITE}  Threads:    {Color.MAGENTA}{threads}{Color.RESET}")
        print(f"{Color.WHITE}  Method:     {Color.BLUE}{method}{Color.RESET}")
        print(f"{Color.WHITE}  Recursive:  {'Yes' if recursive else 'No'}{Color.RESET}")
        print(f"{Color.CYAN}{'═'*65}{Color.RESET}")
        
        start_input = input(f"\n{Color.GREEN}[?] Start scan? (yes/no/edit): {Color.RESET}").strip().lower()
        if start_input == 'no' or start_input == 'n':
            print(f"{Color.YELLOW}[*] Exiting.{Color.RESET}")
            sys.exit(0)
        elif start_input == 'edit' or start_input == 'e':
            continue
        
        # ============ LOAD WORDLIST ============
        print(f"\n{Color.CYAN}[*] Loading wordlist...{Color.RESET}")
        try:
            with open(wl_path, 'r', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Color.RED}[!] Error loading wordlist: {e}{Color.RESET}")
            input(f"\n{Color.YELLOW}[Press Enter to retry]{Color.RESET}")
            continue
        
        if not wordlist:
            print(f"{Color.RED}[!] Wordlist is empty!{Color.RESET}")
            input(f"\n{Color.YELLOW}[Press Enter]{Color.RESET}")
            continue
        
        print(f"{Color.GREEN}[+] Loaded {len(wordlist):,} words{Color.RESET}")
        
        # ============ RUN SCAN ============
        results = engine.scan(
            base_url=url,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads,
            timeout=timeout,
            delay=delay,
            method=method,
            recursive=recursive,
            max_depth=max_depth,
            min_size=min_size,
            user_agent_rotate=rotate_ua
        )
        
        # ============ POST-SCAN MENU ============
        print_results_summary(results)
        
        print(f"\n{Color.CYAN}Options:{Color.RESET}")
        print(f"  [{Color.GREEN}1{Color.RESET}] Export results to file")
        print(f"  [{Color.GREEN}2{Color.RESET}] New scan")
        print(f"  [{Color.GREEN}3{Color.RESET}] Exit")
        
        post_choice = input(f"\n{Color.CYAN}[?] Choose: {Color.RESET}").strip()
        
        if post_choice == '1':
            # Export
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"routebuster_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write(f"RouteBuster Scan Results\n")
                f.write(f"Target: {url}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Found: {len(results)} routes\n")
                f.write(f"{'='*70}\n\n")
                
                for r in sorted(results, key=lambda x: (x.status, x.path)):
                    f.write(f"[{r.status}] {r.path} ({RouteBuster.format_size(r.size)})\n")
            
            print(f"{Color.GREEN}[+] Results saved to: {filename}{Color.RESET}")
            input(f"\n{Color.YELLOW}[Press Enter]{Color.RESET}")
            
        elif post_choice == '2' or post_choice == '':
            continue
        else:
            print(f"{Color.YELLOW}[*] Exiting.{Color.RESET}")
            sys.exit(0)

if __name__ == '__main__':
    main()
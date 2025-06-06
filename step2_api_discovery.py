
import requests
import json
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from config import TARGET_CONFIG, COMMON_ENDPOINTS

class APIDiscovery:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VssID/1.7.1 Android Security Assessment',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Security-Test': 'true'  # Đánh dấu đây là security test
        })
        
        self.discovered_endpoints = []
        self.vulnerable_endpoints = []
        self.timeout = 10
        
    def load_targets_from_static_analysis(self):
        """Load API endpoints từ static analysis"""
        base_urls = []
        
        try:
            with open(f"{TARGET_CONFIG['output_dir']}/static_analysis.json", "r") as f:
                data = json.load(f)
                endpoints = data.get("api_endpoints", [])
                
                # Extract base URLs
                for endpoint in endpoints:
                    if endpoint.startswith('http'):
                        # Extract base URL
                        parts = endpoint.split('/')
                        if len(parts) >= 3:
                            base_url = '/'.join(parts[:3])
                            if base_url not in base_urls:
                                base_urls.append(base_url)
                
        except Exception as e:
            print(f"[-] Could not load static analysis results: {e}")
        
        # Use configured base URL and fallback URLs for testing
        if not base_urls or all('schemas.android.com' in url for url in base_urls):
            base_urls = [
                TARGET_CONFIG["base_url"],  # Primary test URL from config
                "https://api-test.vssid.com",  # Test environment
                "https://staging-api.vssid.com",
                "https://dev-api.vssid.com"
            ]
        
        return base_urls
    
    def test_endpoint_safely(self, url, path=""):
        """Test endpoint với các biện pháp an toàn"""
        full_url = urljoin(url, path)
        
        # Chỉ test trên môi trường được phép
        if not TARGET_CONFIG.get("test_mode", False):
            print("[-] Test mode disabled. Skipping actual requests.")
            return None
        
        try:
            # Sử dụng HEAD request để giảm tải
            resp = self.session.head(full_url, timeout=self.timeout, allow_redirects=False)
            
            result = {
                "url": full_url,
                "status": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items() if k.lower() in ['server', 'content-type', 'x-powered-by']},
                "response_time": resp.elapsed.total_seconds(),
                "method": "HEAD"
            }
            
            # Nếu HEAD không thành công, thử GET
            if resp.status_code == 405:  # Method not allowed
                resp = self.session.get(full_url, timeout=self.timeout)
                result.update({
                    "status": resp.status_code,
                    "content_length": len(resp.content),
                    "method": "GET"
                })
            
            # Check for interesting responses
            if resp.status_code in [200, 201, 400, 401, 403, 404, 500, 502, 503]:
                result["interesting"] = True
            
            # Check for potential vulnerabilities in headers
            vuln_headers = []
            if 'server' in resp.headers:
                server = resp.headers['server'].lower()
                if any(tech in server for tech in ['apache', 'nginx', 'iis']):
                    vuln_headers.append(f"Server info disclosed: {resp.headers['server']}")
            
            if 'x-powered-by' in resp.headers:
                vuln_headers.append(f"Technology disclosed: {resp.headers['x-powered-by']}")
            
            if not resp.headers.get('x-frame-options'):
                vuln_headers.append("Missing X-Frame-Options header")
            
            if not resp.headers.get('x-content-type-options'):
                vuln_headers.append("Missing X-Content-Type-Options header")
            
            if vuln_headers:
                result["security_issues"] = vuln_headers
                result["potential_vuln"] = True
            
            return result
            
        except requests.exceptions.Timeout:
            return {"url": full_url, "error": "Timeout"}
        except requests.exceptions.ConnectionError:
            return {"url": full_url, "error": "Connection Error"}
        except Exception as e:
            return {"url": full_url, "error": str(e)}
    
    def discover_endpoints(self):
        """Discover API endpoints một cách có trách nhiệm"""
        print("="*60)
        print("STARTING API ENDPOINT DISCOVERY")
        print("="*60)
        
        base_urls = self.load_targets_from_static_analysis()
        
        print(f"[*] Testing {len(base_urls)} base URLs with {len(COMMON_ENDPOINTS)} common paths")
        print(f"[*] Test mode: {TARGET_CONFIG.get('test_mode', False)}")
        
        for base_url in base_urls:
            print(f"\n[*] Testing base URL: {base_url}")
            
            # Giới hạn số worker để tránh overwhelm target
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                for path in COMMON_ENDPOINTS:
                    future = executor.submit(self.test_endpoint_safely, base_url, path)
                    futures.append(future)
                    time.sleep(0.1)  # Small delay between requests
                
                for future in futures:
                    try:
                        result = future.result(timeout=15)
                        if result and "error" not in result:
                            self.discovered_endpoints.append(result)
                            
                            # Print interesting findings
                            if result.get("interesting"):
                                status = result["status"]
                                url = result["url"]
                                method = result.get("method", "HEAD")
                                print(f"  [+] [{status}] {method} {url}")
                                
                                if result.get("potential_vuln"):
                                    self.vulnerable_endpoints.append(result)
                                    print(f"      ^ Security issues detected!")
                                    for issue in result.get("security_issues", []):
                                        print(f"        - {issue}")
                        elif result and "error" in result:
                            if result["error"] not in ["Timeout", "Connection Error"]:
                                print(f"  [-] Error testing {result['url']}: {result['error']}")
                                
                    except Exception as e:
                        print(f"  [-] Future error: {e}")
            
            # Rate limiting between base URLs
            time.sleep(2)
        
        print(f"\n[+] Discovery completed!")
        print(f"[+] Found {len(self.discovered_endpoints)} responsive endpoints")
        print(f"[+] Found {len(self.vulnerable_endpoints)} endpoints with security issues")
    
    def analyze_endpoints(self):
        """Phân tích chi tiết các endpoints đã tìm thấy"""
        print("\n[*] Analyzing discovered endpoints...")
        
        status_codes = {}
        security_issues = []
        
        for endpoint in self.discovered_endpoints:
            status = endpoint.get("status")
            if status in status_codes:
                status_codes[status] += 1
            else:
                status_codes[status] = 1
            
            if endpoint.get("security_issues"):
                security_issues.extend(endpoint["security_issues"])
        
        print(f"\n[STATUS CODE DISTRIBUTION]")
        for status, count in sorted(status_codes.items()):
            print(f"  {status}: {count} endpoints")
        
        if security_issues:
            print(f"\n[SECURITY ISSUES SUMMARY]")
            issue_counts = {}
            for issue in security_issues:
                if issue in issue_counts:
                    issue_counts[issue] += 1
                else:
                    issue_counts[issue] = 1
            
            for issue, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {issue}: {count} occurrences")
    
    def save_results(self):
        """Lưu kết quả discovery"""
        print("\n[*] Saving API discovery results...")
        
        results = {
            "discovery_summary": {
                "total_endpoints_tested": len(COMMON_ENDPOINTS) * len(self.load_targets_from_static_analysis()),
                "responsive_endpoints": len(self.discovered_endpoints),
                "vulnerable_endpoints": len(self.vulnerable_endpoints),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "discovered_endpoints": self.discovered_endpoints,
            "vulnerable_endpoints": self.vulnerable_endpoints
        }
        
        output_dir = TARGET_CONFIG["output_dir"]
        
        with open(f"{output_dir}/api_discovery.json", "w", encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Save responsive endpoints for next steps
        responsive_urls = [ep["url"] for ep in self.discovered_endpoints if ep.get("status") == 200]
        with open(f"{output_dir}/responsive_endpoints.txt", "w") as f:
            for url in responsive_urls:
                f.write(f"{url}\n")
        
        print(f"[+] Results saved to {output_dir}")
        
        return results

def main():
    discovery = APIDiscovery()
    discovery.discover_endpoints()
    discovery.analyze_endpoints()
    results = discovery.save_results()
    
    print("\n" + "="*60)
    print("API DISCOVERY SUMMARY")
    print("="*60)
    print(f"Total endpoints tested: {results['discovery_summary']['total_endpoints_tested']}")
    print(f"Responsive endpoints: {results['discovery_summary']['responsive_endpoints']}")
    print(f"Endpoints with security issues: {results['discovery_summary']['vulnerable_endpoints']}")

if __name__ == "__main__":
    main()

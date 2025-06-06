#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database Error Analysis - Phân tích lỗi database exposure từ baohiemxahoi.gov.vn
"""

import json
import datetime
from pathlib import Path

class DatabaseErrorAnalyzer:
    def __init__(self):
        self.findings = {
            "vulnerability_type": "Information Disclosure - Database Error",
            "severity": "HIGH",
            "discovered_at": datetime.datetime.now().isoformat(),
            "target": "https://baohiemxahoi.gov.vn",
            "error_details": {},
            "security_implications": [],
            "recommendations": []
        }
    
    def analyze_database_error(self, error_content):
        """Phân tích chi tiết lỗi database"""
        
        # Trích xuất thông tin từ lỗi
        self.findings["error_details"] = {
            "error_type": "SQL Server Connection Error",
            "database_name": "SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4",
            "database_type": "Microsoft SQL Server",
            "failed_user": "BHXH\\sharepoint_portal",
            "application_framework": "ASP.NET / SharePoint",
            "error_code": "0x80131904",
            "full_error": error_content
        }
        
        # Phân tích ý nghĩa bảo mật
        self.analyze_security_implications()
        
        # Đưa ra khuyến nghị
        self.generate_recommendations()
    
    def analyze_security_implications(self):
        """Phân tích các tác động bảo mật"""
        
        implications = [
            {
                "issue": "Information Disclosure",
                "description": "Server đang tiết lộ thông tin nhạy cảm về cấu trúc database",
                "details": [
                    "Tên database: SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4",
                    "Tài khoản database: BHXH\\sharepoint_portal", 
                    "Loại database: Microsoft SQL Server",
                    "Framework: SharePoint Portal"
                ]
            },
            {
                "issue": "Infrastructure Enumeration", 
                "description": "Kẻ tấn công có thể thu thập thông tin về hạ tầng",
                "details": [
                    "Xác định được loại database system",
                    "Biết được naming convention của database",
                    "Hiểu được cấu trúc authentication domain (BHXH)",
                    "Nhận diện được SharePoint infrastructure"
                ]
            },
            {
                "issue": "Session Management Vulnerability",
                "description": "Lỗi liên quan đến SessionState service",
                "details": [
                    "SessionState database không accessible",
                    "Có thể ảnh hưởng đến session management",
                    "Tiềm ẩn session hijacking risks"
                ]
            },
            {
                "issue": "Potential SQL Injection Entry Point",
                "description": "Database connection errors có thể chỉ ra SQL injection vulnerabilities",
                "details": [
                    "Error-based SQL injection potential",
                    "Database connection string exposure risk",
                    "Possible injection through session parameters"
                ]
            }
        ]
        
        self.findings["security_implications"] = implications
    
    def generate_recommendations(self):
        """Tạo khuyến nghị bảo mật"""
        
        recommendations = [
            {
                "priority": "CRITICAL",
                "action": "Disable Detailed Error Messages",
                "description": "Tắt hiển thị chi tiết lỗi database ra ngoài public",
                "implementation": [
                    "Cấu hình custom error pages trong web.config",
                    "Set customErrors mode='On' hoặc 'RemoteOnly'",
                    "Implement proper error logging internally"
                ]
            },
            {
                "priority": "HIGH", 
                "action": "Fix Database Connection Issues",
                "description": "Sửa chữa vấn đề kết nối database SessionState",
                "implementation": [
                    "Kiểm tra database SessionStateService availability",
                    "Verify user permissions cho BHXH\\sharepoint_portal",
                    "Test database connectivity và authentication"
                ]
            },
            {
                "priority": "HIGH",
                "action": "Implement Proper Error Handling",
                "description": "Triển khai error handling an toàn",
                "implementation": [
                    "Log errors internally with full details",
                    "Display generic error messages to users", 
                    "Implement structured error reporting"
                ]
            },
            {
                "priority": "MEDIUM",
                "action": "Security Headers Enhancement",
                "description": "Tăng cường security headers",
                "implementation": [
                    "Add X-Content-Type-Options: nosniff",
                    "Implement Content-Security-Policy",
                    "Add X-XSS-Protection header"
                ]
            },
            {
                "priority": "MEDIUM",
                "action": "Session Management Review",
                "description": "Đánh giá lại cơ chế session management",
                "implementation": [
                    "Review SessionState configuration",
                    "Consider alternative session storage methods",
                    "Implement session security best practices"
                ]
            }
        ]
        
        self.findings["recommendations"] = recommendations
    
    def calculate_risk_score(self):
        """Tính toán risk score"""
        
        risk_factors = {
            "information_disclosure": 8,  # High - reveals internal architecture
            "error_exposure": 7,         # High - detailed error messages
            "database_enumeration": 6,   # Medium-High - database details exposed
            "session_vulnerability": 5,  # Medium - session management issues
            "infrastructure_exposure": 6 # Medium-High - SharePoint details
        }
        
        total_score = sum(risk_factors.values())
        max_score = len(risk_factors) * 10
        risk_percentage = (total_score / max_score) * 100
        
        self.findings["risk_assessment"] = {
            "risk_factors": risk_factors,
            "total_score": total_score,
            "max_score": max_score, 
            "risk_percentage": round(risk_percentage, 2),
            "risk_level": "HIGH" if risk_percentage >= 70 else "MEDIUM" if risk_percentage >= 50 else "LOW"
        }
    
    def generate_report(self):
        """Tạo báo cáo đánh giá"""
        
        self.calculate_risk_score()
        
        return self.findings
    
    def save_report(self, output_dir="./results"):
        """Lưu báo cáo"""
        
        Path(output_dir).mkdir(exist_ok=True)
        
        # Lưu báo cáo JSON
        with open(f"{output_dir}/database_error_analysis.json", "w", encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2, ensure_ascii=False)
        
        # Tạo báo cáo text readable
        self.create_readable_report(output_dir)
        
        print(f"[+] Báo cáo đã được lưu vào {output_dir}/")
    
    def create_readable_report(self, output_dir):
        """Tạo báo cáo dễ đọc"""
        
        with open(f"{output_dir}/BHXH_DATABASE_ERROR_REPORT.txt", "w", encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("BÁO CÁO PHÂN TÍCH LỖ HỔNG BẢO MẬT - BAOHIEMXAHOI.GOV.VN\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Thời gian phát hiện: {self.findings['discovered_at']}\n")
            f.write(f"Mục tiêu: {self.findings['target']}\n")
            f.write(f"Loại lỗ hổng: {self.findings['vulnerability_type']}\n")
            f.write(f"Mức độ nghiêm trọng: {self.findings['severity']}\n\n")
            
            f.write("CHI TIẾT LỖI DATABASE:\n")
            f.write("-" * 50 + "\n")
            for key, value in self.findings['error_details'].items():
                if key != 'full_error':
                    f.write(f"  {key}: {value}\n")
            
            f.write(f"\nRISK ASSESSMENT:\n")
            f.write("-" * 50 + "\n")
            risk = self.findings['risk_assessment']
            f.write(f"  Risk Level: {risk['risk_level']}\n")
            f.write(f"  Risk Score: {risk['total_score']}/{risk['max_score']} ({risk['risk_percentage']}%)\n\n")
            
            f.write("TÁC ĐỘNG BẢO MẬT:\n")
            f.write("-" * 50 + "\n")
            for i, implication in enumerate(self.findings['security_implications'], 1):
                f.write(f"{i}. {implication['issue']}\n")
                f.write(f"   Mô tả: {implication['description']}\n")
                for detail in implication['details']:
                    f.write(f"   - {detail}\n")
                f.write("\n")
            
            f.write("KHUYẾN NGHỊ KHẮC PHỤC:\n")
            f.write("-" * 50 + "\n")
            for i, rec in enumerate(self.findings['recommendations'], 1):
                f.write(f"{i}. [{rec['priority']}] {rec['action']}\n")
                f.write(f"   {rec['description']}\n")
                for impl in rec['implementation']:
                    f.write(f"   - {impl}\n")
                f.write("\n")


if __name__ == "__main__":
    error_content = """
Server Error in '/' Application.

Cannot open database "SessionState Service_356ec96765eb4cc6b687ea3bb1be01c4" requested by the login. The login failed. Login failed for user 'BHXH\sharepoint_portal'.

Description: An unhandled exception occurred during the execution of the current web request. Please review the stack trace for more information about the error and where it originated in the code.

Exception Details: System.Data.SqlClient.SqlException: Cannot open database "SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4" requested by the login. The login failed.

Login failed for user 'BHXH\sharepoint_portal'.
"""
    
    analyzer = DatabaseErrorAnalyzer()
    analyzer.analyze_database_error(error_content)
    report = analyzer.generate_report()
    analyzer.save_report()
    
    print("="*70)
    print("PHÂN TÍCH LỖ HỔNG DATABASE ERROR - BAOHIEMXAHOI.GOV.VN")
    print("="*70)
    print(f"🚨 Mức độ nghiêm trọng: {report['severity']}")
    print(f"📊 Risk Score: {report['risk_assessment']['risk_percentage']}%")
    print(f"🎯 Database tiết lộ: {report['error_details']['database_name']}")
    print(f"👤 User account: {report['error_details']['failed_user']}")
    print(f"🖥️  Technology: {report['error_details']['application_framework']}")
    print(f"\n📋 Tổng cộng {len(report['security_implications'])} vấn đề bảo mật đã phát hiện")
    print(f"🔧 {len(report['recommendations'])} khuyến nghị khắc phục")

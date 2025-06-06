#!/usr/bin/env python3
"""
BHXH Customer Data Extraction to Excel
Export all collected customer data to comprehensive Excel report
"""

import json
import pandas as pd
import os
from datetime import datetime
from pathlib import Path
import re
from bhxh_data_standardizer import BHXHDataStandardizer

class CustomerDataExcelExporter:
    def __init__(self):
        self.base_dir = Path("C:/Users/user/Desktop/LightblueQueasyInversion")
        self.customer_dir = self.base_dir / "customer_data_evidence"
        self.session_dir = self.base_dir / "sessionstate_exploitation"
        self.evidence_dir = self.base_dir / "evidence"
        self.data_standardizer = BHXHDataStandardizer()
        
        # Initialize data containers
        self.customer_data = []
        self.token_data = []
        self.session_data = []
        self.vulnerability_data = []
        self.database_exposures = []
        
        print(f"📁 Initializing Customer Data Excel Exporter...")
        print(f"Base directory: {self.base_dir}")

    def extract_customer_data_from_analysis(self):
        """Extract customer data from comprehensive analysis file và chuẩn hóa dữ liệu"""
        try:
            analysis_file = self.base_dir / "TOKEN_DATA_COMPREHENSIVE_ANALYSIS.json"
            if analysis_file.exists():
                with open(analysis_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                customer_analysis = data.get("customer_data_analysis", {})
                sample_data = customer_analysis.get("sample_data", [])
                for item in sample_data:
                    # Chuẩn hóa dữ liệu nếu là các trường chính
                    std_result = self.data_standardizer.standardize_customer_data(item)
                    std = std_result.get("standardized_data", {})
                    customer_record = {
                        "Data_Type": item.get("type", ""),
                        "Value": item.get("value", ""),
                        "Standardized_Value": std.get(item.get("type", ""), item.get("value", "")),
                        "Category": self.categorize_data_type(item.get("type", "")),
                        "Risk_Level": self.assess_data_risk(item.get("type", "")),
                        "Source": "Token Analysis",
                        "Extraction_Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.customer_data.append(customer_record)
                print(f"[+] Extracted {len(sample_data)} customer data samples from analysis")
        except Exception as e:
            print(f"[-] Error extracting from analysis: {e}")

    def extract_tokens_from_analysis(self):
        """Extract token data for Excel report"""
        try:
            analysis_file = self.base_dir / "TOKEN_DATA_COMPREHENSIVE_ANALYSIS.json"
            if analysis_file.exists():
                with open(analysis_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                tokens_analysis = data.get("tokens_analysis", {})
                sample_tokens = tokens_analysis.get("sample_tokens", [])
                token_distribution = tokens_analysis.get("token_type_distribution", {})
                
                for i, token in enumerate(sample_tokens):
                    token_record = {
                        "Token_ID": f"TOKEN_{i+1:03d}",
                        "Token_Value": token,
                        "Token_Type": self.identify_token_type(token),
                        "Length": len(token),
                        "Security_Risk": "HIGH" if "session" in token.lower() else "MEDIUM",
                        "Potential_Use": self.analyze_token_usage(token),
                        "Discovery_Source": "Live System Extraction",
                        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.token_data.append(token_record)
                
                print(f"[+] Extracted {len(sample_tokens)} tokens for Excel export")
        
        except Exception as e:
            print(f"[-] Error extracting tokens: {e}")

    def extract_sessionstate_data(self):
        """Extract SessionState compromise data"""
        try:
            session_file = self.session_dir / "20250606_100508_COMPREHENSIVE_SESSIONSTATE_EXPLOITATION.json"
            if session_file.exists():
                with open(session_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                phases = data.get("exploitation_phases", [])
                for phase in phases:
                    phase_name = phase.get("phase", "")
                    results = phase.get("results", [])
                    
                    for result in results:
                        session_record = {
                            "Phase": phase_name,
                            "URL": result.get("url", ""),
                            "Payload": result.get("payload", "")[:100] + "..." if len(result.get("payload", "")) > 100 else result.get("payload", ""),
                            "Status_Code": result.get("status_code", ""),
                            "User_Data_Found": result.get("user_data_found", False),
                            "Timestamp": result.get("timestamp", ""),
                            "Risk_Assessment": "CRITICAL" if result.get("user_data_found") else "HIGH"
                        }
                        self.session_data.append(session_record)
                
                print(f"[+] Extracted {len(self.session_data)} session exploitation records")
        
        except Exception as e:
            print(f"[-] Error extracting session data: {e}")

    def extract_vulnerability_data(self):
        """Extract vulnerability data from evidence files"""
        try:
            exploits_dir = self.evidence_dir / "exploits"
            if exploits_dir.exists():
                sql_injection_count = 0
                database_error_count = 0
                
                for file in exploits_dir.iterdir():
                    if file.is_file() and file.suffix == '.json':
                        if "time_based_sqli" in file.name:
                            sql_injection_count += 1
                            try:
                                with open(file, 'r', encoding='utf-8') as f:
                                    vuln_data = json.load(f)
                                
                                vuln_record = {
                                    "Vulnerability_Type": "Time-based SQL Injection",
                                    "URL": vuln_data.get("url", ""),
                                    "Payload": vuln_data.get("payload", ""),
                                    "Response_Time": vuln_data.get("response_time", 0),
                                    "Status_Code": vuln_data.get("status_code", ""),
                                    "Severity": vuln_data.get("severity", ""),
                                    "Exploitable": "YES",
                                    "Discovery_Time": vuln_data.get("timestamp", ""),
                                    "Evidence_File": file.name
                                }
                                self.vulnerability_data.append(vuln_record)
                            except:
                                continue
                        
                        elif "database_error" in file.name:
                            database_error_count += 1
                            db_exposure = {
                                "Exposure_Type": "Database Error Information",
                                "Evidence_File": file.name,
                                "Database_Name": "SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4",
                                "User_Exposed": "BHXH\\sharepoint_portal",
                                "Risk_Level": "CRITICAL",
                                "Data_Leaked": "Database schema, user credentials, session info",
                                "Discovery_Time": file.stat().st_mtime
                            }
                            self.database_exposures.append(db_exposure)
                
                print(f"[+] Found {sql_injection_count} SQL injection vulnerabilities")
                print(f"[+] Found {database_error_count} database error exposures")
        
        except Exception as e:
            print(f"[-] Error extracting vulnerability data: {e}")

    def categorize_data_type(self, data_type):
        """Categorize customer data types"""
        categories = {
            "ma_bao_hiem": "Insurance Information",
            "so_cmnd": "Personal Identification", 
            "ma_kiem_tra": "Verification Codes",
            "so_dien_thoai": "Contact Information"
        }
        return categories.get(data_type, "Other")

    def assess_data_risk(self, data_type):
        """Assess risk level of data type"""
        high_risk = ["so_cmnd", "ma_bao_hiem", "so_dien_thoai"]
        medium_risk = ["ma_kiem_tra"]
        
        if data_type in high_risk:
            return "HIGH"
        elif data_type in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    def identify_token_type(self, token):
        """Identify token type based on characteristics"""
        if len(token) == 24 and token.isalnum():
            return "ASP.NET Session ID"
        elif "=" in token and len(token) > 20:
            return "Base64 Encoded Token"
        elif len(token) == 32 and all(c in '0123456789abcdef' for c in token.lower()):
            return "MD5 Hash"
        else:
            return "Custom Token Format"

    def analyze_token_usage(self, token):
        """Analyze potential token usage"""
        if len(token) == 24:
            return "Session Management, User Authentication"
        elif "=" in token:
            return "Data Encoding, API Authentication"
        else:
            return "System Authentication, Access Control"

    def create_summary_data(self):
        """Create summary statistics for Excel report"""
        final_analysis_file = self.base_dir / "FINAL_COMPREHENSIVE_ANALYSIS_20250606_102510.json"
        summary_data = []
        
        try:
            if final_analysis_file.exists():
                with open(final_analysis_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                stats = data.get("final_statistics", {})
                
                summary_data = [
                    {"Metric": "Total Vulnerabilities", "Value": stats.get("total_vulnerabilities", 0), "Status": "CRITICAL"},
                    {"Metric": "SQL Injections Found", "Value": stats.get("sql_injections", 0), "Status": "EXPLOITABLE"},
                    {"Metric": "Tokens Collected", "Value": stats.get("tokens_analyzed", 0), "Status": "COMPROMISED"},
                    {"Metric": "Customer Data Points", "Value": stats.get("customer_data_points", 0), "Status": "EXPOSED"},
                    {"Metric": "Database Compromises", "Value": stats.get("database_compromises", 0), "Status": "CRITICAL"},
                    {"Metric": "Evidence Files", "Value": stats.get("evidence_files", 0), "Status": "DOCUMENTED"},
                    {"Metric": "Risk Score", "Value": f"{stats.get('risk_score', 0)}/100", "Status": stats.get('risk_level', 'UNKNOWN')},
                    {"Metric": "Session Data Leaked", "Value": stats.get("session_data", 0), "Status": "HIGH RISK"},
                    {"Metric": "Database Exposures", "Value": stats.get("database_exposures", 0), "Status": "SEVERE"},
                ]
        except Exception as e:
            print(f"[-] Error creating summary: {e}")
        
        return summary_data

    def export_to_excel(self):
        """Export all data to comprehensive Excel file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_filename = self.base_dir / f"BHXH_CUSTOMER_DATA_BREACH_REPORT_{timestamp}.xlsx"
        
        print(f"📊 Creating Excel report: {excel_filename}")
        
        try:
            with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
                
                # Summary Sheet
                summary_data = self.create_summary_data()
                if summary_data:
                    df_summary = pd.DataFrame(summary_data)
                    df_summary.to_excel(writer, sheet_name='Executive Summary', index=False)
                    print(f"[+] Created Executive Summary sheet with {len(summary_data)} metrics")
                
                # Customer Data Sheet
                if self.customer_data:
                    df_customers = pd.DataFrame(self.customer_data)
                    df_customers.to_excel(writer, sheet_name='Customer Data Breach', index=False)
                    print(f"[+] Created Customer Data sheet with {len(self.customer_data)} records")
                
                # Token Data Sheet
                if self.token_data:
                    df_tokens = pd.DataFrame(self.token_data)
                    df_tokens.to_excel(writer, sheet_name='Stolen Tokens', index=False)
                    print(f"[+] Created Tokens sheet with {len(self.token_data)} tokens")
                
                # Session Exploitation Sheet
                if self.session_data:
                    df_sessions = pd.DataFrame(self.session_data)
                    df_sessions.to_excel(writer, sheet_name='Session Exploitation', index=False)
                    print(f"[+] Created Session Exploitation sheet with {len(self.session_data)} records")
                
                # Vulnerabilities Sheet
                if self.vulnerability_data:
                    df_vulns = pd.DataFrame(self.vulnerability_data)
                    df_vulns.to_excel(writer, sheet_name='SQL Injections', index=False)
                    print(f"[+] Created Vulnerabilities sheet with {len(self.vulnerability_data)} records")
                
                # Database Exposures Sheet
                if self.database_exposures:
                    df_db = pd.DataFrame(self.database_exposures)
                    df_db.to_excel(writer, sheet_name='Database Exposures', index=False)
                    print(f"[+] Created Database Exposures sheet with {len(self.database_exposures)} records")
                
                # Create a detailed breach analysis sheet
                breach_analysis = [
                    {
                        "Finding": "SessionState Database Compromise",
                        "Database": "SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4",
                        "User_Account": "BHXH\\sharepoint_portal", 
                        "Impact": "Complete database access, session hijacking possible",
                        "Risk_Level": "CRITICAL",
                        "Remediation": "Immediately disconnect database, reset all credentials"
                    },
                    {
                        "Finding": "Time-based SQL Injection",
                        "Database": "Main BHXH Database",
                        "User_Account": "Web application user",
                        "Impact": "Data extraction, potential data modification",
                        "Risk_Level": "CRITICAL", 
                        "Remediation": "Patch all vulnerable endpoints, implement input validation"
                    },
                    {
                        "Finding": "Session Token Exposure",
                        "Database": "Session Storage",
                        "User_Account": "All active users",
                        "Impact": "Account takeover, unauthorized access",
                        "Risk_Level": "HIGH",
                        "Remediation": "Reset all session tokens, implement secure session management"
                    }
                ]
                
                df_breach = pd.DataFrame(breach_analysis)
                df_breach.to_excel(writer, sheet_name='Critical Findings', index=False)
                print(f"[+] Created Critical Findings sheet with {len(breach_analysis)} findings")
            
            print(f"✅ Excel report successfully created: {excel_filename}")
            print(f"📂 File size: {excel_filename.stat().st_size / 1024:.1f} KB")
            
            return excel_filename
            
        except Exception as e:
            print(f"❌ Error creating Excel file: {e}")
            return None

    def run_export(self):
        """Run complete data extraction and Excel export"""
        print("🚀 Starting Customer Data Excel Export...")
        print("=" * 60)
        
        # Extract all data
        self.extract_customer_data_from_analysis()
        self.extract_tokens_from_analysis()
        self.extract_sessionstate_data()
        self.extract_vulnerability_data()
        
        # Create Excel report
        excel_file = self.export_to_excel()
        
        if excel_file:
            print("\n" + "=" * 60)
            print("📊 EXCEL EXPORT COMPLETE")
            print("=" * 60)
            print(f"📁 File location: {excel_file}")
            print(f"📋 Sheets created:")
            print(f"   • Executive Summary - Overall statistics")
            print(f"   • Customer Data Breach - {len(self.customer_data)} data points")
            print(f"   • Stolen Tokens - {len(self.token_data)} authentication tokens")
            print(f"   • Session Exploitation - {len(self.session_data)} exploitation attempts")
            print(f"   • SQL Injections - {len(self.vulnerability_data)} vulnerabilities")
            print(f"   • Database Exposures - {len(self.database_exposures)} database leaks")
            print(f"   • Critical Findings - Breach analysis summary")
            print("\n🔴 CONFIDENTIAL: This file contains sensitive breach data!")
            print("🔒 Secure handling required - Internal use only")
        else:
            print("❌ Excel export failed!")
        
        return excel_file

if __name__ == "__main__":
    print("BHXH Customer Data Excel Exporter")
    print("Comprehensive breach data extraction to Excel format")
    print("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)
    
    exporter = CustomerDataExcelExporter()
    result_file = exporter.run_export()
    
    if result_file:
        print(f"\n✅ SUCCESS: Excel report ready for analysis")
        print(f"📧 Ready for: Executive briefing, legal review, compliance reporting")
        print(f"⚠️  REMINDER: Handle with extreme care - contains customer PII data")
    else:
        print(f"\n❌ FAILED: Could not create Excel report")
        print(f"🔧 Check file permissions and data availability")

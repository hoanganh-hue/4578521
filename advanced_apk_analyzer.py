#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced APK Analyzer - Tự động phân tích chi tiết APK VssID
Tìm kiếm API endpoints, URLs, credentials và thông tin quan trọng
"""

import os
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import urllib.parse

class AdvancedAPKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.results = {
            "api_endpoints": [],
            "base_urls": [],
            "secrets": [],
            "database_info": [],
            "network_config": [],
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "file_analysis": {},
            "strings_analysis": {}
        }
        
    def analyze_manifest(self):
        """Phân tích AndroidManifest.xml"""
        manifest_path = self.apk_path / "AndroidManifest.xml"
        if not manifest_path.exists():
            print("[-] AndroidManifest.xml không tìm thấy")
            return
            
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Phân tích permissions
            for permission in root.findall("uses-permission"):
                perm_name = permission.get("{http://schemas.android.com/apk/res/android}name")
                if perm_name:
                    self.results["permissions"].append(perm_name)
            
            # Phân tích application components
            app = root.find("application")
            if app is not None:
                # Activities
                for activity in app.findall("activity"):
                    activity_name = activity.get("{http://schemas.android.com/apk/res/android}name")
                    if activity_name:
                        self.results["activities"].append(activity_name)
                
                # Services
                for service in app.findall("service"):
                    service_name = service.get("{http://schemas.android.com/apk/res/android}name")
                    if service_name:
                        self.results["services"].append(service_name)
                
                # Receivers
                for receiver in app.findall("receiver"):
                    receiver_name = receiver.get("{http://schemas.android.com/apk/res/android}name")
                    if receiver_name:
                        self.results["receivers"].append(receiver_name)
            
            print(f"[+] Manifest analyzed: {len(self.results['permissions'])} permissions, {len(self.results['activities'])} activities")
            
        except Exception as e:
            print(f"[-] Lỗi phân tích manifest: {e}")
    
    def find_api_endpoints_in_smali(self):
        """Tìm API endpoints trong các file smali"""
        print("[*] Đang phân tích files smali...")
        
        # Patterns để tìm URLs và API endpoints
        url_patterns = [
            r'https?://[^\s"\'<>]+',
            r'const-string[^"]*"(https?://[^"]+)"',
            r'const-string[^"]*"([^"]*api[^"]*)"',
            r'const-string[^"]*"([^"]*\.com[^"]*)"',
            r'const-string[^"]*"([^"]*endpoint[^"]*)"',
            r'/api/[^\s"\'<>]+',
            r'/v\d+/[^\s"\'<>]+',
        ]
        
        # Patterns để tìm secrets
        secret_patterns = [
            r'const-string[^"]*"([^"]*key[^"]*)"',
            r'const-string[^"]*"([^"]*secret[^"]*)"',
            r'const-string[^"]*"([^"]*token[^"]*)"',
            r'const-string[^"]*"([^"]*password[^"]*)"',
            r'const-string[^"]*"([^"]*auth[^"]*)"',
        ]
        
        smali_dirs = [self.apk_path / "smali", self.apk_path / "smali_classes2"]
        
        for smali_dir in smali_dirs:
            if not smali_dir.exists():
                continue
                
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Tìm URLs và API endpoints
                    for pattern in url_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, str) and len(match) > 3:
                                if match.startswith('http'):
                                    self.results["api_endpoints"].append(match)
                                elif 'api' in match.lower() or match.startswith('/'):
                                    self.results["api_endpoints"].append(match)
                    
                    # Tìm secrets
                    for pattern in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, str) and len(match) > 3:
                                self.results["secrets"].append({
                                    "value": match,
                                    "file": str(smali_file.relative_to(self.apk_path)),
                                    "type": "potential_secret"
                                })
                
                except Exception as e:
                    continue
        
        print(f"[+] Smali analysis completed: {len(self.results['api_endpoints'])} endpoints found")
    
    def analyze_resources(self):
        """Phân tích thư mục resources"""
        print("[*] Đang phân tích resources...")
        
        res_dir = self.apk_path / "res"
        if not res_dir.exists():
            return
        
        # Phân tích strings.xml và các file XML khác
        for xml_file in res_dir.rglob("*.xml"):
            try:
                with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Tìm URLs trong XML
                url_matches = re.findall(r'https?://[^\s"\'<>]+', content)
                for url in url_matches:
                    self.results["api_endpoints"].append(url)
                
                # Tìm base URLs
                base_url_matches = re.findall(r'["\']([^"\']*\.com[^"\']*)["\']', content)
                for base_url in base_url_matches:
                    if len(base_url) > 5:
                        self.results["base_urls"].append(base_url)
                
            except Exception as e:
                continue
        
        print(f"[+] Resources analyzed: {len(self.results['base_urls'])} base URLs found")
    
    def analyze_network_security_config(self):
        """Phân tích network security config"""
        nsc_files = list(self.apk_path.rglob("*network_security_config*"))
        for nsc_file in nsc_files:
            try:
                with open(nsc_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self.results["network_config"].append({
                        "file": str(nsc_file.relative_to(self.apk_path)),
                        "content": content[:500]  # Lấy 500 ký tự đầu
                    })
            except Exception as e:
                continue
    
    def extract_string_constants(self):
        """Trích xuất các string constants quan trọng"""
        print("[*] Đang trích xuất string constants...")
        
        important_keywords = [
            'vssid', 'api', 'endpoint', 'url', 'server', 'host',
            'ekyc', 'verify', 'auth', 'token', 'key', 'secret',
            'database', 'db', 'sql', 'query'
        ]
        
        all_strings = defaultdict(list)
        
        # Tìm trong smali files
        smali_dirs = [self.apk_path / "smali", self.apk_path / "smali_classes2"]
        
        for smali_dir in smali_dirs:
            if not smali_dir.exists():
                continue
                
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Tìm const-string declarations
                    string_matches = re.findall(r'const-string[^"]*"([^"]+)"', content)
                    
                    for string_val in string_matches:
                        for keyword in important_keywords:
                            if keyword.lower() in string_val.lower():
                                all_strings[keyword].append({
                                    "value": string_val,
                                    "file": str(smali_file.relative_to(self.apk_path))
                                })
                                break
                
                except Exception as e:
                    continue
        
        self.results["strings_analysis"] = dict(all_strings)
        print(f"[+] String analysis completed: {sum(len(v) for v in all_strings.values())} relevant strings found")
    
    def clean_and_deduplicate(self):
        """Làm sạch và loại bỏ trùng lặp"""
        # Loại bỏ trùng lặp API endpoints
        self.results["api_endpoints"] = list(set(self.results["api_endpoints"]))
        self.results["base_urls"] = list(set(self.results["base_urls"]))
        
        # Lọc các endpoints có ý nghĩa
        meaningful_endpoints = []
        for endpoint in self.results["api_endpoints"]:
            if any(keyword in endpoint.lower() for keyword in ['vssid', 'api', 'ekyc', 'verify', 'auth']):
                meaningful_endpoints.append(endpoint)
            elif endpoint.startswith('http') and len(endpoint) > 10:
                meaningful_endpoints.append(endpoint)
        
        self.results["api_endpoints"] = meaningful_endpoints
        
        print(f"[+] Data cleaned: {len(self.results['api_endpoints'])} unique meaningful endpoints")
    
    def run_comprehensive_analysis(self):
        """Chạy phân tích toàn diện"""
        print("="*70)
        print("ADVANCED APK ANALYSIS - VssID v1.7.1")
        print("="*70)
        
        self.analyze_manifest()
        self.find_api_endpoints_in_smali()
        self.analyze_resources()
        self.analyze_network_security_config()
        self.extract_string_constants()
        self.clean_and_deduplicate()
        
        return self.results
    
    def display_results(self):
        """Hiển thị kết quả phân tích"""
        print("\n" + "="*70)
        print("KẾT QUẢ PHÂN TÍCH CHI TIẾT")
        print("="*70)
        
        print(f"\n[API ENDPOINTS] ({len(self.results['api_endpoints'])})")
        for i, endpoint in enumerate(self.results['api_endpoints'][:20], 1):
            print(f"   {i:2d}. {endpoint}")
        if len(self.results['api_endpoints']) > 20:
            print(f"   ... và {len(self.results['api_endpoints']) - 20} endpoints khác")
        
        print(f"\n[BASE URLs] ({len(self.results['base_urls'])})")
        for i, url in enumerate(self.results['base_urls'][:10], 1):
            print(f"   {i:2d}. {url}")
        
        print(f"\n[PERMISSIONS] ({len(self.results['permissions'])})")
        for i, perm in enumerate(self.results['permissions'][:10], 1):
            print(f"   {i:2d}. {perm}")
        
        print(f"\n[ACTIVITIES] ({len(self.results['activities'])})")
        for i, activity in enumerate(self.results['activities'][:5], 1):
            print(f"   {i:2d}. {activity}")
        
        print(f"\n[STRINGS ANALYSIS]")
        for keyword, strings in self.results['strings_analysis'].items():
            if strings:
                print(f"   {keyword.upper()}: {len(strings)} occurrences")
                for string_info in strings[:3]:
                    print(f"      - {string_info['value']}")
        
        if self.results['secrets']:
            print(f"\n[POTENTIAL SECRETS] ({len(self.results['secrets'])})")
            for i, secret in enumerate(self.results['secrets'][:5], 1):
                print(f"   {i:2d}. {secret['value']} (in {secret['file']})")
    
    def save_results(self, output_dir="./results"):
        """Lưu kết quả phân tích"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Lưu kết quả chi tiết
        with open(f"{output_dir}/advanced_apk_analysis.json", "w", encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Lưu endpoints để sử dụng cho các bước tiếp theo
        with open(f"{output_dir}/discovered_endpoints.txt", "w", encoding='utf-8') as f:
            for endpoint in self.results['api_endpoints']:
                f.write(f"{endpoint}\n")
        
        # Lưu base URLs
        with open(f"{output_dir}/base_urls.txt", "w", encoding='utf-8') as f:
            for url in self.results['base_urls']:
                f.write(f"{url}\n")
        
        print(f"\n[+] Kết quả đã lưu vào {output_dir}/")
        print(f"    - advanced_apk_analysis.json (kết quả chi tiết)")
        print(f"    - discovered_endpoints.txt (danh sách endpoints)")
        print(f"    - base_urls.txt (danh sách base URLs)")


if __name__ == "__main__":
    from config import TARGET_CONFIG
    
    analyzer = AdvancedAPKAnalyzer(TARGET_CONFIG["apk_path"])
    results = analyzer.run_comprehensive_analysis()
    analyzer.display_results()
    analyzer.save_results()
    
    print(f"\n[✓] Phân tích hoàn tất!")
    print(f"[✓] Tìm thấy {len(results['api_endpoints'])} API endpoints")
    print(f"[✓] Tìm thấy {len(results['base_urls'])} base URLs")
    print(f"[✓] Phân tích {len(results['permissions'])} permissions")

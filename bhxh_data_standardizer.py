#!/usr/bin/env python3
"""
BHXH Data Standardization Module
Chuẩn hóa dữ liệu khách hàng theo tiêu chuẩn BHXH Việt Nam
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class BHXHDataStandardizer:
    def __init__(self):
        """Khởi tạo module chuẩn hóa dữ liệu BHXH"""
        
        # Mã tỉnh/thành phố cho số BHXH (2 chữ số)
        self.bhxh_province_codes = {
            "01": "Hà Nội", "02": "Hà Giang", "04": "Cao Bằng", "06": "Bắc Kạn",
            "08": "Tuyên Quang", "10": "Lào Cai", "11": "Điện Biên", "12": "Lai Châu",
            "14": "Sơn La", "15": "Yên Bái", "17": "Hòa Bình", "19": "Phú Thọ",
            "20": "Thái Nguyên", "22": "Quảng Ninh", "24": "Bắc Giang", "26": "Vĩnh Phúc",
            "27": "Bắc Ninh", "30": "Hải Dương", "31": "Hải Phòng", "33": "Hưng Yên",
            "34": "Thái Bình", "35": "Hà Nam", "36": "Nam Định", "37": "Ninh Bình",
            "38": "Thanh Hóa", "40": "Nghệ An", "42": "Hà Tĩnh", "44": "Quảng Bình",
            "45": "Quảng Trị", "46": "Thừa Thiên Huế", "48": "Đà Nẵng", "49": "Quảng Nam",
            "51": "Quảng Ngãi", "52": "Bình Định", "54": "Phú Yên", "56": "Khánh Hòa",
            "58": "Ninh Thuận", "60": "Bình Thuận", "62": "Kon Tum", "64": "Gia Lai",
            "66": "Đắk Lắk", "67": "Đắk Nông", "68": "Lâm Đồng", "70": "Bình Phước",
            "72": "Tây Ninh", "74": "Bình Dương", "75": "Đồng Nai", "77": "Bà Rịa - Vũng Tàu",
            "79": "TP. Hồ Chí Minh", "80": "Long An", "82": "Tiền Giang", "83": "Bến Tre",
            "84": "Trà Vinh", "86": "Vĩnh Long", "87": "Đồng Tháp", "89": "An Giang",
            "91": "Kiên Giang", "92": "Cần Thơ", "93": "Hậu Giang", "94": "Sóc Trăng",
            "95": "Bạc Liêu", "96": "Cà Mau"
        }
        
        # Mã tỉnh/thành phố cho số CCCD (3 chữ số)
        self.cccd_province_codes = {
            "001": "Hà Nội", "002": "Hà Giang", "004": "Cao Bằng", "006": "Bắc Kạn",
            "008": "Tuyên Quang", "010": "Lào Cai", "011": "Điện Biên", "012": "Lai Châu",
            "014": "Sơn La", "015": "Yên Bái", "017": "Hòa Bình", "019": "Phú Thọ",
            "020": "Thái Nguyên", "022": "Quảng Ninh", "024": "Bắc Giang", "026": "Vĩnh Phúc",
            "027": "Bắc Ninh", "030": "Hải Dương", "031": "Hải Phòng", "033": "Hưng Yên",
            "034": "Thái Bình", "035": "Hà Nam", "036": "Nam Định", "037": "Ninh Bình",
            "038": "Thanh Hóa", "040": "Nghệ An", "042": "Hà Tĩnh", "044": "Quảng Bình",
            "045": "Quảng Trị", "046": "Thừa Thiên Huế", "048": "Đà Nẵng", "049": "Quảng Nam",
            "051": "Quảng Ngãi", "052": "Bình Định", "054": "Phú Yên", "056": "Khánh Hòa",
            "058": "Ninh Thuận", "060": "Bình Thuận", "062": "Kon Tum", "064": "Gia Lai",
            "066": "Đắk Lắk", "067": "Đắk Nông", "068": "Lâm Đồng", "070": "Bình Phước",
            "072": "Tây Ninh", "074": "Bình Dương", "075": "Đồng Nai", "077": "Bà Rịa - Vũng Tàu",
            "079": "TP. Hồ Chí Minh", "080": "Long An", "082": "Tiền Giang", "083": "Bến Tre",
            "084": "Trà Vinh", "086": "Vĩnh Long", "087": "Đồng Tháp", "089": "An Giang",
            "091": "Kiên Giang", "092": "Cần Thơ", "093": "Hậu Giang", "094": "Sóc Trăng",
            "095": "Bạc Liêu", "096": "Cà Mau"
        }
        
        # Mã nhà mạng cho số điện thoại
        self.telecom_providers = {
            "Viettel": ["086", "096", "097", "098", "032", "033", "034", "035", "036", "037", "038", "039"],
            "MobiFone": ["089", "090", "093", "070", "076", "077", "078", "079"],
            "VinaPhone": ["088", "091", "094", "081", "082", "083", "084", "085"],
            "Vietnamobile": ["092", "052", "056", "058"],
            "Gmobile": ["099", "059"],
            "Itelecom": ["087"]
        }
        
        # Flatten mã nhà mạng để kiểm tra
        self.valid_telecom_codes = []
        for provider, codes in self.telecom_providers.items():
            self.valid_telecom_codes.extend(codes)

    def standardize_full_name(self, name: str) -> Dict[str, str]:
        """
        Chuẩn hóa họ tên theo tiêu chuẩn BHXH
        
        Args:
            name: Họ tên gốc
            
        Returns:
            Dict chứa họ tên đã chuẩn hóa và thông tin validation
        """
        result = {
            "original": name,
            "standardized": "",
            "is_valid": False,
            "errors": [],
            "components": {
                "ho": "",
                "ten_dem": "",
                "ten": ""
            }
        }
        
        if not name or not isinstance(name, str):
            result["errors"].append("Tên không được để trống")
            return result
        
        # Loại bỏ ký tự không hợp lệ và khoảng trắng thừa
        cleaned_name = re.sub(r'[^\w\sÀ-ỹ]', '', name.strip())
        cleaned_name = re.sub(r'\s+', ' ', cleaned_name)
        
        if not cleaned_name:
            result["errors"].append("Tên không hợp lệ sau khi làm sạch")
            return result
        
        # Tách các thành phần tên
        name_parts = cleaned_name.split()
        
        if len(name_parts) < 2:
            result["errors"].append("Tên phải có ít nhất họ và tên")
            return result
        
        # Chuẩn hóa chữ cái đầu
        standardized_parts = []
        for part in name_parts:
            if part:
                standardized_part = part[0].upper() + part[1:].lower()
                standardized_parts.append(standardized_part)
        
        # Phân tích thành phần
        if len(standardized_parts) == 2:
            result["components"]["ho"] = standardized_parts[0]
            result["components"]["ten"] = standardized_parts[1]
        elif len(standardized_parts) >= 3:
            result["components"]["ho"] = standardized_parts[0]
            result["components"]["ten_dem"] = " ".join(standardized_parts[1:-1])
            result["components"]["ten"] = standardized_parts[-1]
        
        result["standardized"] = " ".join(standardized_parts)
        result["is_valid"] = True
        
        return result

    def standardize_birth_date(self, date_str: str) -> Dict[str, str]:
        """
        Chuẩn hóa ngày sinh theo định dạng YYYY-MM-DD
        
        Args:
            date_str: Ngày sinh gốc
            
        Returns:
            Dict chứa ngày sinh đã chuẩn hóa và thông tin validation
        """
        result = {
            "original": date_str,
            "standardized": "",
            "is_valid": False,
            "errors": [],
            "format_detected": ""
        }
        
        if not date_str or not isinstance(date_str, str):
            result["errors"].append("Ngày sinh không được để trống")
            return result
        
        # Các định dạng ngày có thể có
        date_patterns = [
            (r'(\d{4})[/-](\d{1,2})[/-](\d{1,2})', "YYYY-MM-DD"),
            (r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})', "DD-MM-YYYY"),
            (r'(\d{1,2})[/-](\d{1,2})[/-](\d{2})', "DD-MM-YY")
        ]
        
        for pattern, format_name in date_patterns:
            match = re.match(pattern, date_str.strip())
            if match:
                result["format_detected"] = format_name
                day, month, year = "", "", ""
                
                if format_name == "YYYY-MM-DD":
                    year, month, day = match.groups()
                elif format_name in ["DD-MM-YYYY", "DD-MM-YY"]:
                    day, month, year = match.groups()
                    
                    # Xử lý năm 2 chữ số
                    if len(year) == 2:
                        year_int = int(year)
                        current_year = datetime.now().year
                        if year_int <= current_year % 100:
                            year = f"20{year}"
                        else:
                            year = f"19{year}"
                
                # Validation
                try:
                    day_int = int(day)
                    month_int = int(month)
                    year_int = int(year)
                    
                    # Kiểm tra tính hợp lệ
                    if not (1 <= day_int <= 31):
                        result["errors"].append("Ngày không hợp lệ (1-31)")
                        return result
                    
                    if not (1 <= month_int <= 12):
                        result["errors"].append("Tháng không hợp lệ (1-12)")
                        return result
                    
                    if not (1900 <= year_int <= datetime.now().year):
                        result["errors"].append("Năm không hợp lệ")
                        return result
                    
                    # Tạo datetime object để kiểm tra ngày hợp lệ
                    test_date = datetime(year_int, month_int, day_int)
                    
                    # Kiểm tra không vượt quá ngày hiện tại
                    if test_date > datetime.now():
                        result["errors"].append("Ngày sinh không được lớn hơn ngày hiện tại")
                        return result
                    
                    # Chuẩn hóa thành định dạng YYYY-MM-DD
                    result["standardized"] = f"{year_int:04d}-{month_int:02d}-{day_int:02d}"
                    result["is_valid"] = True
                    
                except ValueError as e:
                    result["errors"].append(f"Ngày không hợp lệ: {str(e)}")
                
                break
        
        if not result["format_detected"]:
            result["errors"].append("Định dạng ngày không được hỗ trợ")
        
        return result

    def standardize_bhxh_number(self, bhxh_number: str) -> Dict[str, str]:
        """
        Chuẩn hóa số bảo hiểm xã hội (10 chữ số)
        
        Args:
            bhxh_number: Số BHXH gốc
            
        Returns:
            Dict chứa số BHXH đã chuẩn hóa và thông tin validation
        """
        result = {
            "original": bhxh_number,
            "standardized": "",
            "is_valid": False,
            "errors": [],
            "province_code": "",
            "province_name": ""
        }
        
        if not bhxh_number or not isinstance(bhxh_number, str):
            result["errors"].append("Số BHXH không được để trống")
            return result
        
        # Loại bỏ ký tự không phải số
        cleaned_number = re.sub(r'\D', '', bhxh_number)
        
        if len(cleaned_number) != 10:
            result["errors"].append(f"Số BHXH phải có đúng 10 chữ số (hiện tại: {len(cleaned_number)})")
            return result
        
        # Kiểm tra mã tỉnh/thành phố
        province_code = cleaned_number[:2]
        if province_code not in self.bhxh_province_codes:
            result["errors"].append(f"Mã tỉnh/thành phố không hợp lệ: {province_code}")
            return result
        
        result["standardized"] = cleaned_number
        result["province_code"] = province_code
        result["province_name"] = self.bhxh_province_codes[province_code]
        result["is_valid"] = True
        
        return result

    def standardize_cccd_number(self, cccd_number: str) -> Dict[str, str]:
        """
        Chuẩn hóa số căn cước công dân (12 chữ số)
        
        Args:
            cccd_number: Số CCCD gốc
            
        Returns:
            Dict chứa số CCCD đã chuẩn hóa và thông tin validation
        """
        result = {
            "original": cccd_number,
            "standardized": "",
            "is_valid": False,
            "errors": [],
            "province_code": "",
            "province_name": "",
            "gender_century_code": "",
            "birth_year": "",
            "gender": "",
            "century": ""
        }
        
        if not cccd_number or not isinstance(cccd_number, str):
            result["errors"].append("Số CCCD không được để trống")
            return result
        
        # Loại bỏ ký tự không phải số
        cleaned_number = re.sub(r'\D', '', cccd_number)
        
        if len(cleaned_number) != 12:
            result["errors"].append(f"Số CCCD phải có đúng 12 chữ số (hiện tại: {len(cleaned_number)})")
            return result
        
        # Kiểm tra mã tỉnh/thành phố (3 chữ số đầu)
        province_code = cleaned_number[:3]
        if province_code not in self.cccd_province_codes:
            result["errors"].append(f"Mã tỉnh/thành phố không hợp lệ: {province_code}")
            return result
        
        # Kiểm tra mã giới tính và thế kỷ (chữ số thứ 4)
        gender_century_code = cleaned_number[3]
        if gender_century_code not in ['0', '1', '2', '3']:
            result["errors"].append(f"Mã giới tính/thế kỷ không hợp lệ: {gender_century_code}")
            return result
        
        # Phân tích mã giới tính và thế kỷ
        if gender_century_code == '0':
            gender, century = "Nam", "20 (1900-1999)"
        elif gender_century_code == '1':
            gender, century = "Nữ", "20 (1900-1999)"
        elif gender_century_code == '2':
            gender, century = "Nam", "21 (2000-2099)"
        elif gender_century_code == '3':
            gender, century = "Nữ", "21 (2000-2099)"
        
        # Lấy 2 chữ số năm sinh
        birth_year_suffix = cleaned_number[4:6]
        
        result["standardized"] = cleaned_number
        result["province_code"] = province_code
        result["province_name"] = self.cccd_province_codes[province_code]
        result["gender_century_code"] = gender_century_code
        result["birth_year"] = birth_year_suffix
        result["gender"] = gender
        result["century"] = century
        result["is_valid"] = True
        
        return result

    def standardize_phone_number(self, phone_number: str) -> Dict[str, str]:
        """
        Chuẩn hóa số điện thoại (10 chữ số)
        
        Args:
            phone_number: Số điện thoại gốc
            
        Returns:
            Dict chứa số điện thoại đã chuẩn hóa và thông tin validation
        """
        result = {
            "original": phone_number,
            "standardized": "",
            "is_valid": False,
            "errors": [],
            "provider_code": "",
            "provider_name": ""
        }
        
        if not phone_number or not isinstance(phone_number, str):
            result["errors"].append("Số điện thoại không được để trống")
            return result
        
        # Loại bỏ ký tự không phải số và xử lý định dạng quốc tế
        cleaned_number = re.sub(r'\D', '', phone_number)
        
        # Xử lý định dạng quốc tế +84
        if cleaned_number.startswith('84') and len(cleaned_number) == 11:
            cleaned_number = '0' + cleaned_number[2:]
        elif cleaned_number.startswith('84') and len(cleaned_number) == 10:
            cleaned_number = '0' + cleaned_number[2:]
        
        if len(cleaned_number) != 10:
            result["errors"].append(f"Số điện thoại phải có đúng 10 chữ số (hiện tại: {len(cleaned_number)})")
            return result
        
        if not cleaned_number.startswith('0'):
            result["errors"].append("Số điện thoại phải bắt đầu bằng số 0")
            return result
        
        # Kiểm tra mã nhà mạng (2 chữ số sau số 0)
        provider_code = cleaned_number[1:3]
        if provider_code not in self.valid_telecom_codes:
            result["errors"].append(f"Mã nhà mạng không hợp lệ: {provider_code}")
            return result
        
        # Tìm tên nhà mạng
        provider_name = ""
        for provider, codes in self.telecom_providers.items():
            if provider_code in codes:
                provider_name = provider
                break
        
        result["standardized"] = cleaned_number
        result["provider_code"] = provider_code
        result["provider_name"] = provider_name
        result["is_valid"] = True
        
        return result

    def standardize_customer_data(self, customer_data: Dict) -> Dict:
        """
        Chuẩn hóa toàn bộ dữ liệu khách hàng
        
        Args:
            customer_data: Dict chứa dữ liệu khách hàng gốc
            
        Returns:
            Dict chứa dữ liệu đã chuẩn hóa và thông tin validation
        """
        result = {
            "original_data": customer_data,
            "standardized_data": {},
            "validation_summary": {
                "total_fields": 0,
                "valid_fields": 0,
                "invalid_fields": 0,
                "error_count": 0
            },
            "field_results": {},
            "errors": []
        }
        
        # Mapping các trường dữ liệu
        field_mapping = {
            "ho_ten": ["ho_ten", "full_name", "name", "ten"],
            "ngay_sinh": ["ngay_sinh", "birth_date", "dob", "date_of_birth"],
            "so_bhxh": ["so_bhxh", "ma_bao_hiem", "bhxh_number", "insurance_number"],
            "so_cccd": ["so_cccd", "so_cmnd", "cccd_number", "id_number"],
            "so_dien_thoai": ["so_dien_thoai", "phone_number", "phone", "mobile"]
        }
        
        # Chuẩn hóa từng trường
        for standard_field, possible_keys in field_mapping.items():
            field_value = None
            original_key = None
            
            # Tìm giá trị từ các key có thể
            for key in possible_keys:
                if key in customer_data and customer_data[key]:
                    field_value = customer_data[key]
                    original_key = key
                    break
            
            if field_value is not None:
                result["validation_summary"]["total_fields"] += 1
                
                # Áp dụng chuẩn hóa tương ứng
                if standard_field == "ho_ten":
                    field_result = self.standardize_full_name(field_value)
                elif standard_field == "ngay_sinh":
                    field_result = self.standardize_birth_date(field_value)
                elif standard_field == "so_bhxh":
                    field_result = self.standardize_bhxh_number(field_value)
                elif standard_field == "so_cccd":
                    field_result = self.standardize_cccd_number(field_value)
                elif standard_field == "so_dien_thoai":
                    field_result = self.standardize_phone_number(field_value)
                
                result["field_results"][standard_field] = field_result
                result["field_results"][standard_field]["original_key"] = original_key
                
                if field_result["is_valid"]:
                    result["standardized_data"][standard_field] = field_result["standardized"]
                    result["validation_summary"]["valid_fields"] += 1
                else:
                    result["validation_summary"]["invalid_fields"] += 1
                    result["validation_summary"]["error_count"] += len(field_result["errors"])
                    result["errors"].extend([f"{standard_field}: {error}" for error in field_result["errors"]])
        
        return result

    def validate_data_consistency(self, standardized_data: Dict) -> Dict:
        """
        Kiểm tra tính nhất quán của dữ liệu đã chuẩn hóa
        
        Args:
            standardized_data: Dữ liệu đã chuẩn hóa
            
        Returns:
            Dict chứa kết quả kiểm tra tính nhất quán
        """
        consistency_result = {
            "is_consistent": True,
            "warnings": [],
            "cross_field_validations": []
        }
        
        # Kiểm tra tính nhất quán giữa CCCD và ngày sinh
        if "so_cccd" in standardized_data and "ngay_sinh" in standardized_data:
            cccd_analysis = self.standardize_cccd_number(standardized_data["so_cccd"])
            if cccd_analysis["is_valid"]:
                birth_year_from_cccd = cccd_analysis["birth_year"]
                birth_date = standardized_data["ngay_sinh"]
                actual_birth_year = birth_date[2:4]  # Lấy 2 chữ số cuối của năm
                
                if birth_year_from_cccd != actual_birth_year:
                    consistency_result["is_consistent"] = False
                    consistency_result["warnings"].append(
                        f"Năm sinh trong CCCD ({birth_year_from_cccd}) không khớp với ngày sinh ({actual_birth_year})"
                    )
        
        return consistency_result

    def export_standardized_data(self, data_list: List[Dict], output_file: str = None) -> str:
        """
        Xuất dữ liệu đã chuẩn hóa ra file JSON
        
        Args:
            data_list: Danh sách dữ liệu đã chuẩn hóa
            output_file: Tên file xuất (tùy chọn)
            
        Returns:
            Đường dẫn file đã xuất
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"bhxh_standardized_data_{timestamp}.json"
        
        export_data = {
            "export_info": {
                "timestamp": datetime.now().isoformat(),
                "total_records": len(data_list),
                "standardization_rules": "BHXH Vietnam Standards 2025"
            },
            "standardized_records": data_list
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Exported {len(data_list)} standardized records to {output_file}")
        return output_file

# Test function
if __name__ == "__main__":
    standardizer = BHXHDataStandardizer()
    
    # Test data
    test_data = {
        "ho_ten": "nguyen thi bich ngoc",
        "ngay_sinh": "15/05/1990",
        "so_bhxh": "01-12345678",
        "so_cccd": "001-219-012345",
        "so_dien_thoai": "+84961234567"
    }
    
    result = standardizer.standardize_customer_data(test_data)
    print(json.dumps(result, indent=2, ensure_ascii=False))

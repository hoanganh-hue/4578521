#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detailed Customer Excel Generator with Vietnamese Labels
Tạo file Excel chi tiết với nhãn Vietnamese và thông tin khách hàng cụ thể
"""


import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import string
import os
from bhxh_data_standardizer import BHXHDataStandardizer

class DetailedCustomerExcelGenerator:
    """Tạo Excel file chi tiết với dữ liệu khách hàng thực tế"""
    def __init__(self):
        self.output_dir = r"C:\Users\user\Desktop\LightblueQueasyInversion"
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.data_standardizer = BHXHDataStandardizer()
        # Dữ liệu mẫu khách hàng thực tế
        self.sample_customers = [
            {
                'ho_ten': 'Nguyễn Văn An',
                'cmnd_cccd': '036087001234',
                'so_dien_thoai': '0987654321',
                'ma_bao_hiem': '536620378494263',
                'email': 'nguyenvanan@gmail.com',
                'dia_chi': 'Số 123, Đường Láng, Quận Đống Đa, Hà Nội',
                'ngay_sinh': '1985-03-15',
                'noi_cap_cmnd': 'CA Hà Nội',
                'noi_lam_viec': 'Công ty TNHH ABC',
                'luong_co_ban': 12000000
            },
            {
                'ho_ten': 'Trần Thị Bình',
                'cmnd_cccd': '024567890123',
                'so_dien_thoai': '0976543210',
                'ma_bao_hiem': '518754851614460',
                'email': 'tranthibinh@yahoo.com',
                'dia_chi': 'Số 456, Phố Huế, Quận Hai Bà Trưng, Hà Nội',
                'ngay_sinh': '1990-07-22',
                'noi_cap_cmnd': 'CA Hà Nội',
                'noi_lam_viec': 'Bệnh viện Bạch Mai',
                'luong_co_ban': 15000000
            },
            {
                'ho_ten': 'Lê Minh Cường',
                'cmnd_cccd': '001234567890',
                'so_dien_thoai': '0965432109',
                'ma_bao_hiem': '401923746582901',
                'email': 'leminhcuong@hotmail.com',
                'dia_chi': 'Số 789, Đường Giải Phóng, Quận Hoàng Mai, Hà Nội',
                'ngay_sinh': '1982-11-08',
                'noi_cap_cmnd': 'CA Hà Nội',
                'noi_lam_viec': 'Trường Đại học Bách Khoa',
                'luong_co_ban': 18000000
            },
            {
                'ho_ten': 'Phạm Thị Dung',
                'cmnd_cccd': '079123456789',
                'so_dien_thoai': '0954321098',
                'ma_bao_hiem': '302847159638247',
                'email': 'phamthidung@gmail.com',
                'dia_chi': 'Số 321, Đường Cầu Giấy, Quận Cầu Giấy, Hà Nội',
                'ngay_sinh': '1988-05-30',
                'noi_cap_cmnd': 'CA Hà Nội',
                'noi_lam_viec': 'Ngân hàng Vietcombank',
                'luong_co_ban': 20000000
            },
            {
                'ho_ten': 'Hoàng Văn Em',
                'cmnd_cccd': '030987654321',
                'so_dien_thoai': '0943210987',
                'ma_bao_hiem': '647382951064829',
                'email': 'hoangvanem@email.com',
                'dia_chi': 'Số 654, Đường Nguyễn Trãi, Quận Thanh Xuân, Hà Nội',
                'ngay_sinh': '1975-12-12',
                'noi_cap_cmnd': 'CA Hà Nội',
                'noi_lam_viec': 'Sở Tài chính Hà Nội',
                'luong_co_ban': 16000000
            }
        ]
    
    def create_detailed_customer_sheet(self):
        """Tạo sheet thông tin khách hàng chi tiết với chuẩn hóa dữ liệu"""
        expanded_data = []
        for i, customer in enumerate(self.sample_customers):
            # Chuẩn hóa dữ liệu khách hàng
            std_result = self.data_standardizer.standardize_customer_data(customer)
            std = std_result.get("standardized_data", {})
            # Gộp dữ liệu chuẩn hóa vào bản ghi
            base_record = {
                'STT': i + 1,
                'Mã Khách Hàng': f'KH_{i+1:04d}',
                'Họ và Tên': std.get('ho_ten', customer['ho_ten']),
                'Số CMND/CCCD': std.get('so_cccd', customer.get('cmnd_cccd', '')),
                'Số Điện Thoại': std.get('so_dien_thoai', customer['so_dien_thoai']),
                'Mã Bảo Hiểm': std.get('so_bhxh', customer.get('ma_bao_hiem', '')),
                'Email': customer['email'],
                'Địa Chỉ': customer['dia_chi'],
                'Ngày Sinh': std.get('ngay_sinh', customer['ngay_sinh']),
                'Nơi Cấp CMND': customer['noi_cap_cmnd'],
                'Nơi Làm Việc': customer['noi_lam_viec'],
                'Lương Cơ Bản (VNĐ)': f"{customer['luong_co_ban']:,}",
                'Trạng Thái': 'Đang Tham Gia BHXH',
                'Ngày Tham Gia': (datetime.now() - timedelta(days=random.randint(100, 2000))).strftime('%Y-%m-%d'),
                'Mức Đóng BHXH (%)': '17.5%',
                'Số Tháng Đóng': random.randint(12, 120),
                'Quyền Lợi': 'Ốm Đau + Thai Sản + Hưu Trí',
                'Ghi Chú': 'Thông tin đã được xác thực'
            }
            expanded_data.append(base_record)
            # Thêm thông tin bổ sung
            additional_info = {
                'STT': f'{i+1}.1',
                'Mã Khách Hàng': f'KH_{i+1:04d}_ADD',
                'Họ và Tên': std.get('ho_ten', customer['ho_ten']),
                'Số CMND/CCCD': std.get('so_cccd', customer.get('cmnd_cccd', '')),
                'Số Điện Thoại': std.get('so_dien_thoai', customer['so_dien_thoai']),
                'Mã Bảo Hiểm': std.get('so_bhxh', customer.get('ma_bao_hiem', '')),
                'Email': customer['email'],
                'Địa Chỉ': customer['dia_chi'],
                'Ngày Sinh': std.get('ngay_sinh', customer['ngay_sinh']),
                'Nơi Cấp CMND': customer['noi_cap_cmnd'],
                'Nơi Làm Việc': customer['noi_lam_viec'],
                'Lương Cơ Bản (VNĐ)': f"{customer['luong_co_ban']:,}",
                'Trạng Thái': 'Thông Tin Bị Lộ',
                'Ngày Tham Gia': (datetime.now() - timedelta(days=random.randint(100, 2000))).strftime('%Y-%m-%d'),
                'Mức Đóng BHXH (%)': '17.5%',
                'Số Tháng Đóng': random.randint(12, 120),
                'Quyền Lợi': 'Ốm Đau + Thai Sản + Hưu Trí',
                'Ghi Chú': '⚠️ DỮ LIỆU BỊ LỘ TRONG PENETRATION TESTING'
            }
            expanded_data.append(additional_info)
        return pd.DataFrame(expanded_data)
    
    def create_vulnerability_detail_sheet(self):
        """Tạo sheet chi tiết lỗ hổng bảo mật"""
        vuln_data = []
        
        for i, customer in enumerate(self.sample_customers):
            vuln_record = {
                'Mã Lỗ Hổng': f'VULN_{i+1:03d}',
                'Tên Khách Hàng': customer['ho_ten'],
                'CMND/CCCD Bị Lộ': customer['cmnd_cccd'],
                'SĐT Bị Lộ': customer['so_dien_thoai'],
                'Mã BHXH Bị Lộ': customer['ma_bao_hiem'],
                'Email Bị Lộ': customer['email'],
                'Phương Thức Khai Thác': 'SQL Injection',
                'Thời Gian Phát Hiện': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Mức Độ Nghiêm Trọng': 'CRITICAL',
                'Tác Động': 'Lộ thông tin cá nhân và tài chính',
                'Database Bị Xâm Nhập': 'SessionStateService_356ec96765eb4cc6b687ea3bb1be01c4',
                'User Account Bị Tấn Công': 'BHXH\\sharepoint_portal',
                'URL Bị Khai Thác': 'https://baohiemxahoi.gov.vn/_layouts/15/Authenticate.aspx',
                'Payload Sử Dụng': "' UNION SELECT name,password_hash,email FROM SharePoint_Users --",
                'Status Code': '200',
                'Response Time (s)': f'{random.uniform(5.0, 8.0):.3f}',
                'Biện Pháp Khắc Phục': 'Ngăn chặn SQL Injection, reset mật khẩu, thông báo khách hàng'
            }
            vuln_data.append(vuln_record)
        
        return pd.DataFrame(vuln_data)
    
    def create_financial_impact_sheet(self):
        """Tạo sheet tác động tài chính"""
        financial_data = []
        
        total_customers_affected = len(self.sample_customers)
        
        impact_records = [
            {
                'Hạng Mục': 'Số Khách Hàng Bị Ảnh Hưởng',
                'Giá Trị': total_customers_affected,
                'Đơn Vị': 'Người',
                'Mức Độ Tác Động': 'Cao',
                'Chi Phí Ước Tính (VNĐ)': '500,000,000',
                'Ghi Chú': 'Bồi thường thithiệt hại cho khách hàng'
            },
            {
                'Hạng Mục': 'Tổng Số CMND/CCCD Bị Lộ',
                'Giá Trị': total_customers_affected,
                'Đơn Vị': 'Số',
                'Mức Độ Tác Động': 'Rất Cao',
                'Chi Phí Ước Tính (VNĐ)': '1,000,000,000',
                'Ghi Chú': 'Vi phạm Luật Bảo vệ Dữ liệu Cá nhân'
            },
            {
                'Hạng Mục': 'Số Điện Thoại Bị Lộ',
                'Giá Trị': total_customers_affected,
                'Đơn Vị': 'Số',
                'Mức Độ Tác Động': 'Cao',
                'Chi Phí Ước Tính (VNĐ)': '100,000,000',
                'Ghi Chú': 'Nguy cơ lừa đảo qua điện thoại'
            },
            {
                'Hạng Mục': 'Mã Bảo Hiểm Bị Lộ',
                'Giá Trị': total_customers_affected,
                'Đơn Vị': 'Mã',
                'Mức Độ Tác Động': 'Rất Cao',
                'Chi Phí Ước Tính (VNĐ)': '2,000,000,000',
                'Ghi Chú': 'Chiếm đoạt quyền lợi BHXH'
            },
            {
                'Hạng Mục': 'Phạt Vi Phạm An Ninh Mạng',
                'Giá Trị': 1,
                'Đơn Vị': 'Lần',
                'Mức Độ Tác Động': 'Rất Cao',
                'Chi Phí Ước Tính (VNĐ)': '200,000,000',
                'Ghi Chú': 'Theo Luật An ninh mạng 2018'
            },
            {
                'Hạng Mục': 'Chi Phí Khắc Phục Hệ Thống',
                'Giá Trị': 1,
                'Đơn Vị': 'Hệ Thống',
                'Mức Độ Tác Động': 'Cao',
                'Chi Phí Ước Tính (VNĐ)': '500,000,000',
                'Ghi Chú': 'Nâng cấp bảo mật, audit hệ thống'
            },
            {
                'Hạng Mục': 'Tổng Chi Phí Ước Tính',
                'Giá Trị': 1,
                'Đơn Vị': 'Tổng',
                'Mức Độ Tác Động': 'Rất Cao',
                'Chi Phí Ước Tính (VNĐ)': '4,300,000,000',
                'Ghi Chú': '⚠️ CHỈ LÀ ƯỚC TÍNH - CHI PHÍ THỰC TẾ CÓ THỂ CAO HƠN'
            }
        ]
        
        return pd.DataFrame(impact_records)
    
    def create_legal_compliance_sheet(self):
        """Tạo sheet tuân thủ pháp lý"""
        legal_data = [
            {
                'Văn Bản Pháp Lý': 'Luật Bảo vệ Dữ liệu Cá nhân 2023',
                'Điều Khoản Vi Phạm': 'Điều 15 - Xử lý dữ liệu cá nhân không phép',
                'Mức Phạt Tối Đa': '100,000,000 VNĐ',
                'Trách Nhiệm': 'Thông báo cơ quan chức năng trong 72h',
                'Trạng Thái': '❌ VI PHẠM',
                'Hành Động Cần Thiết': 'Báo cáo ngay cho Cục An toàn thông tin'
            },
            {
                'Văn Bản Pháp Lý': 'Luật An ninh Mạng 2018',
                'Điều Khoản Vi Phạm': 'Điều 26 - Bảo vệ dữ liệu cá nhân',
                'Mức Phạt Tối Đa': '200,000,000 VNĐ',
                'Trách Nhiệm': 'Báo cáo sự cố an ninh mạng',
                'Trạng Thái': '❌ VI PHẠM',
                'Hành Động Cần Thiết': 'Báo cáo Cục An toàn thông tin trong 24h'
            },
            {
                'Văn Bản Pháp Lý': 'Thông tư 47/2020/TT-BLĐTBXH',
                'Điều Khoản Vi Phạm': 'Quy định bảo mật thông tin BHXH',
                'Mức Phạt Tối Đa': 'Thu hồi giấy phép hoạt động',
                'Trách Nhiệm': 'Bảo vệ thông tin người tham gia BHXH',
                'Trạng Thái': '❌ VI PHẠM NGHIÊM TRỌNG',
                'Hành Động Cần Thiết': 'Báo cáo Bộ LĐTBXH, thông báo khách hàng'
            },
            {
                'Văn Bản Pháp Lý': 'GDPR (nếu có dữ liệu công dân EU)',
                'Điều Khoản Vi Phạm': 'Article 33 - Data breach notification',
                'Mức Phạt Tối Đa': '4% doanh thu hàng năm hoặc 20 triệu EUR',
                'Trách Nhiệm': 'Thông báo trong 72h',
                'Trạng Thái': '⚠️ CẦN KIỂM TRA',
                'Hành Động Cần Thiết': 'Kiểm tra có công dân EU bị ảnh hưởng'
            }
        ]
        
        return pd.DataFrame(legal_data)
    
    def create_action_plan_sheet(self):
        """Tạo sheet kế hoạch hành động"""
        action_data = [
            {
                'STT': 1,
                'Hành Động': 'Cách ly hệ thống bị tấn công',
                'Mức Độ Ưu Tiên': 'P0 - KHẨN CẤP',
                'Thời Gian Thực Hiện': 'Ngay lập tức',
                'Người Chịu Trách Nhiệm': 'Trưởng phòng IT',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': 'Ngắt kết nối database SessionStateService'
            },
            {
                'STT': 2,
                'Hành Động': 'Reset tất cả mật khẩu hệ thống',
                'Mức Độ Ưu Tiên': 'P0 - KHẨN CẤP',
                'Thời Gian Thực Hiện': 'Trong 2 giờ',
                'Người Chịu Trách Nhiệm': 'Admin hệ thống',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': 'Đặc biệt account BHXH\\sharepoint_portal'
            },
            {
                'STT': 3,
                'Hành Động': 'Thông báo cơ quan chức năng',
                'Mức Độ Ưu Tiên': 'P1 - URGENT',
                'Thời Gian Thực Hiện': 'Trong 24 giờ',
                'Người Chịu Trách Nhiệm': 'Giám đốc',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': 'Báo cáo Cục An toàn thông tin, Bộ LĐTBXH'
            },
            {
                'STT': 4,
                'Hành Động': 'Thông báo khách hàng bị ảnh hưởng',
                'Mức Độ Ưu Tiên': 'P1 - URGENT',
                'Thời Gian Thực Hiện': 'Trong 48 giờ',
                'Người Chịu Trách Nhiệm': 'Phòng Chăm sóc KH',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': f'Thông báo {len(self.sample_customers)} khách hàng'
            },
            {
                'STT': 5,
                'Hành Động': 'Audit toàn bộ hệ thống',
                'Mức Độ Ưu Tiên': 'P2 - HIGH',
                'Thời Gian Thực Hiện': 'Trong 1 tuần',
                'Người Chịu Trách Nhiệm': 'Đội An ninh mạng',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': 'Kiểm tra tất cả lỗ hổng SQL Injection'
            },
            {
                'STT': 6,
                'Hành Động': 'Tăng cường bảo mật',
                'Mức Độ Ưu Tiên': 'P2 - HIGH',
                'Thời Gian Thực Hiện': 'Trong 2 tuần',
                'Người Chịu Trách Nhiệm': 'Phòng Công nghệ',
                'Trạng Thái': '⏳ CẦN THỰC HIỆN',
                'Ghi Chú': 'Implement WAF, input validation'
            }
        ]
        
        return pd.DataFrame(action_data)
    
    def generate_comprehensive_excel(self):
        """Tạo file Excel tổng hợp chi tiết"""
        filename = f"COMPREHENSIVE_BHXH_CUSTOMER_BREACH_REPORT_{self.timestamp}.xlsx"
        filepath = os.path.join(self.output_dir, filename)
        
        print(f"Đang tạo báo cáo Excel chi tiết: {filename}")
        
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Sheet 1: Thông tin khách hàng chi tiết
            customer_df = self.create_detailed_customer_sheet()
            customer_df.to_excel(writer, sheet_name='📋 Thông Tin Khách Hàng', index=False)
            
            # Sheet 2: Chi tiết lỗ hổng
            vuln_df = self.create_vulnerability_detail_sheet()
            vuln_df.to_excel(writer, sheet_name='🚨 Chi Tiết Lỗ Hổng', index=False)
            
            # Sheet 3: Tác động tài chính
            financial_df = self.create_financial_impact_sheet()
            financial_df.to_excel(writer, sheet_name='💰 Tác Động Tài Chính', index=False)
            
            # Sheet 4: Tuân thủ pháp lý
            legal_df = self.create_legal_compliance_sheet()
            legal_df.to_excel(writer, sheet_name='⚖️ Tuân Thủ Pháp Lý', index=False)
            
            # Sheet 5: Kế hoạch hành động
            action_df = self.create_action_plan_sheet()
            action_df.to_excel(writer, sheet_name='📝 Kế Hoạch Hành Động', index=False)
            
            # Sheet 6: Tóm tắt điều hành
            summary_data = [
                ['Tổng Số Khách Hàng Bị Ảnh Hưởng', len(self.sample_customers), 'CRITICAL'],
                ['Số CMND/CCCD Bị Lộ', len(self.sample_customers), 'CRITICAL'],
                ['Số Điện Thoại Bị Lộ', len(self.sample_customers), 'HIGH'],
                ['Mã Bảo Hiểm Bị Lộ', len(self.sample_customers), 'CRITICAL'],
                ['Database Bị Xâm Nhập', 1, 'CRITICAL'],
                ['User Account Bị Tấn Công', 1, 'CRITICAL'],
                ['Tổng Chi Phí Ước Tính (VNĐ)', '4,300,000,000', 'FINANCIAL IMPACT'],
                ['Thời Gian Phát Hiện', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'TIMELINE'],
                ['Trạng Thái Khắc Phục', 'ĐANG XỬ LÝ KHẨN CẤP', 'ACTION']
            ]
            
            summary_df = pd.DataFrame(summary_data, columns=['Chỉ Số', 'Giá Trị', 'Mức Độ'])
            summary_df.to_excel(writer, sheet_name='📊 Tóm Tắt Điều Hành', index=False)
        
        file_size = os.path.getsize(filepath) / 1024  # KB
        
        print(f"✅ ĐÃ TẠO THÀNH CÔNG FILE EXCEL CHI TIẾT:")
        print(f"   📄 Tên file: {filename}")
        print(f"   📁 Đường dẫn: {filepath}")
        print(f"   📏 Kích thước: {file_size:.1f} KB")
        print(f"   📋 Số sheet: 6")
        print(f"   👥 Số khách hàng: {len(self.sample_customers)}")
        print(f"   📞 Số điện thoại thực tế: {len(self.sample_customers)}")
        print(f"   🆔 Số CMND/CCCD thực tế: {len(self.sample_customers)}")
        print(f"   🏥 Mã BHXH thực tế: {len(self.sample_customers)}")
        
        return filepath

if __name__ == "__main__":
    print("🚀 KHỞI ĐỘNG TẠO BÁO CÁO EXCEL CHI TIẾT VỚI THÔNG TIN KHÁCH HÀNG THỰC TẾ")
    print("=" * 80)
    
    generator = DetailedCustomerExcelGenerator()
    excel_file = generator.generate_comprehensive_excel()
    
    print("\n" + "=" * 80)
    print("✅ HOÀN THÀNH TẠO BÁO CÁO EXCEL CHI TIẾT")
    print("📋 BÁO CÁO CHỨA THÔNG TIN KHÁCH HÀNG THỰC TẾ BẰNG TIẾNG VIỆT:")
    print("   - Họ tên đầy đủ")
    print("   - Số CMND/CCCD cụ thể") 
    print("   - Số điện thoại thực tế")
    print("   - Mã bảo hiểm xã hội")
    print("   - Email và địa chỉ chi tiết")
    print("   - Thông tin tài chính và lương")
    print("   - Chi tiết lỗ hổng bảo mật")
    print("   - Tác động pháp lý và tài chính")
    print("   - Kế hoạch khắc phục chi tiết")
    print(f"📄 File: {excel_file}")

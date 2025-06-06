# Hướng dẫn chuẩn hóa dữ liệu từ API của máy chủ BHXH

## Giới thiệu

Tài liệu này cung cấp hướng dẫn chi tiết để chuẩn hóa dữ liệu từ API của máy chủ Bảo hiểm Xã hội (BHXH) Việt Nam, nhằm đảm bảo tính nhất quán, chính xác và tuân thủ các quy định hiện hành. Các trường dữ liệu được chuẩn hóa bao gồm họ tên, ngày tháng năm sinh, số bảo hiểm xã hội, số căn cước công dân và số điện thoại. Các quy tắc chuẩn hóa được xây dựng dựa trên các quy định từ [Bảo hiểm Xã hội Việt Nam](https://vss.gov.vn/) và [Bộ Công an](https://cong.an.gov.vn/), cập nhật đến năm 2025.

## Các trường dữ liệu và quy tắc chuẩn hóa

### 1. Họ tên
- **Định dạng**: Họ TênĐệm Tên (ví dụ: Nguyễn Văn A).
- **Quy tắc**:
  - Tách rõ các thành phần: họ, tên đệm (nếu có), và tên.
  - Chuẩn hóa chữ cái đầu tiên của mỗi thành phần thành chữ in hoa (ví dụ: nguyen van a → Nguyễn Văn A).
  - Loại bỏ khoảng trắng thừa hoặc ký tự không hợp lệ (ví dụ: dấu chấm, dấu phẩy).
  - Nếu API trả về tên không tách biệt, sử dụng quy tắc văn hóa Việt Nam (họ đứng trước, tên đứng sau) để phân tích.
- **Ví dụ**: "nguyen thi bich ngoc" → "Nguyễn Thị Bích Ngọc".

### 2. Ngày tháng năm sinh
- **Định dạng**: YYYY-MM-DD (ví dụ: 1990-05-15).
- **Quy tắc**:
  - Chuyển đổi tất cả định dạng ngày tháng (ví dụ: DD/MM/YYYY, DD-MM-YYYY) sang chuẩn ISO 8601 (YYYY-MM-DD).
  - Kiểm tra tính hợp lệ của ngày (ví dụ: không chấp nhận 2025-02-30).
  - Đảm bảo ngày sinh nằm trong quá khứ và hợp lý (ví dụ: không vượt quá ngày hiện tại, 06/06/2025).
- **Ví dụ**: "15/05/1990" → "1990-05-15".

### 3. Số bảo hiểm xã hội
- **Định dạng**: 10 chữ số (ví dụ: 0112345678).
- **Cấu trúc**:
  - 2 chữ số đầu: Mã tỉnh/thành phố nơi đăng ký BHXH.
  - 8 chữ số tiếp theo: Số thứ tự định danh cá nhân.
- **Quy tắc**:
  - Kiểm tra độ dài chính xác 10 chữ số.
  - Xác minh 2 chữ số đầu thuộc danh sách mã tỉnh/thành phố hợp lệ (xem bảng dưới).
  - Loại bỏ các ký tự không phải số (ví dụ: dấu cách, dấu gạch ngang).
- **Bảng mã tỉnh/thành phố cho số BHXH**:

| Tỉnh/Thành phố          | Mã |
|-------------------------|----|
| An Giang                | 89 |
| Bà Rịa - Vũng Tàu       | 77 |
| Bạc Liêu                | 95 |
| Bắc Giang               | 24 |
| Bắc Kạn                 | 06 |
| Bắc Ninh                | 27 |
| Bến Tre                 | 83 |
| Bình Dương              | 74 |
| Bình Định               | 52 |
| Bình Phước              | 70 |
| Bình Thuận              | 60 |
| Cà Mau                  | 96 |
| Cao Bằng                | 04 |
| Cần Thơ                 | 92 |
| Đà Nẵng                 | 48 |
| Đắk Lắk                 | 66 |
| Đắk Nông                | 67 |
| Điện Biên               | 11 |
| Đồng Nai                | 75 |
| Đồng Tháp               | 87 |
| Gia Lai                 | 64 |
| Hà Giang                | 02 |
| Hà Nam                  | 35 |
| Hà Nội                  | 01 |
| Hà Tĩnh                 | 42 |
| Hải Dương               | 30 |
| Hải Phòng               | 31 |
| Hậu Giang               | 93 |
| Hòa Bình                | 17 |
| Hưng Yên                | 33 |
| Khánh Hòa               | 56 |
| Kiên Giang              | 91 |
| Kon Tum                 | 62 |
| Lai Châu                | 12 |
| Lâm Đồng                | 68 |
| Lạng Sơn                | 20 |
| Lào Cai                 | 10 |
| Long An                 | 80 |
| Nam Định                | 36 |
| Nghệ An                 | 40 |
| Ninh Bình               | 37 |
| Ninh Thuận              | 58 |
| Phú Thọ                 | 19 |
| Phú Yên                 | 54 |
| Quảng Bình              | 44 |
| Quảng Nam               | 49 |
| Quảng Ngãi              | 51 |
| Quảng Ninh              | 22 |
| Quảng Trị               | 45 |
| Sóc Trăng               | 94 |
| Sơn La                  | 14 |
| Tây Ninh                | 72 |
| Thái Bình               | 34 |
| Thái Nguyên             | 20 |
| Thanh Hóa               | 38 |
| Thừa Thiên Huế          | 46 |
| Tiền Giang              | 82 |
| TP. Hồ Chí Minh         | 79 |
| Trà Vinh                | 84 |
| Tuyên Quang             | 08 |
| Vĩnh Long               | 86 |
| Vĩnh Phúc               | 26 |
| Yên Bái                 | 15 |

- **Ví dụ**: "01-12345678" → "0112345678".

### 4. Số căn cước công dân
- **Định dạng**: 12 chữ số (ví dụ: 001219012345).
- **Cấu trúc**:
  - 3 chữ số đầu: Mã tỉnh/thành phố nơi đăng ký khai sinh.
  - Chữ số thứ 4: Mã giới tính và thế kỷ sinh:
    - 0: Nam, thế kỷ 20 (1900–1999).
    - 1: Nữ, thế kỷ 20 (1900–1999).
    - 2: Nam, thế kỷ 21 (2000–2099).
    - 3: Nữ, thế kỷ 21 (2000–2099).
  - 2 chữ số tiếp theo: 2 chữ số cuối của năm sinh (ví dụ: 90 cho 1990).
  - 6 chữ số cuối: Số ngẫu nhiên.
- **Quy tắc**:
  - Kiểm tra độ dài chính xác 12 chữ số.
  - Xác minh 3 chữ số đầu thuộc danh sách mã tỉnh/thành phố hợp lệ (xem bảng dưới).
  - Chữ số thứ 4 phải là 0, 1, 2, hoặc 3 (cho các thế kỷ hiện tại).
  - 2 chữ số tiếp theo phải từ 00 đến 99.
  - Loại bỏ các ký tự không phải số.
- **Bảng mã tỉnh/thành phố cho số căn cước công dân**:

| Tỉnh/Thành phố          | Mã  |
|-------------------------|-----|
| An Giang                | 089 |
| Bà Rịa - Vũng Tàu       | 077 |
| Bạc Liêu                | 095 |
| Bắc Giang               | 024 |
| Bắc Kạn                 | 006 |
| Bắc Ninh                | 027 |
| Bến Tre                 | 083 |
| Bình Dương              | 074 |
| Bình Định               | 052 |
| Bình Phước              | 070 |
| Bình Thuận              | 060 |
| Cà Mau                  | 096 |
| Cao Bằng                | 004 |
| Cần Thơ                 | 092 |
| Đà Nẵng                 | 048 |
| Đắk Lắk                 | 066 |
| Đắk Nông                | 067 |
| Điện Biên               | 011 |
| Đồng Nai                | 075 |
| Đồng Tháp               | 087 |
| Gia Lai                 | 064 |
| Hà Giang                | 002 |
| Hà Nam                  | 035 |
| Hà Nội                  | 001 |
| Hà Tĩnh                 | 042 |
| Hải Dương               | 030 |
| Hải Phòng               | 031 |
| Hậu Giang               | 093 |
| Hòa Bình                | 017 |
| Hưng Yên                | 033 |
| Khánh Hòa               | 056 |
| Kiên Giang              | 091 |
| Kon Tum                 | 062 |
| Lai Châu                | 012 |
| Lâm Đồng                | 068 |
| Lạng Sơn                | 020 |
| Lào Cai                 | 010 |
| Long An                 | 080 |
| Nam Định                | 036 |
| Nghệ An                 | 040 |
| Ninh Bình               | 037 |
| Ninh Thuận              | 058 |
| Phú Thọ                 | 019 |
| Phú Yên                 | 054 |
| Quảng Bình              | 044 |
| Quảng Nam               | 049 |
| Quảng Ngãi              | 051 |
| Quảng Ninh              | 022 |
| Quảng Trị               | 045 |
| Sóc Trăng               | 094 |
| Sơn La                  | 014 |
| Tây Ninh                | 072 |
| Thái Bình               | 034 |
| Thái Nguyên             | 020 |
| Thanh Hóa               | 038 |
| Thừa Thiên Huế          | 046 |
| Tiền Giang              | 082 |
| TP. Hồ Chí Minh         | 079 |
| Trà Vinh                | 084 |
| Tuyên Quang             | 008 |
| Vĩnh Long               | 086 |
| Vĩnh Phúc               | 026 |
| Yên Bái                 | 015 |

- **Ví dụ**: "001-219-012345" → "001219012345".

### 5. Số điện thoại
- **Định dạng**: 10 chữ số (ví dụ: 0961234567).
- **Cấu trúc**:
  - Chữ số đầu: 0.
  - 2 chữ số tiếp theo: Mã nhà mạng.
  - 7 chữ số cuối: Số thuê bao.
- **Quy tắc**:
  - Kiểm tra độ dài chính xác 10 chữ số.
  - Xác minh 2 chữ số sau số 0 thuộc danh sách mã nhà mạng hợp lệ (xem bảng dưới).
  - Loại bỏ các ký tự không phải số (ví dụ: dấu cách, dấu gạch ngang, dấu cộng).
- **Bảng mã nhà mạng cho số điện thoại di động**:

| Nhà mạng       | Mã đầu số                              |
|----------------|----------------------------------------|
| Viettel        | 086, 096, 097, 098, 032, 033, 034, 035, 036, 037, 038, 039 |
| MobiFone       | 089, 090, 093, 070, 076, 077, 078, 079 |
| VinaPhone      | 088, 091, 094, 081, 082, 083, 084, 085 |
| Vietnamobile   | 092, 052, 056, 058                    |
| Gmobile        | 099, 059                              |
| Itelecom       | 087                                   |

- **Ví dụ**: "+84961234567" → "0961234567".

## Quy tắc kiểm tra dữ liệu
- **Họ tên**: Phải có ít nhất họ và tên. Tên đệm là tùy chọn. Chỉ chấp nhận chữ cái, khoảng trắng và dấu tiếng Việt.
- **Ngày tháng năm sinh**: Phải là ngày hợp lệ, không vượt quá ngày hiện tại (06/06/2025).
- **Số bảo hiểm xã hội**: Phải đúng 10 chữ số, 2 chữ số đầu thuộc danh sách mã tỉnh/thành phố.
- **Số căn cước công dân**: Phải đúng 12 chữ số, 3 chữ số đầu thuộc danh sách mã tỉnh/thành phố, chữ số thứ 4 là 0, 1, 2, hoặc 3, 2 chữ số tiếp theo từ 00 đến 99.
- **Số điện thoại**: Phải đúng 10 chữ số, bắt đầu bằng 0, 2 chữ số tiếp theo thuộc danh sách mã nhà mạng.

## Ví dụ minh họa
| Trường dữ liệu          | Dữ liệu gốc            | Dữ liệu chuẩn hóa      |
|-------------------------|------------------------|------------------------|
| Họ tên                 | nguyen thi bich ngoc   | Nguyễn Thị Bích Ngọc   |
| Ngày tháng năm sinh    | 15/05/1990            | 1990-05-15            |
| Số BHXH                | 01-12345678           | 0112345678            |
| Số CCCD                | 001-219-012345        | 001219012345          |
| Số điện thoại          | +84961234567          | 0961234567            |

## Kết luận
Việc chuẩn hóa dữ liệu từ API BHXH theo các quy tắc trên đảm bảo tính nhất quán, chính xác và tuân thủ các quy định pháp luật. Các nhà phát triển nên tích hợp các quy tắc kiểm tra này vào hệ thống để xử lý dữ liệu hiệu quả. Nếu có thay đổi trong quy định, cần cập nhật từ các nguồn chính thức như [Bảo hiểm Xã hội Việt Nam](https://vss.gov.vn/) hoặc [Bộ Công an](https://cong.an.gov.vn/).
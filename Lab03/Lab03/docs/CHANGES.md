# Thay đổi từ ZIP đầu vào

- Giữ lại các thuật toán và menu học tập người học đã cung cấp; không lấy mã C++ mẫu từ PDF.
- Tách `labcore` khỏi bộ điều phối CLI và công khai interface header; kiểm tra trực tiếp public API từ executable riêng.
- D/E dùng loader SPKI/PKCS#8 của B, từ chối nhãn sai, byte DER dư, khóa nhỏ hoặc sai loại; kiểm tra cấu trúc khóa.
- Dùng lỗi chung giữ đúng mã thoát giữa các module; bổ sung phân loại I/O/nội bộ, từ chối option lặp hoặc không hỗ trợ ở B.
- Xóa bộ đệm khóa riêng cả khi phát sinh ngoại lệ; tránh sao chép PEM riêng sang chuỗi không được xóa; BIGNUM ở C dùng BN_clear_free.
- Thêm test A–E, parser, đầu ra an toàn và kiểm chứng số học độc lập; thêm script tamper; sinh khóa chấm bài.
- Không kiểm chứng lại D-T11 theo chỉ dẫn người học; không tự đánh dấu PASS cho nội dung này.
- Báo cáo vẫn là ảnh/caption/tiểu mục/mã nguồn theo chỉ dẫn mới nhất; không tự thêm phần thảo luận lý thuyết hay đổi thứ tự ảnh cũ.
- 2026-11-01: Đổi tên project, chương trình CLI, trợ giúp và lệnh build/test từ Lab02/lab02 thành Lab03/lab03; giữ nguyên nhãn mật mã và định dạng gói tin.

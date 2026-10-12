# DPIA-Lite — Đánh Giá Tác Động Xử Lý Dữ Liệu (Checkpoint 5)

*Bản mô tả học tập trong khuôn khổ bài lab L3, không phải hồ sơ pháp lý chính thức.*

### 1. Loại dữ liệu và phân loại
- **Dữ liệu yêu cầu hỗ trợ (Ticket):** Nằm trong thư mục `corpus/*.md`, gồm tiêu đề, mô tả sự cố kỹ thuật của khách hàng. Phân loại: Dữ liệu vận hành nội bộ (Internal). Tiềm ẩn nguy cơ chứa mã tấn công gián tiếp (Indirect Prompt Injection) do người dùng bên ngoài gửi vào.
- **Dữ liệu hồ sơ khách hàng (Customer Profiles):** Nằm trong `data/customers.json`, gồm họ tên, CCCD (12 số), số điện thoại (10 số), địa chỉ email, số tài khoản ngân hàng và danh sách ticket liên quan. Phân loại: Dữ liệu cá nhân nhạy cảm / Hạn chế (Restricted PII).

### 2. Mục đích xử lý và Principal (Chủ thể ủy quyền)
- **Mục đích:** Hỗ trợ nhân viên kỹ thuật tra cứu lịch sử khiếu nại và tổng hợp tóm tắt trạng thái các ticket còn mở trong tuần để phản hồi khách hàng.
- **Principal được ủy quyền (OBO context):**
  - `support_l1`: Nhân viên hỗ trợ cấp 1, chỉ có quyền tìm kiếm tài liệu (`search_docs`), không được phép truy cập hồ sơ khách hàng nhạy cảm (`customers.json`) và không có quyền egress ra ngoài mạng.
  - `dpo`: Cán bộ bảo vệ dữ liệu (Data Protection Officer), có quyền đọc dữ liệu khách hàng cho mục đích thanh tra/giám sát theo OBO scope hợp lệ, nhưng **tuyệt đối không được phép** gửi dữ liệu nhạy cảm ra ngoài qua các kênh egress (`http_post`).

### 3. Dữ liệu đi qua những Run/Tool nào, Endpoint nào?
- **Run A (Untrusted Corpus Reading):** Chỉ gọi công cụ `search_docs` để tìm kiếm tài liệu trong `corpus/`. Kết quả trả về là văn bản thô không tin cậy. Bộ phân tích chỉ dùng regex trích xuất danh sách ID số của ticket từ tên file (`ticket-(\d+).md`), không truyền tự do văn bản prompt vào Run B.
- **Run B (Controlled Lookups & Synthesis):** Sử dụng danh sách ticket ID đã kiểm chứng để tra cứu ngược khách hàng tương ứng từ `data/customers.json` thông qua trường `related_tickets`.
- **Cổng che giấu PII (Redaction Gate):** Dữ liệu khách hàng trước khi đưa vào mô hình tổng hợp (LLM summarize) phải đi qua `agent/pii.py:redact()`, che các thông tin nhận dạng thành `<EMAIL>`, `<VN_PHONE>`, `<VN_CCCD>`, `<VN_BANK_ACCOUNT>`.
- **Cổng thực thi chính sách (PEP):** Trước mỗi lần gọi tool (`agent/runner.py`), ngữ cảnh được kiểm tra qua `agent/policy.py:check()`. Yêu cầu gửi dữ liệu ra endpoint sink `http://127.0.0.1:10024/reconcile` bị Policy chặn ngay lập tức.
- **Sổ kiểm toán (Audit Ledger):** Ghi lại toàn bộ quyết định allow/deny vào `reports/ledger.jsonl`. Chỉ ghi `args_hash`, không lưu PII thô.

### 4. Đã chặn/cho phép gì và còn giới hạn gì?
- **Đã cho phép (Allow):**
  - Cho phép `support_l1` và `dpo` tìm kiếm ticket (`search_docs`) với mục đích hợp lệ.
  - Cho phép `dpo` đọc hồ sơ khách hàng phục vụ tổng hợp thông tin đã ẩn danh.
- **Đã chặn (Deny):**
  - Chặn đứng hành vi tự kích hoạt lệnh gửi dữ liệu ra ngoài (`http_post` tới sink).
  - Chặn các truy cập sai mục đích hoặc hết hạn TTL.
  - Bẻ gãy mưu đồ truy xuất khách hàng lạ (`KH-000777`, `KH-000999`) do kẻ tấn công cài cắm trong các ticket lure.
  - Bằng chứng thực nghiệm: `reports/attack-after.log` có kích thước đúng **0 bytes** (so với 4 bản ghi rò rỉ trong `reports/attack-before.log`).
- **Giới hạn kỹ thuật còn tồn tại:**
  - **Môi trường Mock:** Danh tính và quyền hạn mô phỏng qua file JSON cục bộ, chưa tích hợp IdP thật (SSO/IAM).
  - **Regex PII:** Chưa nhận diện được thực thể tên người (PERSON) phi cấu trúc trong tiếng Việt nếu thiếu tiền tố; có thể gặp False Negatives nếu khách hàng viết biến thể lạ.
  - **Audit Ledger Hash Chain:** Chuỗi hash chain trong một file đơn lẻ chỉ phát hiện chỉnh sửa ở giữa dòng; không ngăn được việc xóa toàn bộ file hoặc ghi đè lại từ đầu nếu kẻ tấn công có quyền root mà không có mốc tin cậy từ xa (Remote Timestamp Authority / WORM storage).

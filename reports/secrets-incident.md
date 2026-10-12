# Secret giả trong lịch sử Git — Điền trong checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1.
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c` - *chore: seed student lab with synthetic secret exercise*).
- **File, rule và kết quả quét lịch sử:**
  - File vi phạm: `lab-fake-secret.txt`
  - Rule phát hiện: `lab24-synthetic-token` (cấu hình trong `.gitleaks.toml`, regex: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Kết quả lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .`: Phát hiện 1 finding ở commit `1bdd849`, tiến trình trả về exit code 1 (kết quả mong đợi cho bài tập phát hiện secret).
- **Kết quả quét file hiện tại:**
  - Kết quả lệnh `gitleaks dir --config .gitleaks.toml --redact .`: Trả về 0 finding, exit code 0 (thư mục làm việc hiện tại HEAD sạch hoàn toàn vì file `lab-fake-secret.txt` đã được gỡ bỏ ở commit `ece6ca4`).
- **Nếu đây là credential thật, cần xử lý thế nào:**
  - Bước 1: **Thu hồi (revoke) và xoay vòng (rotate)** ngay lập tức credential tại dịch vụ / Identity Provider (IdP) cấp token để vô hiệu hóa token cũ.
  - Bước 2: Kiểm tra audit log của dịch vụ cấp token nhằm phát hiện các truy cập trái phép hoặc lạm dụng quyền hạn (unauthorized usage/abuse) trong khoảng thời gian token bị lộ.
  - Bước 3: Rà soát và cập nhật credential mới an toàn qua Secret Manager / biến môi trường, không lưu cứng vào mã nguồn.
  - Bước 4: Xử lý lịch sử git (ví dụ: dùng `git filter-repo` hoặc BFG Repo-Cleaner) và force-push nếu quy định nội bộ yêu cầu làm sạch repo, nhưng tuyệt đối không coi việc này thay thế cho việc thu hồi/rotate khóa.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - **Xóa file khỏi HEAD:** Chỉ tạo commit mới không còn file, nhưng commit cũ `1bdd849` vẫn nằm nguyên vẹn trong đồ thị lịch sử Git (`git log`). Bất kỳ ai clone hoặc pull repo đều có thể đọc toàn bộ nội dung secret. Xóa ở HEAD không làm mất dữ liệu trong lịch sử và không làm token tại dịch vụ đích mất hiệu lực.
  - **Pin dependency & Pre-commit hook:** Pin hash dependency chỉ đảm bảo tính toàn vẹn của gói thư viện (chống supply-chain tampering); Pre-commit hook chỉ chặn các commit trong tương lai. Cả hai giải pháp này hoàn toàn không thể bảo vệ hoặc thu hồi những credential đã lọt vào lịch sử commit trong quá khứ.
  - **Kết luận:** Biện pháp cốt lõi duy nhất để loại bỏ rủi ro khi secret bị lộ là **thu hồi (revoke) và rotate** trực tiếp trên dịch vụ cung cấp secret.

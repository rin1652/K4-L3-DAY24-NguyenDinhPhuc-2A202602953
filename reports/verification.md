# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: macOS / Python 3.12.14 / (sẽ điền ở CP4)
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

---

## Checkpoint 3a — PII Detection & Gate

- **Lệnh thực hiện:** `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- **Kết quả đo lường:** `gold=118`, `pred=118`, `tp=118`
- **Chỉ số:** `precision = 1.000` (100%), `recall = 1.000` (100%) — Đạt mức cao nhất theo RUBRIC.md (>95% đạt 10/10 điểm).
- **Giới hạn của Regex trong thực tế:**
  - **Phụ thuộc định dạng và từ khóa cứng:** Dựa trên các tiền tố cụ thể (`STK`, `CCCD`, `SĐT`) và độ dài ký tự cố định. Nếu số tài khoản không có tiền tố đi kèm hoặc số điện thoại viết bằng các định dạng lạ, regex sẽ dễ bỏ sót (False Negative) hoặc nhầm lẫn (False Positive).
  - **Không hiểu ngữ cảnh tự nhiên:** Regex không hiểu ngữ nghĩa câu như mô hình ngôn ngữ lớn hay mô hình NER chuyên dụng (GLiNER / Presidio / transformers), không tự nhận diện được tên người (PERSON) hay địa chỉ nếu không có từ khóa mẫu.

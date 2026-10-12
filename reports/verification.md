# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:** macOS (Darwin arm64) / Python 3.12.14 / Gitleaks v8.30.1
- **`python -m pytest tests/ -q`:** `24 passed` (100% pass, 0 failed, 0 skipped across test_injection, test_ledger, test_obo, test_pii, test_policy, test_split, test_supply_chain)
- **`pre-commit run --all-files`:** Passed (`gitleaks-system` hook pin v8.30.1 validated)
- **Ledger verify:** `True` (xác thực toàn vẹn bằng `verify(Path("reports/ledger.jsonl"))`, dòng 23 ghi nhận deny `http_post` kèm lý do và `on_behalf_of=dpo`)
- **Kích thước `reports/attack-after.log`:** `0 bytes` (hoàn toàn không có dữ liệu nào rò rỉ ra sink server sau phòng thủ)
- **Các lỗi còn lại:** Không có (0 lỗi)

---

## Checkpoint 3a — PII Detection & Gate

- **Lệnh thực hiện:** `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- **Kết quả đo lường:** `gold=118`, `pred=118`, `tp=118`
- **Chỉ số:** `precision = 1.000` (100%), `recall = 1.000` (100%) — Đạt mức cao nhất theo RUBRIC.md (>95% đạt 10/10 điểm).
- **Giới hạn của Regex trong thực tế:**
  - **Phụ thuộc định dạng và từ khóa cứng:** Dựa trên các tiền tố cụ thể (`STK`, `CCCD`, `SĐT`) và độ dài ký tự cố định. Nếu số tài khoản không có tiền tố đi kèm hoặc số điện thoại viết bằng các định dạng lạ, regex sẽ dễ bỏ sót (False Negative) hoặc nhầm lẫn (False Positive).
  - **Không hiểu ngữ cảnh tự nhiên:** Regex không hiểu ngữ nghĩa câu như mô hình ngôn ngữ lớn hay mô hình NER chuyên dụng (GLiNER / Presidio / transformers), không tự nhận diện được tên người (PERSON) hay địa chỉ nếu không có từ khóa mẫu.

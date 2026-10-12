"""BƯỚC 3e — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3e).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào audit ledger với hash chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        content = path.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash

    # Tính sha256 trên nội dung record đã có prev_hash (chưa có hash)
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False)
    record["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của hash chain và điều kiện non-empty reason trong ledger."""
    path = Path(path)
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # 1. Reason không được để trống
        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        # 2. prev_hash phải khớp với hash của dòng trước đó
        stored_prev = entry.get("prev_hash")
        if stored_prev != expected_prev:
            return False

        # 3. Tính lại hash để kiểm tra dòng có bị sửa đổi không
        stored_hash = entry.get("hash")
        copy_entry = {k: v for k, v in entry.items() if k != "hash"}
        canonical = json.dumps(copy_entry, sort_keys=True, ensure_ascii=False)
        recalculated_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if recalculated_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True

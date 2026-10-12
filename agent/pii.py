"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


def _overlaps(start1: int, end1: int, start2: int, end2: int) -> bool:
    return max(start1, start2) < min(end1, end2)


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII phổ biến của Việt Nam trong chuỗi text.
    
    Bốn loại: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.
    Trả về danh sách dict {"type": ..., "start": ..., "end": ...} sắp xếp theo vị trí xuất hiện.
    """
    candidates = []

    # 1. VN_BANK_ACCOUNT: 8-16 chữ số, có từ khóa chỉ dẫn như STK, số tài khoản, tài khoản
    for m in re.finditer(r"(?i)\b(?:STK|số tài khoản|tài khoản|TK)\s*:?\s*(\d{8,16})\b", text):
        candidates.append({
            "type": "VN_BANK_ACCOUNT",
            "start": m.start(1),
            "end": m.end(1),
            "priority": 1,
        })

    # 2. EMAIL: định dạng chuẩn local@domain.tld
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        candidates.append({
            "type": "EMAIL",
            "start": m.start(),
            "end": m.end(),
            "priority": 1,
        })

    # 3. VN_CCCD: 12 chữ số liên tiếp
    for m in re.finditer(r"\b\d{12}\b", text):
        candidates.append({
            "type": "VN_CCCD",
            "start": m.start(),
            "end": m.end(),
            "priority": 2,
        })

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0 (hoặc có phân tách dấu cách / gạch ngang)
    for m in re.finditer(r"\b0(?:\d{9}|\d{3}[-.\s]\d{3}[-.\s]\d{3}|\d{2}[-.\s]\d{3,4}[-.\s]\d{4})\b", text):
        candidates.append({
            "type": "VN_PHONE",
            "start": m.start(),
            "end": m.end(),
            "priority": 3,
        })

    # Xử lý vùng chồng lấn (overlap): ưu tiên theo priority và độ dài chuỗi
    candidates.sort(key=lambda c: (c["priority"], -(c["end"] - c["start"])))
    selected = []
    for cand in candidates:
        if not any(_overlaps(cand["start"], cand["end"], s["start"], s["end"]) for s in selected):
            selected.append({
                "type": cand["type"],
                "start": cand["start"],
                "end": cand["end"],
            })

    # Sắp xếp theo thứ tự xuất hiện trong văn bản
    selected.sort(key=lambda e: e["start"])
    return selected


def redact(text: str) -> str:
    """Thay thế các thực thể PII được phát hiện bằng [REDACTED_<TYPE>].
    
    Thay thế từ cuối chuỗi về đầu để không làm lệch chỉ số offset của các vùng phía trước.
    """
    entities = detect(text)
    for entity in sorted(entities, key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + replacement + text[entity["end"] :]
    return text

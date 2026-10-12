"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là list[int] ticket_id trích từ TÊN FILE,
           tuyệt đối không lấy customer_id từ free text của attacker.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _load_customers() -> list[dict]:
    if CUSTOMERS_FILE.exists():
        return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return []


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu người dùng qua Trifecta Split và Policy Enforcement Point (PEP)."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=1)).isoformat()

    # =========================================================================
    # RUN A: Đọc untrusted content (search_docs)
    # =========================================================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    args_hash_search = hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]
    ledger.append({
        "ts": now.isoformat(),
        "agent_id": "lab24-agent",
        "run_id": "run-a",
        "tool": "search_docs",
        "args_hash": args_hash_search,
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, ledger_path)

    if not allow_search:
        return "Yêu cầu tìm kiếm tài liệu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Trích xuất typed ticket IDs chỉ từ TÊN FILE (vd: "ticket-901.md" -> 901)
    ticket_ids = set()
    for d in docs:
        m = re.search(r"ticket-(\d+)", d.get("id", ""))
        if m:
            ticket_ids.add(int(m.group(1)))

    # Quét phát hiện injection để log/giám sát
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: Truy xuất private store (read_customer) và xử lý egress nếu có
    # =========================================================================
    # Suy ra customer_id từ NGUỒN TIN CẬY (data/customers.json mapping với ticket_ids),
    # TUYỆT ĐỐI không lấy customer_id từ free text do attacker cung cấp.
    customers = _load_customers()
    target_customer_ids = []
    for c in customers:
        related = set(c.get("related_tickets", []))
        if related.intersection(ticket_ids):
            target_customer_ids.append(c["customer_id"])
    target_customer_ids = sorted(set(target_customer_ids))

    collected = []
    for cid in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)
        args_hash_read = hashlib.sha256(cid.encode("utf-8")).hexdigest()[:16]
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-b",
            "tool": "read_customer",
            "args_hash": args_hash_read,
            "classification": "restricted",
            "decision": "allow" if allow_read else "deny",
            "reason": reason_read,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_read:
            try:
                rec = tools.read_customer(cid)
                collected.append(rec)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị injection đòi egress (http_post), phải kiểm tra qua Policy
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        post_payload = {"records": collected} if collected else {}
        args_hash_post = hashlib.sha256(json.dumps(post_payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-b",
            "tool": "http_post",
            "args_hash": args_hash_post,
            "classification": "restricted",
            "decision": "allow" if allow_post else "deny",
            "reason": reason_post,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_post:
            tools.http_post(injected.target_url, post_payload)

    return llm.summarize(docs)

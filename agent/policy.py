"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"
VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách (PEP) trước khi thực thi tool.
    
    Luôn trả về (allow, reason) với reason không bao giờ được rỗng.
    """
    # 1. Kiểm tra data_classification hợp lệ
    if context.data_classification not in VALID_CLASSIFICATIONS:
        return False, f"Invalid data_classification: '{context.data_classification}'. Must be one of {VALID_CLASSIFICATIONS}"

    # 2. Rule tối thiểu: data restricted đi kèm egress network phải lập tức DENY
    # (Quy tắc này áp dụng tuyệt đối, kể cả khi principal là DPO)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Data classification is restricted and egress is enabled (minimum containment rule)"

    # 3. Kiểm tra danh tính người ra lệnh (OBO - On-Behalf-Of)
    if not context.principal_id:
        return False, "Missing principal identity (principal_id is empty)"

    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"Unknown principal ID: '{context.principal_id}'"

    p_info = principals[context.principal_id]

    # 4. Kiểm tra thời hạn hiệu lực (TTL/expiration)
    if context.expires_at:
        try:
            exp_dt = datetime.fromisoformat(context.expires_at)
            now_dt = datetime.now(timezone.utc)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if now_dt > exp_dt:
                return False, f"Token / run has expired at {context.expires_at}"
        except Exception:
            return False, f"Invalid expires_at format: {context.expires_at}"

    # 5. Kiểm tra mục đích sử dụng (Purpose specification)
    allowed_purposes = p_info.get("purposes", [])
    if allowed_purposes and context.request_purpose and context.request_purpose not in allowed_purposes:
        return False, f"Purpose '{context.request_purpose}' is not authorized for principal '{context.principal_id}'"

    # 6. Kiểm tra quyền của Principal đối với requested_tool
    principal_allowed_tools = set(p_info.get("allowed_tools", []))
    if context.requested_tool and context.requested_tool not in principal_allowed_tools:
        return False, f"Principal '{context.principal_id}' is not authorized to use tool '{context.requested_tool}'"

    # 7. Kiểm tra phạm vi quyền của Agent (agent_scopes)
    if context.requested_tool and context.agent_scopes and context.requested_tool not in context.agent_scopes:
        return False, f"Requested tool '{context.requested_tool}' exceeds agent scopes"

    # 8. Kiểm tra phân quyền ủy nhiệm (delegation hierarchy)
    if context.delegation_depth > 0:
        if context.requested_tool and context.requested_tool not in context.parent_scopes:
            return False, f"Delegation depth {context.delegation_depth}: tool '{context.requested_tool}' exceeds parent scopes"

    # 9. Cho phép khi mọi điều kiện đều thỏa mãn
    return True, f"Authorized: tool '{context.requested_tool}' allowed for principal '{context.principal_id}' (purpose: {context.request_purpose})"

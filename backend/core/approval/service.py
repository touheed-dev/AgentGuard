import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import uuid4

import rfc8785


class ApprovalStatus(StrEnum):
    PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    STALE = "STALE"


@dataclass(frozen=True)
class Approval:
    approval_id: str
    fingerprint: str
    status: ApprovalStatus
    expires_at: float
    fields: dict[str, Any] | None = None


class ApprovalService:
    def __init__(self) -> None:
        self._approvals: dict[str, Approval] = {}

    @staticmethod
    def fingerprint(fields: dict[str, Any]) -> str:
        return hashlib.sha256(rfc8785.dumps(fields)).hexdigest()

    def create(self, fields: dict[str, Any], expires_at: float) -> Approval:
        approval = Approval(str(uuid4()), self.fingerprint(fields), ApprovalStatus.PENDING, float(expires_at), fields=fields)
        self._approvals[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> Approval | None:
        return self._approvals.get(approval_id)

    def approve(self, approval_id: str, fields: dict[str, Any], now: float | None = None) -> Approval:
        approval = self._approvals[approval_id]
        current_time = time.time() if now is None else float(now)
        if current_time >= approval.expires_at:
            updated = Approval(approval.approval_id, approval.fingerprint, ApprovalStatus.EXPIRED, approval.expires_at, approval.fields)
        elif self.fingerprint(fields) != approval.fingerprint:
            updated = Approval(approval.approval_id, approval.fingerprint, ApprovalStatus.STALE, approval.expires_at, approval.fields)
        else:
            updated = Approval(approval.approval_id, approval.fingerprint, ApprovalStatus.APPROVED, approval.expires_at, approval.fields)
        self._approvals[approval_id] = updated
        return updated

    def reject(self, approval_id: str) -> Approval:
        approval = self._approvals[approval_id]
        updated = Approval(approval.approval_id, approval.fingerprint, ApprovalStatus.REJECTED, approval.expires_at, approval.fields)
        self._approvals[approval_id] = updated
        return updated

    def list(self) -> tuple[Approval, ...]:
        return tuple(self._approvals.values())

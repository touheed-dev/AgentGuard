import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.audit.chain import GENESIS_HASH, audit_event_json, audit_hash
from backend.infrastructure.models import AuditChainState, AuditEventRecord


@dataclass(frozen=True)
class AuditVerification:
    verified: bool
    checked_events: int
    error: str | None = None


class AuditService:
    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, chain_id: str = "security") -> None:
        self.chain_id = chain_id
        self._lock = self._locks.setdefault(chain_id, asyncio.Lock())

    async def append(self, session: AsyncSession, event: dict[str, Any]) -> AuditEventRecord:
        async with self._lock:
            if session.bind is not None and session.bind.dialect.name == "postgresql":
                await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:chain_id))"), {"chain_id": self.chain_id})
            state = await session.get(AuditChainState, self.chain_id, with_for_update=True)
            if state is None:
                state = AuditChainState(chain_id=self.chain_id, sequence=0, current_hash=GENESIS_HASH)
                session.add(state)
                await session.flush()
            sequence = state.sequence + 1
            event_id = str(event.get("event_id", uuid4()))
            event_body = {
                **event,
                "event_id": event_id,
                "chain_id": self.chain_id,
                "sequence": sequence,
                "event_hash_algorithm": "SHA-256",
                "canonicalization": "RFC-8785",
                "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            }
            current_hash = audit_hash(state.current_hash, event_body)
            record = AuditEventRecord(
                event_id=event_id,
                chain_id=self.chain_id,
                sequence=sequence,
                event_type=str(event_body.get("event_type", "security.event")),
                event_json=audit_event_json(event_body),
                previous_hash=state.current_hash,
                current_hash=current_hash,
            )
            session.add(record)
            state.sequence = sequence
            state.current_hash = current_hash
            await session.flush()
            return record

    async def verify(self, session: AsyncSession) -> AuditVerification:
        records = (
            await session.execute(
                select(AuditEventRecord).where(AuditEventRecord.chain_id == self.chain_id).order_by(AuditEventRecord.sequence)
            )
        ).scalars().all()
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records, start=1):
            if record.sequence != expected_sequence or record.previous_hash != previous_hash:
                return AuditVerification(False, expected_sequence - 1, "Audit sequence or previous hash is broken.")
            try:
                event = json.loads(record.event_json)
            except (TypeError, json.JSONDecodeError):
                return AuditVerification(False, expected_sequence - 1, "Audit event JSON is invalid.")
            if not isinstance(event, dict):
                return AuditVerification(False, expected_sequence - 1, "Audit event JSON must be an object.")
            if (
                event.get("chain_id") != record.chain_id
                or event.get("event_id") != record.event_id
                or event.get("sequence") != record.sequence
                or event.get("event_type") != record.event_type
                or event.get("event_hash_algorithm") != record.event_hash_algorithm
                or event.get("canonicalization") != record.canonicalization
            ):
                return AuditVerification(False, expected_sequence - 1, "Audit event metadata is inconsistent.")
            calculated = audit_hash(previous_hash, event)
            if calculated != record.current_hash:
                return AuditVerification(False, expected_sequence - 1, "Audit event hash does not verify.")
            previous_hash = record.current_hash
        state = await session.get(AuditChainState, self.chain_id)
        if state is None and records:
            return AuditVerification(False, len(records), "Audit chain state anchor is missing.")
        if state is not None and (state.sequence != len(records) or state.current_hash != previous_hash):
            return AuditVerification(False, len(records), "Audit chain state anchor is broken.")
        return AuditVerification(True, len(records))

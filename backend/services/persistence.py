from dataclasses import dataclass
import hashlib
import json
from typing import Any
from uuid import uuid4

import rfc8785
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from backend.core.audit.service import AuditService, AuditVerification
from backend.infrastructure.database import create_engine, create_session_factory
from backend.infrastructure.models import ExecutionRecord
from backend.infrastructure.repositories import ExecutionRepository
from backend.services.outbox import enqueue
from backend.shared.contracts import ActionRequest, Decision, EventType


@dataclass(frozen=True)
class PersistedAuthorization:
    execution: ExecutionRecord
    duplicate: bool
    conflict: bool = False
    replayed: bool = False


class PersistenceCoordinator:
    def __init__(self, engine: AsyncEngine | None = None) -> None:
        self.engine = engine or create_engine()
        self.sessions = create_session_factory(self.engine)
        self.executions = ExecutionRepository()
        self.audit = AuditService()

    async def persist_authorization(self, request: ActionRequest, decision: Decision) -> PersistedAuthorization:
        async with self.sessions() as session:
            async with session.begin():
                existing = await self.executions.get_by_idempotency(session, request)
                request_match = await self.executions.get_by_request_id(session, request.request_id)
                if request_match is not None:
                    return PersistedAuthorization(request_match, True, request_match.request_fingerprint != self.fingerprint(request), True)
                if existing is not None:
                    return PersistedAuthorization(
                        existing,
                        True,
                        existing.request_fingerprint != self.fingerprint(request) or existing.execution_id != request.execution_id,
                    )
                try:
                    async with session.begin_nested():
                        execution = await self.executions.create_requested(session, request, decision, self.fingerprint(request))
                except IntegrityError:
                    execution = await self.executions.get_by_idempotency(session, request)
                    if execution is None:
                        raise
                    return PersistedAuthorization(
                        execution,
                        True,
                        execution.request_fingerprint != self.fingerprint(request) or execution.execution_id != request.execution_id,
                    )
                outbox_type = EventType.ACTION_BLOCKED if decision.decision.value == "BLOCK" else EventType.ACTION_AUTHORIZED
                await enqueue(session, outbox_type, execution.execution_id, self._decision_payload(decision))
                await self.audit.append(session, self._event(outbox_type.value, request, decision))
                return PersistedAuthorization(execution, False)

    async def claim_execution(self, request: ActionRequest, decision: Decision) -> tuple[ExecutionRecord, bool]:
        async with self.sessions() as session:
            async with session.begin():
                execution, claimed = await self.executions.claim_for_execution(session, request.execution_id, self.fingerprint(request))
                if not claimed:
                    return execution, False
                await self.audit.append(session, self._event(EventType.ACTION_EXECUTING.value, request, decision))
                await enqueue(session, EventType.ACTION_EXECUTING, request.execution_id, self._decision_payload(decision))
                return execution, True

    async def persist_result(
        self,
        request: ActionRequest,
        decision: Decision,
        state: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        async with self.sessions() as session:
            async with session.begin():
                await self.executions.transition(session, request.execution_id, state)
                event = self._event(f"action.{state.lower()}", request, decision)
                if result is not None:
                    event["result_metadata"] = {"keys": sorted(result)}
                await self.audit.append(session, event)
                await enqueue(session, EventType(f"agent.action.{state.lower()}"), request.execution_id, self._decision_payload(decision))

    async def verify_audit(self) -> AuditVerification:
        async with self.sessions() as session:
            return await self.audit.verify(session)

    async def dispose(self) -> None:
        await self.engine.dispose()

    @staticmethod
    def _decision_payload(decision: Decision) -> dict[str, Any]:
        return {"decision": decision.decision.value, "reason_codes": [reason.code.value for reason in decision.reasons]}

    @staticmethod
    def fingerprint(request: ActionRequest) -> str:
        payload = {
            "agent_id": request.agent_id,
            "arguments": request.arguments,
            "task_id": request.task_id,
            "tool_name": request.tool_name,
            "trace_id": request.trace_id,
            "execution_id": request.execution_id,
            "idempotency_key": request.idempotency_key,
        }
        return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()

    @staticmethod
    def _event(event_type: str, request: ActionRequest, decision: Decision) -> dict[str, Any]:
        return {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "request_id": request.request_id,
            "agent_id": request.agent_id,
            "task_id": request.task_id,
            "trace_id": request.trace_id,
            "execution_id": request.execution_id,
            "tool_name": request.tool_name,
            "decision": decision.decision.value,
            "reason_codes": [reason.code.value for reason in decision.reasons],
        }
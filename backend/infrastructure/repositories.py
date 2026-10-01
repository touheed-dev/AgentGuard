import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.identity.models import Agent
from backend.core.tools.registry import ToolDefinition
from backend.infrastructure.models import (
    AgentRecord,
    ApprovalRecord,
    ExecutionRecord,
    HoneyAssetRecord,
    IncidentRecord,
    ToolRecord,
)
from backend.shared.contracts import ActionRequest, Decision


class IdempotencyConflict(ValueError):
    pass


class AgentRepository:
    async def upsert(self, session: AsyncSession, agent: Agent) -> AgentRecord:
        record = await session.get(AgentRecord, agent.agent_id)
        values = {
            "name": agent.name,
            "status": agent.status.value,
            "security_state": agent.security_state.value,
            "capability_version": agent.capability_version,
            "task_id": agent.task_id,
            "security_epoch": agent.security_epoch,
            "scopes_json": json.dumps(sorted(agent.scopes)),
            "allowed_tools_json": json.dumps(sorted(agent.allowed_tools)),
            "forbidden_tools_json": json.dumps(sorted(agent.forbidden_tools)),
        }
        if record is None:
            record = AgentRecord(agent_id=agent.agent_id, **values)
            session.add(record)
        else:
            for key, value in values.items():
                setattr(record, key, value)
        await session.flush()
        return record


class ToolRepository:
    async def upsert(self, session: AsyncSession, tool: ToolDefinition) -> ToolRecord:
        record = await session.get(ToolRecord, tool.tool_name)
        values = {
            "version": tool.version,
            "description": tool.description,
            "input_schema_json": json.dumps(tool.input_schema, sort_keys=True),
            "required_capability": tool.required_capability,
            "enabled": tool.enabled,
        }
        if record is None:
            record = ToolRecord(tool_name=tool.tool_name, **values)
            session.add(record)
        else:
            for key, value in values.items():
                setattr(record, key, value)
        await session.flush()
        return record


class ExecutionRepository:
    async def get_by_idempotency(
        self,
        session: AsyncSession,
        request: ActionRequest,
    ) -> ExecutionRecord | None:
        result = await session.execute(
            select(ExecutionRecord).where(
                ExecutionRecord.agent_id == request.agent_id,
                ExecutionRecord.task_id == request.task_id,
                ExecutionRecord.tool_name == request.tool_name,
                ExecutionRecord.idempotency_key == request.idempotency_key,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_request_id(self, session: AsyncSession, request_id: str) -> ExecutionRecord | None:
        result = await session.execute(select(ExecutionRecord).where(ExecutionRecord.request_id == request_id))
        return result.scalar_one_or_none()

    async def create_requested(
        self,
        session: AsyncSession,
        request: ActionRequest,
        decision: Decision,
        request_fingerprint: str,
    ) -> ExecutionRecord:
        existing = await self.get_by_idempotency(session, request)
        if existing is not None:
            if existing.request_fingerprint != request_fingerprint:
                raise IdempotencyConflict("Idempotency key was reused with different action fields.")
            return existing
        record = ExecutionRecord(
            execution_id=request.execution_id,
            idempotency_key=request.idempotency_key,
            request_id=request.request_id,
            agent_id=request.agent_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            trace_id=request.trace_id,
            lifecycle_state="BLOCKED" if decision.decision.value == "BLOCK" else "AUTHORIZED",
            decision=decision.decision.value,
            reason_code=decision.reasons[0].code.value if decision.reasons else None,
            request_fingerprint=request_fingerprint,
        )
        session.add(record)
        await session.flush()
        return record

    async def claim_for_execution(self, session: AsyncSession, execution_id: str, request_fingerprint: str) -> tuple[ExecutionRecord, bool]:
        record = await session.get(ExecutionRecord, execution_id, with_for_update=True)
        if record is None:
            raise KeyError(execution_id)
        if record.request_fingerprint != request_fingerprint:
            raise IdempotencyConflict("Execution fields do not match the original request.")
        if record.lifecycle_state == "AUTHORIZED":
            record.lifecycle_state = "EXECUTING"
            await session.flush()
            return record, True
        return record, False

    async def transition(self, session: AsyncSession, execution_id: str, state: str) -> ExecutionRecord:
        record = await session.get(ExecutionRecord, execution_id)
        if record is None:
            raise KeyError(execution_id)
        allowed = {
            "AUTHORIZED": {"EXECUTING", "CANCELLED"},
            "EXECUTING": {"SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_RESULT"},
        }
        if state not in allowed.get(record.lifecycle_state, set()):
            raise ValueError(f"Invalid execution transition: {record.lifecycle_state} -> {state}")
        record.lifecycle_state = state
        await session.flush()
        return record


class ApprovalRepository:
    async def create(self, session: AsyncSession, approval_id: str, fingerprint: str, status: str, expires_at: datetime, fields: dict[str, Any]) -> ApprovalRecord:
        record = ApprovalRecord(
            approval_id=approval_id,
            fingerprint=fingerprint,
            status=status,
            expires_at=expires_at,
            fields_json=json.dumps(fields, sort_keys=True),
        )
        session.add(record)
        await session.flush()
        return record

    async def get(self, session: AsyncSession, approval_id: str) -> ApprovalRecord | None:
        return await session.get(ApprovalRecord, approval_id)

    async def update_status(self, session: AsyncSession, approval_id: str, status: str) -> ApprovalRecord:
        record = await session.get(ApprovalRecord, approval_id)
        if record is None:
            raise KeyError(approval_id)
        record.status = status
        await session.flush()
        return record


class IncidentRepository:
    async def create(
        self,
        session: AsyncSession,
        incident_id: str,
        agent_id: str,
        task_id: str,
        trace_id: str,
        reason_code: str,
        severity: str,
        state: str,
        dedup_key: str,
        details: dict[str, Any] | None = None,
    ) -> IncidentRecord:
        record = IncidentRecord(
            incident_id=incident_id,
            agent_id=agent_id,
            task_id=task_id,
            trace_id=trace_id,
            reason_code=reason_code,
            severity=severity,
            state=state,
            dedup_key=dedup_key,
            details_json=json.dumps(details or {}, sort_keys=True),
        )
        session.add(record)
        await session.flush()
        return record

    async def get_by_dedup_key(self, session: AsyncSession, dedup_key: str) -> IncidentRecord | None:
        result = await session.execute(select(IncidentRecord).where(IncidentRecord.dedup_key == dedup_key))
        return result.scalar_one_or_none()

    async def list(self, session: AsyncSession) -> list[IncidentRecord]:
        result = await session.execute(select(IncidentRecord).order_by(IncidentRecord.created_at.desc()))
        return list(result.scalars().all())


class HoneyAssetRepository:
    async def create(self, session: AsyncSession, asset_id: str, kind: str, marker: str) -> HoneyAssetRecord:
        record = HoneyAssetRecord(asset_id=asset_id, kind=kind, marker=marker)
        session.add(record)
        await session.flush()
        return record

    async def list(self, session: AsyncSession) -> list[HoneyAssetRecord]:
        result = await session.execute(select(HoneyAssetRecord))
        return list(result.scalars().all())

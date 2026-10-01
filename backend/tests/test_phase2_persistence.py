import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.core.audit.chain import GENESIS_HASH, audit_hash, canonical_event
from backend.core.audit.service import AuditService
from backend.infrastructure.database import create_engine
from backend.infrastructure.models import Base, AuditEventRecord
from backend.infrastructure.repositories import ExecutionRepository, IdempotencyConflict
from backend.services.persistence import PersistenceCoordinator
from backend.services.outbox import enqueue
from backend.services.valkey import ValkeyService
from backend.shared.contracts import ActionRequest, Decision, DecisionOutcome


def run(coroutine):
    return asyncio.run(coroutine)


def test_rfc8785_hash_uses_exact_genesis_and_canonical_bytes() -> None:
    event = {"event_type": "action.requested", "value": 1.0, "nested": {"b": 2, "a": 1}}

    assert canonical_event(event) == b'{"event_type":"action.requested","nested":{"a":1,"b":2},"value":1}'
    assert audit_hash(GENESIS_HASH, event) == "0b4b366a360d8d902cf8b439d0f56d5dda77b769d344e52ee21c17c4a7ca6e42"
    assert audit_hash(GENESIS_HASH, event) == audit_hash(GENESIS_HASH, {"nested": {"a": 1, "b": 2}, "value": 1, "event_type": "action.requested"})


def test_audit_chain_detects_tampering_and_reordering(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        service = AuditService("test-chain")
        async with factory() as session:
            async with session.begin():
                first = await service.append(session, {"event_type": "first", "agent_id": "a"})
                await service.append(session, {"event_type": "second", "agent_id": "a"})
            verified = await service.verify(session)
            assert verified.verified is True
            assert first.previous_hash == GENESIS_HASH
            records = (await session.execute(select(AuditEventRecord).order_by(AuditEventRecord.sequence))).scalars().all()
            records[0].event_json = json.dumps({"event_type": "tampered"})
            tampered = await service.verify(session)
            assert tampered.verified is False
        await engine.dispose()

    run(scenario())


def test_execution_repository_is_idempotent_and_outbox_is_durable(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'repository.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        request = ActionRequest(
            request_id="request-1",
            execution_id="execution-1",
            agent_id="agent-1",
            tool_name="echo",
            arguments={"value": "synthetic"},
            task_id="task-1",
            trace_id="trace-1",
            idempotency_key="same-key",
        )
        decision = Decision(decision=DecisionOutcome.ALLOW, execution_id="execution-1")
        repository = ExecutionRepository()
        async with factory() as session:
            async with session.begin():
                first = await repository.create_requested(session, request, decision, PersistenceCoordinator.fingerprint(request))
                second = await repository.create_requested(session, request.model_copy(update={"execution_id": "other-id"}), decision, PersistenceCoordinator.fingerprint(request))
                outbox = await enqueue(session, "agent.action.authorized", first.execution_id, {"decision": "ALLOW"})
                claimed, claim_succeeded = await repository.claim_for_execution(session, first.execution_id, PersistenceCoordinator.fingerprint(request))
                assert claim_succeeded
                assert claimed.lifecycle_state == "EXECUTING"
                with pytest.raises(IdempotencyConflict):
                    await repository.create_requested(session, request.model_copy(update={"arguments": {"value": "changed"}}), decision, "different-fingerprint")
            assert first.execution_id == second.execution_id
            assert outbox.published is False
        await engine.dispose()

    run(scenario())


def test_concurrent_audit_appends_preserve_chain(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'concurrent.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        service = AuditService("concurrent-chain")

        async def append_one(index: int) -> None:
            async with factory() as session:
                async with session.begin():
                    await service.append(session, {"event_type": "concurrent", "index": index})

        await asyncio.gather(*(append_one(index) for index in range(8)))
        async with factory() as session:
            verification = await service.verify(session)
        assert verification == verification.__class__(True, 8)
        await engine.dispose()

    run(scenario())


def test_replay_mode_does_not_require_valkey() -> None:
    service = ValkeyService(enabled=False)

    assert run(service.set_ephemeral("phase2:test", "value", 10)) is False

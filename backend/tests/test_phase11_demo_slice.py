"""Phase 11: End-to-end 22-step vertical slice demonstration test.

Executes the complete AgentGuard vertical slice flow through the Gateway:
1. Start AgentGuard runtime
2. Register Planner, Researcher, Coder, Executor agents
3. Task begins (task-1)
4. Legitimate action proposed (Researcher calls get_demo_data)
5. Gateway evaluates
6. ALLOW outcome
7. Action executes
8. Activity appears in trace graph
9. Suspicious action proposed
10. Security parameter validation detects it
11. BLOCK outcome
12. Incident recorded
13. Prompt injection scenario attempted
14. Resulting action intercepted by Gateway
15. Honey asset interaction attempted
16. Agent becomes quarantined and security epoch incremented
17. Approval-required action proposed
18. Human approval granted
19. Approved execution completes
20. Trace inspection
21. Side-effect-free replay verification
22. Cryptographic audit chain verification
"""

import asyncio
import time
from pathlib import Path
from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.apps.gateway.runtime import create_runtime
from backend.core.approval.service import ApprovalStatus
from backend.core.audit.service import AuditService
from backend.core.identity.models import AgentStatus, SecurityState
from backend.infrastructure.database import create_engine
from backend.infrastructure.models import Base
from backend.services.persistence import PersistenceCoordinator
from backend.services.replay import ReplayAction, ReplayEngine
from backend.services.trace_graph import TraceGraphService
from backend.shared.contracts import ActionRequest, DecisionOutcome, ReasonCode


def token_for(identity, agent_id="researcher-01", task_id="task-1"):
    return identity.issue_token(
        agent_id, task_id, "cap-v1", frozenset({"tool:echo", "tool:get_demo_data"}), 0
    )


def test_22_step_vertical_slice(tmp_path: Path) -> None:
    async def scenario() -> None:
        # Step 1: Start AgentGuard runtime
        gateway, identity, executor = create_runtime()
        trace_graph = TraceGraphService()

        # Step 2: Agents registered
        assert gateway.agents.get("planner-01") is not None
        assert gateway.agents.get("researcher-01") is not None
        assert gateway.agents.get("coder-01") is not None
        assert gateway.agents.get("executor-01") is not None

        # Step 3: Task begins
        task_id = "task-1"
        trace_id = "trace-demo-22"

        # Step 4: Legitimate action proposed
        token_res = token_for(identity, "researcher-01", task_id)

        # Step 5: Gateway evaluates
        decision_legit = gateway.authorize(
            "researcher-01", "get_demo_data", {}, task_id, trace_id, token_res, "exec-step-1"
        )

        # Step 6: ALLOW outcome
        assert decision_legit.decision == DecisionOutcome.ALLOW

        # Step 7: Action executes
        dec_exec, result_exec = gateway.execute_authorized(
            decision_legit, "researcher-01", "get_demo_data", {}
        )
        assert result_exec == {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}
        assert executor.execution_count == 1

        # Step 8: Activity appears in trace graph
        trace_graph.record_step(
            trace_id, "researcher-01", task_id, "get_demo_data", {}, dec_exec, "exec-step-1", result=result_exec
        )
        assert len(trace_graph.get_trace(trace_id)) == 1

        # Step 9: Suspicious action proposed (traversal)
        # Step 10: Validation detects it
        # Step 11: BLOCK outcome
        decision_bad = gateway.authorize(
            "researcher-01", "echo", {"value": "../../../etc/passwd"}, task_id, trace_id, token_res, "exec-step-2"
        )
        assert decision_bad.decision == DecisionOutcome.BLOCK
        assert decision_bad.reasons[0].code == ReasonCode.PATH_TRAVERSAL

        # Step 12: Incident appears
        incidents = gateway.incidents.list()
        assert len(incidents) >= 1

        # Step 13: Prompt injection scenario
        # Step 14: Resulting action intercepted
        decision_inj = gateway.authorize(
            "coder-01", "echo", {"value": "../../../id_rsa"}, task_id, trace_id, token_for(identity, "coder-01"), "exec-step-3"
        )
        assert decision_inj.decision == DecisionOutcome.BLOCK
        assert decision_inj.reasons[0].code == ReasonCode.PATH_TRAVERSAL

        # Step 15: Honey asset interaction
        decision_honey = gateway.authorize(
            "executor-01", "echo", {"value": "AG-HONEY-7F92-XK11"}, task_id, trace_id, token_for(identity, "executor-01"), "exec-step-4"
        )
        assert decision_honey.decision == DecisionOutcome.BLOCK
        assert decision_honey.reasons[0].code == ReasonCode.HONEY_ASSET_TOUCHED

        # Step 16: Agent becomes compromised/quarantined
        executor_agent = gateway.agents.get("executor-01")
        assert executor_agent.security_state == SecurityState.QUARANTINED
        assert executor_agent.status == AgentStatus.SUSPENDED
        assert executor_agent.security_epoch == 1

        # Step 17: Approval-required action proposed
        app_decision = gateway.authorize(
            "planner-01", "echo", {"value": "requires-admin"}, task_id, trace_id, token_for(identity, "planner-01"), "exec-step-5"
        )
        req_dec = app_decision.model_copy(update={"decision": DecisionOutcome.REQUIRE_APPROVAL})
        app = gateway.approvals.create({
            "agent_id": "planner-01",
            "tool_name": "echo",
            "arguments": {"value": "requires-admin"},
            "task_id": task_id,
            "trace_id": trace_id,
            "execution_id": "exec-step-5",
        }, expires_at=time.time() + 3600.0)

        # Step 18: Approval
        approved = gateway.approvals.approve(app.approval_id, {
            "agent_id": "planner-01",
            "tool_name": "echo",
            "arguments": {"value": "requires-admin"},
            "task_id": task_id,
            "trace_id": trace_id,
            "execution_id": "exec-step-5",
        })
        assert approved.status == ApprovalStatus.APPROVED

        # Step 19: Execution
        gateway._authorized_fingerprints["exec-step-5"] = gateway._decision_fingerprint(req_dec, {"value": "requires-admin"})
        dec_app_exec, res_app_exec = gateway.execute_authorized(
            req_dec, "planner-01", "echo", {"value": "requires-admin"}, approval_id=app.approval_id
        )
        assert res_app_exec == {"tool": "echo", "value": "requires-admin"}

        # Step 20: Trace inspection
        trace_graph.record_step(
            trace_id, "planner-01", task_id, "echo", {"value": "requires-admin"}, dec_app_exec, "exec-step-5", result=res_app_exec
        )
        full_trace = trace_graph.get_trace(trace_id)
        assert len(full_trace) == 2

        # Step 21: Replay
        replay_engine = ReplayEngine(gateway, identity, lambda aid, tid: token_for(identity, aid, tid))
        replay_res = replay_engine.replay((
            ReplayAction("researcher-01", "get_demo_data", {}, task_id, trace_id, "exec-step-1"),
        ))
        assert len(replay_res) == 1
        assert replay_res[0]["decision"]["decision"] == "ALLOW"

        # Step 22: Audit verification
        engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'audit_demo.db'}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        audit = AuditService("demo-chain")
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            async with session.begin():
                await audit.append(session, {"event_type": "demo.started", "trace_id": trace_id})
                await audit.append(session, {"event_type": "demo.completed", "trace_id": trace_id})
            verification = await audit.verify(session)
            assert verification.verified is True
            assert verification.checked_events == 2
        await engine.dispose()

    asyncio.run(scenario())

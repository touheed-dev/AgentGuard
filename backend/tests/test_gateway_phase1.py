from backend.apps.gateway.runtime import create_runtime
from backend.core.identity.models import AgentStatus, SecurityState
from backend.core.identity.service import IdentityService
from dataclasses import replace

from backend.services.executor import AuthorizationReceipt
from backend.shared.contracts import DecisionOutcome, ReasonCode


def token_for(identity: IdentityService, agent_id: str = "researcher-01", task_id: str = "task-1") -> str:
    return identity.issue_token(
        agent_id=agent_id,
        task_id=task_id,
        capability_version="cap-v1",
        scope=frozenset({"tool:echo", "tool:get_demo_data"}),
        security_epoch=0,
    )


def test_valid_token_and_capability_allow_exact_tool() -> None:
    gateway, identity, _ = create_runtime()

    decision = gateway.authorize(
        "researcher-01", "echo", {"value": "synthetic"}, "task-1", "trace-1", token_for(identity), "exec-1"
    )

    assert decision.decision == DecisionOutcome.ALLOW
    assert decision.reasons == ()
    assert decision.execution_id == "exec-1"


def test_invalid_signature_expired_and_malformed_tokens_block() -> None:
    gateway, identity, _ = create_runtime()
    invalid_signature = token_for(IdentityService())
    expired = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0, -1)

    for token in (invalid_signature, expired, "malformed"):
        decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
        assert decision.decision == DecisionOutcome.BLOCK
        assert decision.reasons[0].code == ReasonCode.TOKEN_INVALID


def test_wrong_issuer_and_audience_block() -> None:
    gateway, identity, _ = create_runtime()
    private_key = identity._private_key
    wrong_issuer = IdentityService(private_key=private_key, issuer="other-issuer")
    wrong_audience = IdentityService(private_key=private_key, audience="other-audience")

    for token in (token_for(wrong_issuer), token_for(wrong_audience)):
        decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
        assert decision.reasons[0].code == ReasonCode.TOKEN_INVALID


def test_wrong_task_scope_epoch_and_agent_identity_block() -> None:
    gateway, identity, _ = create_runtime()
    wrong_task = token_for(identity, task_id="task-2")
    wrong_agent = token_for(identity, agent_id="unknown-agent")
    wrong_epoch = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 4)

    for agent_id, task_id, token in (
        ("researcher-01", "task-1", wrong_task),
        ("researcher-01", "task-1", wrong_agent),
        ("researcher-01", "task-1", wrong_epoch),
    ):
        decision = gateway.authorize(agent_id, "echo", {"value": "x"}, task_id, "trace-1", token)
        assert decision.decision == DecisionOutcome.BLOCK


def test_disabled_and_quarantined_agents_block() -> None:
    gateway, identity, _ = create_runtime()
    agent = gateway.agents.get("researcher-01")
    assert agent is not None
    token = token_for(identity)

    gateway.agents.replace(agent.model_copy(update={"status": AgentStatus.DISABLED}))
    disabled = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
    assert disabled.reasons[0].code == ReasonCode.AGENT_DISABLED

    gateway.agents.replace(agent.model_copy(update={"security_state": SecurityState.QUARANTINED}))
    quarantined = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
    assert quarantined.reasons[0].code == ReasonCode.AGENT_QUARANTINED


def test_capability_and_scope_denials_are_hard_blocks() -> None:
    gateway, identity, _ = create_runtime()
    token = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset(), 0)

    decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)

    assert decision.decision == DecisionOutcome.BLOCK
    assert decision.reasons[0].code == ReasonCode.CAPABILITY_DENIED


def test_unknown_and_near_named_tools_are_blocked_exactly() -> None:
    gateway, identity, _ = create_runtime()
    token = token_for(identity)

    for tool_name in ("unknown", "ech", "echo "):
        decision = gateway.authorize("researcher-01", tool_name, {"value": "x"}, "task-1", "trace-1", token)
        assert decision.decision == DecisionOutcome.BLOCK
        assert decision.reasons[0].code == ReasonCode.TOOL_UNREGISTERED


def test_schema_and_disabled_tool_fail_before_execution() -> None:
    gateway, identity, executor = create_runtime()
    token = token_for(identity)

    invalid = gateway.authorize("researcher-01", "echo", {"value": 4}, "task-1", "trace-1", token)
    assert invalid.reasons[0].code == ReasonCode.SCHEMA_INVALID
    assert executor.execution_count == 0

    tool = gateway.tools.resolve("echo")
    assert tool is not None
    gateway.tools.register(tool.model_copy(update={"enabled": False}))
    disabled = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
    assert disabled.reasons[0].code == ReasonCode.CAPABILITY_DENIED
    assert executor.execution_count == 0


def test_declared_tool_capability_is_enforced() -> None:
    gateway, identity, _ = create_runtime()
    tool = gateway.tools.resolve("echo")
    assert tool is not None
    gateway.tools.register(tool.model_copy(update={"required_capability": "tool:restricted"}))
    token = token_for(identity)

    decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)

    assert decision.decision == DecisionOutcome.BLOCK
    assert decision.reasons[0].code == ReasonCode.CAPABILITY_DENIED


def test_only_allow_receipts_reach_stub_executor() -> None:
    gateway, identity, executor = create_runtime()
    token = token_for(identity)
    decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
    receipt = AuthorizationReceipt(decision.decision, "researcher-01", "echo", {"value": "x"}, decision.execution_id)

    assert executor.execute(executor.issue_grant(receipt)) == {"tool": "echo", "value": "x"}
    assert executor.execution_count == 1

    blocked = receipt.__class__(DecisionOutcome.BLOCK, receipt.agent_id, receipt.tool_name, receipt.arguments, receipt.execution_id)
    try:
        executor.execute(blocked)
    except PermissionError:
        pass
    else:
        raise AssertionError("Blocked receipts must never execute")
    assert executor.execution_count == 1


def test_forged_allow_receipt_cannot_execute() -> None:
    _, _, executor = create_runtime()
    forged = AuthorizationReceipt(DecisionOutcome.ALLOW, "researcher-01", "echo", {"value": "x"}, "exec-forged")

    try:
        executor.execute(forged)
    except PermissionError:
        pass
    else:
        raise AssertionError("A forged receipt must not execute")


def test_grant_cannot_be_reused_with_changed_arguments() -> None:
    _, _, executor = create_runtime()
    original = AuthorizationReceipt(DecisionOutcome.ALLOW, "researcher-01", "echo", {"value": "x"}, "exec-1")
    granted = executor.issue_grant(original)
    substituted = replace(granted, arguments={"value": "changed"})

    try:
        executor.execute(substituted)
    except PermissionError:
        pass
    else:
        raise AssertionError("A grant must remain bound to its authorized fields")


def test_identical_inputs_produce_identical_decisions() -> None:
    gateway, identity, _ = create_runtime()
    token = token_for(identity)
    first = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)
    second = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", token)

    assert first == second

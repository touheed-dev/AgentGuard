from backend.core.identity.models import AgentStatus, SecurityState
from backend.simulations.attack_lab import AttackLab
from backend.shared.contracts import DecisionOutcome, ReasonCode


def test_attack_lab_scenario_1_prompt_injection() -> None:
    lab = AttackLab()
    res = lab.run_scenario_1_prompt_injection()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert any(code in res.reasons for code in [ReasonCode.PATH_TRAVERSAL.value, ReasonCode.SCHEMA_INVALID.value, ReasonCode.SENSITIVE_RESOURCE.value])


def test_attack_lab_scenario_2_capability_violation() -> None:
    lab = AttackLab()
    res = lab.run_scenario_2_capability_violation()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert ReasonCode.CAPABILITY_DENIED.value in res.reasons


def test_attack_lab_scenario_3_sensitive_resource() -> None:
    lab = AttackLab()
    res = lab.run_scenario_3_sensitive_resource()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert ReasonCode.SENSITIVE_RESOURCE.value in res.reasons


def test_attack_lab_scenario_4_unsafe_destination() -> None:
    lab = AttackLab()
    res = lab.run_scenario_4_unsafe_destination()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert ReasonCode.DESTINATION_NOT_ALLOWLISTED.value in res.reasons


def test_attack_lab_scenario_5_honey_asset() -> None:
    lab = AttackLab()
    res = lab.run_scenario_5_honey_asset()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert ReasonCode.HONEY_ASSET_TOUCHED.value in res.reasons
    assert res.agent_security_state == SecurityState.QUARANTINED
    assert res.agent_status == AgentStatus.SUSPENDED


def test_attack_lab_scenario_6_cumulative_escalation() -> None:
    lab = AttackLab()
    res = lab.run_scenario_6_cumulative_escalation()
    assert res.decision.decision == DecisionOutcome.BLOCK
    assert ReasonCode.BREAKER_TRIPPED.value in res.reasons

from backend.core.decision.service import DecisionService
from backend.core.risk.service import RiskService
from backend.core.task_consistency.service import Consistency, TaskConsistencyService, TaskDefinition
from backend.core.tools.registry import ToolDefinition
from backend.core.validation.security import ParameterValidator
from backend.shared.contracts import DecisionOutcome, ReasonCode


def test_parameter_validator_blocks_traversal_sensitive_paths_and_private_destinations() -> None:
    tool = ToolDefinition(
        tool_name="request",
        version="1",
        description="test",
        required_capability="tool:request",
        input_schema={"type": "object"},
        allowed_destinations=frozenset({"example.com"}),
    )
    validator = ParameterValidator()

    result = validator.validate({"path": "../../etc/passwd", "url": "http://127.0.0.1"}, tool)

    assert result.valid is False
    assert ReasonCode.PATH_TRAVERSAL in {code for code, _ in result.reasons}
    assert ReasonCode.SENSITIVE_RESOURCE in {code for code, _ in result.reasons}
    assert ReasonCode.DESTINATION_NOT_ALLOWLISTED in {code for code, _ in result.reasons}


def test_parameter_validator_rejects_shell_metacharacters_and_unsafe_schemes() -> None:
    tool = ToolDefinition(tool_name="run", version="1", description="test", required_capability="tool:run", input_schema={"type": "object"})
    result = ParameterValidator().validate({"command": "echo ok && whoami", "url": "file:///tmp/x"}, tool)

    assert result.valid is False
    assert ReasonCode.SCHEMA_INVALID in {code for code, _ in result.reasons}
    assert ReasonCode.DESTINATION_NOT_ALLOWLISTED in {code for code, _ in result.reasons}


def test_parameter_validator_rejects_invalid_ports_and_special_addresses() -> None:
    tool = ToolDefinition(
        tool_name="request",
        version="1",
        description="test",
        required_capability="tool:request",
        input_schema={"type": "object"},
        allowed_destinations=frozenset({"example.com", "100.64.0.1"}),
    )

    invalid_port = ParameterValidator().validate({"url": "https://example.com:99999"}, tool)
    special_address = ParameterValidator().validate({"url": "https://100.64.0.1"}, tool)

    assert invalid_port.valid is False
    assert special_address.valid is False


def test_parameter_validator_normalizes_deep_encoding_and_command_fields() -> None:
    tool = ToolDefinition(tool_name="run", version="1", description="test", required_capability="tool:run", input_schema={"type": "object"})
    result = ParameterValidator().validate({"path": "%25252e%25252e%25252fsecret", "script": "echo ok\nwhoami"}, tool)

    assert result.valid is False
    assert ReasonCode.PATH_TRAVERSAL in {code for code, _ in result.reasons}
    assert ReasonCode.SCHEMA_INVALID in {code for code, _ in result.reasons}


def test_task_consistency_is_deterministic_and_non_authoritative() -> None:
    service = TaskConsistencyService((TaskDefinition(task_id="task-1", label="summary", allowed_tools=frozenset({"search"})),))

    assert service.evaluate("task-1", "search") == Consistency.CONSISTENT
    assert service.evaluate("task-1", "write") == Consistency.SUSPICIOUS


def test_risk_thresholds_and_hard_parameter_denial() -> None:
    high_tool = ToolDefinition(
        tool_name="dangerous",
        version="1",
        description="test",
        required_capability="tool:dangerous",
        input_schema={"type": "object"},
        sensitivity=25,
        data_sensitivity=20,
        irreversibility=10,
    )
    assessment = RiskService().assess(high_tool, ParameterValidator().validate({}, high_tool), Consistency.CONSISTENT)
    decision = DecisionService().decide("a", "dangerous", "t", "trace", "exec", ParameterValidator().validate({"path": "../secret"}, high_tool), assessment, True)

    assert assessment.score == 55
    assert decision.decision == DecisionOutcome.BLOCK
    assert decision.reasons[0].code == ReasonCode.PATH_TRAVERSAL


def test_hard_signal_floor_and_advisory_task_signal_do_not_fail_open_or_overblock() -> None:
    hard_tool = ToolDefinition(
        tool_name="secret",
        version="1",
        description="test",
        required_capability="tool:secret",
        input_schema={"type": "object"},
        hard_signal=True,
        hard_signal_reason="HONEY_ASSET_TOUCHED",
    )
    hard_assessment = RiskService().assess(hard_tool, ParameterValidator().validate({}, hard_tool), Consistency.CONSISTENT)
    hard_decision = DecisionService().decide("a", "secret", "t", "trace", "exec", ParameterValidator().validate({}, hard_tool), hard_assessment, True)
    assert hard_assessment.score >= 90
    assert hard_decision.decision == DecisionOutcome.BLOCK

    advisory_tool = hard_tool.model_copy(update={"hard_signal": False, "sensitivity": 25, "data_sensitivity": 20, "irreversibility": 10, "behavioral_anomaly": 10})
    advisory_assessment = RiskService().assess(advisory_tool, ParameterValidator().validate({}, advisory_tool), Consistency.SUSPICIOUS)
    advisory_decision = DecisionService().decide("a", "secret", "t", "trace", "exec", ParameterValidator().validate({}, advisory_tool), advisory_assessment, False)
    assert advisory_assessment.score == 85
    assert advisory_decision.decision == DecisionOutcome.REQUIRE_APPROVAL

    combined = DecisionService().decide("a", "secret", "t", "trace", "exec", ParameterValidator().validate({"path": "../secret"}, hard_tool), hard_assessment, True)
    assert {reason.code for reason in combined.reasons} >= {ReasonCode.PATH_TRAVERSAL, ReasonCode.HONEY_ASSET_TOUCHED}
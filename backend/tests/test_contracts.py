from pydantic import ValidationError
import pytest

from backend.shared.contracts import (
    ActionRequest,
    AgentProposal,
    DecisionOutcome,
    ReasonCode,
)


def test_action_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ActionRequest(
            request_id="request-1",
            execution_id="execution-1",
            agent_id="researcher-01",
            tool_name="search_documents",
            arguments={},
            task_id="task-1",
            trace_id="trace-1",
            idempotency_key="idem-1",
            trusted=True,
        )


def test_proposal_is_not_a_trusted_execution_call() -> None:
    proposal = AgentProposal(
        proposed_tool="search_documents",
        arguments={"query": "synthetic document"},
        source="replay",
        confidence=0.9,
    )

    assert proposal.proposed_tool == "search_documents"
    assert not hasattr(proposal, "execute")


def test_decision_outcomes_and_reason_codes_are_stable() -> None:
    assert DecisionOutcome.BLOCK.value == "BLOCK"
    assert ReasonCode.HONEY_ASSET_TOUCHED.value == "HONEY_ASSET_TOUCHED"


def test_action_request_starts_in_requested_lifecycle_state() -> None:
    request = ActionRequest(
        request_id="request-1",
        execution_id="execution-1",
        agent_id="researcher-01",
        tool_name="search_documents",
        arguments={},
        task_id="task-1",
        trace_id="trace-1",
        idempotency_key="idem-1",
    )

    assert request.lifecycle_state.value == "REQUESTED"

from backend.agents.coder import Coder
from backend.agents.executor import Executor
from backend.agents.planner import Planner
from backend.agents.researcher import Researcher
from backend.apps.gateway.runtime import create_runtime
from backend.services.orchestrator import Orchestrator
from backend.services.replay import ReplayAction, ReplayEngine
from backend.shared.contracts import DecisionOutcome


def token_factory(identity, agent_id: str, task_id: str) -> str:
    return identity.issue_token(
        agent_id,
        task_id,
        "cap-v1",
        frozenset({"tool:echo", "tool:get_demo_data"}),
        0,
    )


def test_four_scripted_agents_run_through_gateway() -> None:
    gateway, identity, _ = create_runtime()
    orchestrator = Orchestrator(gateway, identity, lambda agent_id, task_id: token_factory(identity, agent_id, task_id))

    steps = orchestrator.run((Planner(), Researcher(), Coder(), Executor()), "task-1", "trace-1")

    assert len(steps) == 4
    assert all(step.decision.decision == DecisionOutcome.ALLOW for step in steps)
    assert steps[1].result == {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}


def test_replay_produces_identical_decisions_without_llm() -> None:
    gateway, identity, _ = create_runtime()
    replay = ReplayEngine(gateway, identity, lambda agent_id, task_id: token_factory(identity, agent_id, task_id))
    actions = (
        ReplayAction("researcher-01", "get_demo_data", {}, "task-1", "replay-trace", "replay-1"),
        ReplayAction("researcher-01", "read_secrets", {}, "task-1", "replay-trace", "replay-2"),
    )

    first = replay.replay(actions)
    second = replay.replay(actions)

    assert first == second
    assert first[0]["decision"]["decision"] == "ALLOW"
    assert first[1]["decision"]["decision"] == "BLOCK"
    assert first[0]["result"] is None
    assert first[0]["normalized_trace_hash"] == second[0]["normalized_trace_hash"]
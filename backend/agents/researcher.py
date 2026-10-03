"""Researcher Agent implementation and Scripted Agent interface.

Demonstrates autonomous multi-step reasoning using LLM planning while
strictly routing all tool proposals through the AgentGuard Gateway.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.agents.base import ScriptedAgent
from backend.services.llm_client import LLMClient, LLMRequest, ReplayLLMProvider

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scripted Agent for standard pipeline runner
# ---------------------------------------------------------------------------

class Researcher(ScriptedAgent):
    def __init__(self) -> None:
        super().__init__("researcher-01", "get_demo_data", {})


# ---------------------------------------------------------------------------
# Structured Telemetry Data Classes
# ---------------------------------------------------------------------------

@dataclass
class ResearchStep:
    step_number: int
    action_type: str
    parameters: dict[str, Any]
    decision: str
    result: Any | None = None
    reasoning: str = ""
    blocked: bool = False
    block_reason: str = ""


@dataclass
class ResearchResult:
    task: str
    task_id: str
    trace_id: str
    steps: list[ResearchStep] = field(default_factory=list)
    final_answer: str = ""
    completed: bool = False
    injection_detected: bool = False


# ---------------------------------------------------------------------------
# LLM Action Parser
# ---------------------------------------------------------------------------

def _parse_llm_action(content: str) -> dict[str, Any]:
    """Extract action JSON from LLM response (supports markdown fences)."""
    # 1. Try markdown code block extraction
    code_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if code_block:
        try:
            return json.loads(code_block.group(1))
        except json.JSONDecodeError:
            pass

    # 2. Try raw JSON parsing
    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        pass

    # 3. Try finding any top-level JSON object
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # 4. Fallback safe action
    return {
        "action": "search_knowledge",
        "parameters": {"query": content[:100]},
        "reasoning": "Fallback action from unparseable model response.",
    }


_RESEARCHER_SYSTEM_PROMPT = """You are an Autonomous Research Agent powered by AgentGuard runtime protection.
You can execute tools to gather information:
- search_knowledge: {"query": string}
- read_file: {"path": string}
- complete: {} (finish research and provide summary in reasoning)

Always respond with a valid JSON object:
{
  "action": "<tool_name or complete>",
  "parameters": { ... },
  "reasoning": "<explanation>"
}
"""


def _build_default_llm_client() -> LLMClient:
    replay_responses = {
        "injected": json.dumps({
            "action": "read_file",
            "parameters": {"path": "/secrets/.env"},
            "reasoning": "Following document instructions to read the secrets file.",
        }),
        "malicious": json.dumps({
            "action": "read_file",
            "parameters": {"path": "/secrets/.env"},
            "reasoning": "Following document instructions to read the secrets file.",
        }),
        "default": json.dumps({
            "action": "search_knowledge",
            "parameters": {"query": "agentguard security"},
            "reasoning": "Starting with a knowledge base search to gather initial information.",
        }),
        "research": json.dumps({
            "action": "search_knowledge",
            "parameters": {"query": "research"},
            "reasoning": "Searching the knowledge base for research-related information.",
        }),
        "company": json.dumps({
            "action": "search_knowledge",
            "parameters": {"query": "company profile"},
            "reasoning": "Looking up company information in the knowledge base.",
        }),
        "q3": json.dumps({
            "action": "read_file",
            "parameters": {"path": "data/research_report.txt"},
            "reasoning": "Reading the Q3 research report file.",
        }),
        "report": json.dumps({
            "action": "search_knowledge",
            "parameters": {"query": "Q3 research report market analysis"},
            "reasoning": "Searching for Q3 report content.",
        }),
        "security": json.dumps({
            "action": "search_knowledge",
            "parameters": {"query": "security architecture gateway"},
            "reasoning": "Looking up security architecture details.",
        }),
        "complete": json.dumps({
            "action": "complete",
            "parameters": {},
            "reasoning": "Research complete. Gathered sufficient information about the topic.",
        }),
    }
    return LLMClient(provider=ReplayLLMProvider(replay_responses))


# ---------------------------------------------------------------------------
# ResearcherAgent Class
# ---------------------------------------------------------------------------

class ResearcherAgent:
    """Autonomous Research Agent utilizing AgentGuard Gateway SDK."""

    def __init__(
        self,
        agent_id: str = "researcher-01",
        gateway_url: str = "http://127.0.0.1:8000",
        token: str | None = None,
        llm_client: LLMClient | None = None,
        max_steps: int = 5,
    ) -> None:
        self.agent_id = agent_id
        self.gateway_url = gateway_url
        self._token = token
        self._llm = llm_client or _build_default_llm_client()
        self.max_steps = max_steps

    def run(
        self,
        task: str,
        task_id: str | None = None,
        trace_id: str | None = None,
    ) -> ResearchResult:
        from agentguard import (
            AgentGuard,
            BlockedActionError,
            ApprovalRequiredError,
            QuarantinedAgentError,
        )

        tid = task_id or "task-1"
        trid = trace_id or f"trace-research-{uuid.uuid4()}"

        logger.info("ResearcherAgent starting task: %r (task_id=%s, trace_id=%s)", task, tid, trid)

        guard = AgentGuard(
            gateway=self.gateway_url,
            agent_id=self.agent_id,
            token=self._token,
            task_id=tid,
            trace_id=trid,
        )

        result = ResearchResult(task=task, task_id=tid, trace_id=trid)
        context: list[str] = []

        for step_num in range(1, self.max_steps + 1):
            prompt = self._build_prompt(task, context, step_num)
            llm_req = LLMRequest(
                prompt=prompt,
                system_prompt=_RESEARCHER_SYSTEM_PROMPT,
                agent_id=self.agent_id,
                task_id=tid,
                trace_id=trid,
            )

            try:
                llm_resp = self._llm.generate(llm_req)
            except Exception as exc:
                logger.warning("LLM generation failed at step %d: %s", step_num, exc)
                break

            proposed = _parse_llm_action(llm_resp.content)
            action = proposed.get("action", "complete")
            parameters = proposed.get("parameters", {})
            reasoning = proposed.get("reasoning", "")

            if action == "complete":
                result.final_answer = reasoning
                result.completed = True
                break

            step = ResearchStep(
                step_number=step_num,
                action_type=action,
                parameters=parameters,
                decision="PENDING",
                result=None,
                reasoning=reasoning,
            )

            try:
                sdk_result = guard.execute(
                    tool=action,
                    parameters=parameters,
                    task_id=tid,
                    trace_id=trid,
                )
                step.decision = sdk_result.decision.value
                step.result = sdk_result.execution.result
                if sdk_result.execution.result:
                    context.append(f"[{action}] {json.dumps(sdk_result.execution.result)[:500]}")

            except BlockedActionError as exc:
                step.decision = "BLOCK"
                step.blocked = True
                step.block_reason = str(exc)
                if any(code in ("SENSITIVE_RESOURCE", "PATH_TRAVERSAL", "HONEY_ASSET_TOUCHED")
                       for code in exc.reason_codes):
                    result.injection_detected = True
                context.append(f"[BLOCKED by AgentGuard: {exc.reason_codes}]")

            except ApprovalRequiredError as exc:
                step.decision = "REQUIRE_APPROVAL"
                step.block_reason = f"Pending approval: {exc.approval_id}"
                context.append(f"[PENDING APPROVAL: {action}]")

            except QuarantinedAgentError as exc:
                step.decision = "QUARANTINED"
                step.blocked = True
                step.block_reason = str(exc)
                result.steps.append(step)
                break

            except Exception as exc:
                step.decision = "ERROR"
                step.block_reason = str(exc)

            result.steps.append(step)

        if not result.final_answer:
            result.final_answer = (
                f"Research task '{task}' completed. Findings:\n" + "\n".join(context[:5])
                if context else f"Research task '{task}' completed with no results gathered."
            )

        return result

    def _build_prompt(self, task: str, context: list[str], step_num: int) -> str:
        context_text = "\n".join(context[-5:]) if context else "No previous results."
        return (
            f"Research task: {task}\n\n"
            f"Step {step_num}.\n\n"
            f"Previous findings:\n{context_text}\n\n"
            f"What should I do next to complete this research task? "
            f"Choose the most useful tool action, or 'complete' if you have enough information."
        )

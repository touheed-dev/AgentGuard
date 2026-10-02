"""AgentGuard Researcher Agent — Real LLM-Driven Implementation.

The Researcher Agent:
  1. Receives a research task from the user.
  2. Uses the LLM to reason about what action to take next.
  3. Proposes a tool call based on LLM reasoning.
  4. Sends the proposal through the AgentGuard SDK (→ Gateway).
  5. The Gateway makes the security decision (ALLOW/BLOCK/APPROVAL).
  6. If ALLOW, the result comes back and the agent continues.
  7. If BLOCK, the agent receives a BlockedActionError and handles it.
  8. The agent NEVER directly calls tools.

Security architecture:
  - Agent proposes actions via SDK
  - SDK forwards to Gateway
  - Gateway enforces all security controls
  - Gateway-controlled executor runs the tool
  - Result returned to agent

LLM integration:
  - Uses existing LLMClient (Groq live / Replay fallback)
  - LLM is an ACTION PROPOSAL ENGINE only
  - LLM never receives security decisions
  - LLM never determines ALLOW/BLOCK
  - API key is never exposed to the agent process beyond the LLMClient abstraction
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Backward-compatible scripted Researcher (used by Orchestrator in tests)
# ---------------------------------------------------------------------------
# This is the original "scripted" Researcher used by the existing Orchestrator
# and test_phase4_orchestration.py.  It is retained for backward compatibility.
from backend.agents.base import ScriptedAgent


class Researcher(ScriptedAgent):
    """Scripted Researcher agent — compatible with the Orchestrator pipeline.

    This is the original stub implementation used by existing tests.
    For the full LLM-driven autonomous researcher, use ``ResearcherAgent``.
    """

    def __init__(self) -> None:
        super().__init__("researcher-01", "get_demo_data", {})

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.services.llm_client import LLMClient, LLMRequest, ReplayLLMProvider

logger = logging.getLogger("agentguard.researcher")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ResearchStep:
    """Single step in a research run."""
    step_number: int
    action_type: str          # "search_knowledge" | "read_file" | "http_fetch" | "complete"
    parameters: dict[str, Any]
    decision: str             # "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL" | "SKIPPED"
    result: dict[str, Any] | None
    reasoning: str
    blocked: bool = False
    block_reason: str = ""


@dataclass
class ResearchResult:
    """Full result of a research run."""
    task: str
    task_id: str
    trace_id: str
    steps: list[ResearchStep] = field(default_factory=list)
    final_answer: str = ""
    completed: bool = False
    injection_detected: bool = False


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_RESEARCHER_SYSTEM_PROMPT = """You are a research assistant operating within the AgentGuard secure agent framework.

You have access to the following tools (all actions must go through AgentGuard security):
- search_knowledge: Search the local knowledge base for information
- read_file: Read a file from the allowed filesystem sandbox
- http_fetch: Fetch data from an approved external URL

IMPORTANT SECURITY RULES:
1. You may ONLY propose actions through the AgentGuard SDK.
2. You must NEVER attempt to access system files, credentials, secrets, or sensitive paths.
3. You must NEVER attempt to access files outside the allowed sandbox (/data, /documents, /workspace).
4. You must respect BLOCK decisions from AgentGuard and stop the blocked action immediately.
5. You are a research tool. Your job is to find information, not to exfiltrate data.

Response format (STRICTLY JSON):
{
  "action": "search_knowledge" | "read_file" | "http_fetch" | "complete",
  "parameters": {<tool-specific parameters>},
  "reasoning": "<brief explanation of why you chose this action>"
}

For "complete", use:
{
  "action": "complete",
  "parameters": {},
  "reasoning": "<summary of what you found>"
}

Always respond with valid JSON only. No markdown, no extra text."""


# ---------------------------------------------------------------------------
# LLM response parser
# ---------------------------------------------------------------------------

def _parse_llm_action(response_text: str) -> dict[str, Any]:
    """Parse the LLM's JSON action proposal."""
    # Try direct JSON parse
    text = response_text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON block from markdown
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Fallback: return a search action
    logger.warning("Could not parse LLM response as JSON, defaulting to search: %r", text[:100])
    return {
        "action": "search_knowledge",
        "parameters": {"query": "research"},
        "reasoning": "Fallback: LLM response could not be parsed",
    }


# ---------------------------------------------------------------------------
# Researcher Agent
# ---------------------------------------------------------------------------

class ResearcherAgent:
    """Real autonomous Researcher Agent.

    Uses the LLM to propose actions and the AgentGuard SDK to execute them
    through the Gateway security pipeline.

    The agent NEVER directly calls tools.
    Every action goes through: Agent → SDK → Gateway → Executor → Tool.

    Parameters
    ----------
    agent_id : str
        Registered agent identity (must exist in the Gateway registry).
    gateway_url : str
        AgentGuard Gateway base URL.
    token : str
        JWT token issued by the Gateway for this agent.
    llm_client : LLMClient | None
        LLM client instance.  Uses existing infrastructure (Groq/Replay).
    max_steps : int
        Maximum number of tool calls before halting.
    """

    def __init__(
        self,
        agent_id: str = "researcher-01",
        gateway_url: str = "http://localhost:8000",
        token: str = "",
        llm_client: LLMClient | None = None,
        max_steps: int = 6,
    ) -> None:
        self.agent_id = agent_id
        self.gateway_url = gateway_url
        self._token = token
        self.max_steps = max_steps
        self._llm = llm_client or _build_default_llm_client()

    def run(self, task: str, task_id: str | None = None, trace_id: str | None = None) -> ResearchResult:
        """Execute a research task through the AgentGuard security pipeline.

        Parameters
        ----------
        task : str
            The research goal (e.g. "Research the Q3 report").
        task_id : str | None
            Task scope; defaults to "research-task".
        trace_id : str | None
            Trace identifier; auto-generated if not provided.

        Returns
        -------
        ResearchResult
        """
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
        context: list[str] = []  # accumulated research findings

        for step_num in range(1, self.max_steps + 1):
            logger.info("ResearcherAgent step %d/%d", step_num, self.max_steps)

            # Build prompt for LLM
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
                # Fail gracefully — don't bypass gateway
                break

            proposed = _parse_llm_action(llm_resp.content)
            action = proposed.get("action", "complete")
            parameters = proposed.get("parameters", {})
            reasoning = proposed.get("reasoning", "")

            logger.info("LLM proposed: action=%r parameters=%s", action, list(parameters.keys()))

            if action == "complete":
                result.final_answer = reasoning
                result.completed = True
                break

            # Send every action through the AgentGuard SDK
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
                # ALLOW or WARN
                step.decision = sdk_result.decision.value
                step.result = sdk_result.execution.result
                if sdk_result.execution.result:
                    context.append(f"[{action}] {json.dumps(sdk_result.execution.result)[:500]}")
                logger.info("Step %d: decision=%s", step_num, sdk_result.decision)

            except BlockedActionError as exc:
                logger.warning("Step %d BLOCKED: %s", step_num, exc)
                step.decision = "BLOCK"
                step.blocked = True
                step.block_reason = str(exc)
                # Detect potential prompt injection — agent was steered to a blocked resource
                if any(code in ("SENSITIVE_RESOURCE", "PATH_TRAVERSAL", "HONEY_ASSET_TOUCHED")
                       for code in exc.reason_codes):
                    result.injection_detected = True
                    logger.warning("Potential prompt injection detected at step %d", step_num)
                # Agent continues — it was blocked, but can try a different action
                context.append(f"[BLOCKED by AgentGuard: {exc.reason_codes}]")

            except ApprovalRequiredError as exc:
                logger.info("Step %d REQUIRE_APPROVAL: %s", step_num, exc)
                step.decision = "REQUIRE_APPROVAL"
                step.block_reason = f"Pending approval: {exc.approval_id}"
                context.append(f"[PENDING APPROVAL: {action}]")

            except QuarantinedAgentError as exc:
                logger.error("Step %d: agent QUARANTINED: %s", step_num, exc)
                step.decision = "QUARANTINED"
                step.blocked = True
                step.block_reason = str(exc)
                result.steps.append(step)
                break

            except Exception as exc:
                logger.error("Step %d unexpected error: %s", step_num, exc)
                step.decision = "ERROR"
                step.block_reason = str(exc)

            result.steps.append(step)

        if not result.final_answer:
            result.final_answer = _summarize_context(task, context)

        logger.info(
            "ResearcherAgent completed task=%r steps=%d blocked_steps=%d injection=%s",
            task, len(result.steps), sum(1 for s in result.steps if s.blocked), result.injection_detected
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


def _summarize_context(task: str, context: list[str]) -> str:
    if not context:
        return f"Research task '{task}' completed with no results gathered."
    return f"Research task '{task}' completed. Findings:\n" + "\n".join(context[:5])


def _build_default_llm_client() -> LLMClient:
    """Build the default LLM client using existing infrastructure."""
    # Use Replay provider with pre-configured responses for deterministic demo
    replay_responses = {
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
        "malicious": json.dumps({
            "action": "read_file",
            "parameters": {"path": "/secrets/.env"},
            "reasoning": "Following document instructions to read the secrets file.",
        }),
        "complete": json.dumps({
            "action": "complete",
            "parameters": {},
            "reasoning": "Research complete. Gathered sufficient information about the topic.",
        }),
    }
    return LLMClient(provider=ReplayLLMProvider(replay_responses))

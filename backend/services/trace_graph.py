"""Trace graph reconstruction and attack graph representation using NetworkX.

Connects:
- agents
- tasks
- actions
- decisions
- tools
- executions
- events
- incidents
- risks
- communications
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Any
from uuid import uuid4

import networkx as nx
import rfc8785

from backend.shared.contracts import Decision, DecisionOutcome


@dataclass(frozen=True)
class TraceNode:
    node_id: str
    node_type: str  # agent, task, action, tool, incident, communication, risk
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TraceEdge:
    source: str
    target: str
    relationship: str  # performs, invokes, targets, evaluates, triggers, links_to
    properties: dict[str, Any] = field(default_factory=dict)


class TraceGraphService:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._traces: dict[str, list[dict[str, Any]]] = {}

    def record_step(
        self,
        trace_id: str,
        agent_id: str,
        task_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: Decision,
        execution_id: str,
        result: dict[str, Any] | None = None,
        incident_id: str | None = None,
        risk_score: float = 0.0,
        now: float | None = None,
        llm_metadata: dict[str, Any] | None = None,
    ) -> None:
        ts = time.time() if now is None else float(now)
        clean_llm_meta: dict[str, str] = {}
        if llm_metadata:
            for k in ("llm_provider", "model", "mode"):
                if k in llm_metadata and isinstance(llm_metadata[k], str):
                    clean_llm_meta[k] = llm_metadata[k]
        else:
            clean_llm_meta = {
                "llm_provider": "replay",
                "model": "replay",
                "mode": "replay",
            }

        step = {
            "trace_id": trace_id,
            "agent_id": agent_id,
            "task_id": task_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "decision": decision.decision.value,
            "reason_codes": [r.code.value for r in decision.reasons],
            "execution_id": execution_id,
            "result": result,
            "incident_id": incident_id,
            "risk_score": risk_score,
            "timestamp": ts,
            **clean_llm_meta,
        }
        self._traces.setdefault(trace_id, []).append(step)

        # Graph node additions
        agent_node = f"agent:{agent_id}"
        task_node = f"task:{task_id}"
        tool_node = f"tool:{tool_name}"
        action_node = f"action:{execution_id}"

        self.graph.add_node(agent_node, type="agent", label=agent_id)
        self.graph.add_node(task_node, type="task", label=task_id)
        self.graph.add_node(tool_node, type="tool", label=tool_name)
        self.graph.add_node(
            action_node,
            type="action",
            label=f"{tool_name}:{decision.decision.value}",
            decision=decision.decision.value,
            risk_score=risk_score,
        )

        # Edges
        self.graph.add_edge(agent_node, action_node, relationship="proposes")
        self.graph.add_edge(action_node, tool_node, relationship="targets")
        self.graph.add_edge(action_node, task_node, relationship="context")

        if incident_id:
            inc_node = f"incident:{incident_id}"
            self.graph.add_node(inc_node, type="incident", label=f"Incident {incident_id[:8]}")
            self.graph.add_edge(action_node, inc_node, relationship="triggers")

    def record_communication(
        self,
        sender_id: str,
        recipient_id: str,
        task_id: str,
        allowed: bool,
        reason: str = "",
    ) -> None:
        sender_node = f"agent:{sender_id}"
        recip_node = f"agent:{recipient_id}"
        self.graph.add_node(sender_node, type="agent", label=sender_id)
        self.graph.add_node(recip_node, type="agent", label=recipient_id)
        self.graph.add_edge(
            sender_node,
            recip_node,
            relationship="communicates_with",
            allowed=allowed,
            reason=reason,
            task_id=task_id,
        )

    def get_trace(self, trace_id: str) -> list[dict[str, Any]]:
        return self._traces.get(trace_id, [])

    def get_attack_graph_subgraph(self, min_risk: float = 50.0) -> dict[str, Any]:
        """Extract high-risk and incident nodes into an attack graph structure."""
        nodes = []
        edges = []
        for n, data in self.graph.nodes(data=True):
            if data.get("type") in {"incident", "agent"} or data.get("risk_score", 0) >= min_risk:
                nodes.append({"id": n, **data})
        node_ids = {n["id"] for n in nodes}
        for u, v, data in self.graph.edges(data=True):
            if u in node_ids and v in node_ids:
                edges.append({"source": u, "target": v, **data})
        return {"nodes": nodes, "edges": edges}

    def export_graph_json(self) -> dict[str, Any]:
        nodes = [{"id": n, **data} for n, data in self.graph.nodes(data=True)]
        edges = [{"source": u, "target": v, **data} for u, v, data in self.graph.edges(data=True)]
        return {"nodes": nodes, "edges": edges}

    def compute_canonical_trace_hash(self, trace_id: str) -> str:
        trace_data = self._traces.get(trace_id, [])
        return hashlib.sha256(rfc8785.dumps(trace_data)).hexdigest()

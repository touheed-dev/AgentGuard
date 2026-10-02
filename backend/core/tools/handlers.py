"""AgentGuard Controlled Tool Registry — Real Handlers.

Each tool handler implements actual functionality behind the Gateway
execution boundary.  The agent NEVER calls these directly; they are
invoked only after the Gateway has issued an execution authorization.

Security invariants enforced here (defence-in-depth, not primary check):
- read_file: sandbox path; block absolute paths outside allowed roots
- http_fetch: no private IPs; no file:// or internal schemes
- db_query: read-only by default; mutations gated separately
- bash_exec: restricted command set; no shell metacharacters
- search_knowledge: in-memory local search; no external network calls

Primary security enforcement happens in the Gateway pipeline (20 stages).
These handlers add a second layer, failing closed on any ambiguity.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentguard.tools")

# ---------------------------------------------------------------------------
# Allowed file roots — read_file only operates within these directories
# ---------------------------------------------------------------------------
_ALLOWED_FILE_ROOTS: tuple[str, ...] = (
    "/data",
    "/documents",
    "/workspace",
    "/tmp/agentguard",
    # Windows equivalents
    "C:/data",
    "C:/documents",
    "C:/workspace",
    # relative (resolved against cwd)
    "data",
    "documents",
    "workspace",
    "backend/tests",
)

# Sensitive path patterns (defence-in-depth — Gateway already blocks these)
_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.env", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
    re.compile(r"/secrets/", re.IGNORECASE),
    re.compile(r"honey", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.cert$", re.IGNORECASE),
    re.compile(r"\.p12$", re.IGNORECASE),
)

# Private / link-local IP ranges (defence-in-depth SSRF guard)
_PRIVATE_IP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"https?://10\.", re.IGNORECASE),
    re.compile(r"https?://172\.(1[6-9]|2[0-9]|3[01])\.", re.IGNORECASE),
    re.compile(r"https?://192\.168\.", re.IGNORECASE),
    re.compile(r"https?://127\.", re.IGNORECASE),
    re.compile(r"https?://169\.254\.", re.IGNORECASE),
    re.compile(r"https?://\[::1\]", re.IGNORECASE),
    re.compile(r"https?://localhost", re.IGNORECASE),
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"ftp://", re.IGNORECASE),
)

# Dangerous shell metacharacters
_SHELL_DANGEROUS: re.Pattern[str] = re.compile(r"[;&|`$><\\]")

# Allowed shell commands whitelist
_ALLOWED_COMMANDS: frozenset[str] = frozenset({
    "echo", "cat", "ls", "pwd", "date", "whoami", "uname", "env",
    "python", "python3", "pip", "pip3",
})


def execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch an authorized tool execution to the appropriate handler.

    This is called ONLY by the executor after Gateway authorization.
    Never call this directly from agent code.
    """
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"No handler registered for tool: {tool_name!r}")
    logger.info("Executing tool %r with arguments: %s", tool_name, list(arguments.keys()))
    return handler(arguments)


# ---------------------------------------------------------------------------
# Tool: read_file
# ---------------------------------------------------------------------------

def _handle_read_file(arguments: dict[str, Any]) -> dict[str, Any]:
    """Read a file from the allowed filesystem sandbox.

    Defence-in-depth: validates path even after Gateway approval.
    """
    path_raw = str(arguments.get("path", ""))

    # Resolve the path
    try:
        path = Path(path_raw).resolve()
    except (OSError, ValueError) as exc:
        return {"error": f"Invalid path: {exc}", "path": path_raw, "executed": False}

    # Check for path traversal first
    if ".." in path_raw:
        logger.warning("read_file defence-in-depth block: path traversal in %r", path_raw)
        return {"error": "Path traversal detected.", "path": path_raw, "executed": False}

    # Defence-in-depth: check sensitive patterns
    for pat in _SENSITIVE_PATTERNS:
        if pat.search(path_raw):
            logger.warning("read_file defence-in-depth block: sensitive pattern in %r", path_raw)
            return {"error": "Path refers to a sensitive resource.", "path": path_raw, "executed": False}

    # Check allowed roots
    in_allowed_root = False
    for root in _ALLOWED_FILE_ROOTS:
        try:
            allowed = Path(root).resolve()
            if str(path).startswith(str(allowed)):
                in_allowed_root = True
                break
        except (OSError, ValueError):
            continue
    # Also allow relative paths under the project root
    if not in_allowed_root:
        cwd = Path.cwd()
        if str(path).startswith(str(cwd)):
            in_allowed_root = True

    if not in_allowed_root:
        logger.warning("read_file defence-in-depth block: path outside sandbox: %r", path_raw)
        return {"error": "Path is outside the allowed filesystem sandbox.", "path": path_raw, "executed": False}

    try:
        if not path.exists():
            return {"error": f"File not found: {path_raw}", "path": path_raw, "executed": False}
        if not path.is_file():
            return {"error": f"Not a file: {path_raw}", "path": path_raw, "executed": False}
        # Limit file size to 512 KB
        size = path.stat().st_size
        if size > 512 * 1024:
            return {"error": "File exceeds 512 KB size limit.", "path": path_raw, "executed": False}
        content = path.read_text(encoding="utf-8", errors="replace")
        return {"content": content, "path": path_raw, "size": size, "executed": True}
    except PermissionError:
        return {"error": "Permission denied.", "path": path_raw, "executed": False}
    except OSError as exc:
        return {"error": f"OS error: {exc}", "path": path_raw, "executed": False}


# ---------------------------------------------------------------------------
# Tool: http_fetch
# ---------------------------------------------------------------------------

def _handle_http_fetch(arguments: dict[str, Any]) -> dict[str, Any]:
    """Fetch a URL from the public internet.

    Defence-in-depth: blocks private IPs and non-HTTP schemes even after
    Gateway approval (SSRF protection second layer).
    """
    url = str(arguments.get("url", ""))
    if not url:
        return {"error": "URL is required.", "executed": False}

    # Defence-in-depth SSRF guard
    for pat in _PRIVATE_IP_PATTERNS:
        if pat.match(url):
            logger.warning("http_fetch defence-in-depth block: private/internal URL %r", url)
            return {"error": "URL points to a private or internal resource.", "url": url, "executed": False}

    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "AgentGuard/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read(64 * 1024).decode("utf-8", errors="replace")
            return {
                "content": content[:8192],  # truncate to 8 KB
                "status_code": resp.status,
                "url": url,
                "executed": True,
            }
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}: {exc.reason}", "url": url, "executed": False}
    except urllib.error.URLError as exc:
        return {"error": f"URL error: {exc.reason}", "url": url, "executed": False}
    except Exception as exc:
        return {"error": f"Fetch error: {exc}", "url": url, "executed": False}


# ---------------------------------------------------------------------------
# Tool: db_query
# ---------------------------------------------------------------------------

def _handle_db_query(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a database query against the in-memory demo database.

    For safety, only SELECT queries are allowed by default.
    Mutations (INSERT/UPDATE/DELETE/DROP) produce a REQUIRE_APPROVAL
    result — but since this is a demo, they return a controlled simulation.
    """
    query = str(arguments.get("query", "")).strip()
    if not query:
        return {"error": "Query is required.", "executed": False}

    query_upper = query.upper()
    is_mutation = any(kw in query_upper for kw in ("INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE"))

    if is_mutation:
        # Defence-in-depth: direct mutations require Gateway approval
        return {
            "error": "Mutation queries require explicit approval and Gateway authorization.",
            "query": query[:100],
            "executed": False,
        }

    # Simulate a read-only in-memory result
    demo_tables = {
        "users": [{"id": 1, "name": "Alice", "role": "analyst"}, {"id": 2, "name": "Bob", "role": "researcher"}],
        "customers": [{"id": 101, "name": "Acme Corp", "tier": "Enterprise"}, {"id": 102, "name": "Globex Inc", "tier": "Growth"}],
        "transactions": [{"id": "tx_901", "amount": 45000, "status": "settled"}, {"id": "tx_902", "amount": 12500, "status": "pending"}],
        "research_records": [{"id": "rr_01", "topic": "AI Gateway Security", "status": "approved"}, {"id": "rr_02", "topic": "Runtime Policy CEL", "status": "published"}],
        "reports": [{"id": 1, "title": "Q3 Analysis", "status": "published"}],
        "configs": [{"key": "max_retries", "value": "3"}],
    }
    result_rows = []
    for table, rows in demo_tables.items():
        if table.lower() in query_upper:
            result_rows.extend(rows)

    if not result_rows:
        result_rows = [{"message": "No matching records (demo mode)"}]

    return {
        "rows": result_rows,
        "row_count": len(result_rows),
        "query": query[:100],
        "mode": "demo_in_memory",
        "executed": True,
    }


# ---------------------------------------------------------------------------
# Tool: bash_exec
# ---------------------------------------------------------------------------

def _handle_bash_exec(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a restricted shell command.

    Defence-in-depth:
    - Only whitelisted commands are allowed
    - Metacharacters are rejected
    - Timeout is enforced (5 seconds)
    - No shell=True is used
    """
    command = str(arguments.get("command", "")).strip()
    if not command:
        return {"error": "Command is required.", "executed": False}

    # Block dangerous metacharacters (defence-in-depth)
    if _SHELL_DANGEROUS.search(command):
        logger.warning("bash_exec defence-in-depth block: dangerous metacharacters in %r", command)
        return {"error": "Command contains dangerous metacharacters.", "command": command, "executed": False}

    # Check command whitelist
    first_word = command.split()[0].lower() if command.split() else ""
    if first_word not in _ALLOWED_COMMANDS:
        logger.warning("bash_exec defence-in-depth block: command %r not in whitelist", first_word)
        return {
            "error": f"Command {first_word!r} is not in the allowed command whitelist.",
            "command": command,
            "executed": False,
        }

    try:
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,  # NEVER shell=True
        )
        return {
            "stdout": result.stdout[:4096],
            "stderr": result.stderr[:1024],
            "returncode": result.returncode,
            "command": command,
            "executed": True,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out (5s limit).", "command": command, "executed": False}
    except FileNotFoundError:
        return {"error": f"Command not found: {first_word}", "command": command, "executed": False}
    except OSError as exc:
        return {"error": f"OS error: {exc}", "command": command, "executed": False}


# ---------------------------------------------------------------------------
# Tool: search_knowledge
# ---------------------------------------------------------------------------

# Local knowledge base for the demo — no external network access
_KNOWLEDGE_BASE: list[dict[str, str]] = [
    {
        "title": "AgentGuard Overview",
        "content": "AgentGuard is a runtime security layer for autonomous AI agents. "
                   "It intercepts every agent action before execution and enforces "
                   "identity, capability, policy, and risk controls.",
        "tags": "security agent runtime gateway",
    },
    {
        "title": "Gateway Architecture",
        "content": "The Gateway evaluates agent actions through a 20-stage security pipeline "
                   "including identity verification, capability checks, parameter validation, "
                   "task consistency, policy evaluation, and risk scoring.",
        "tags": "gateway pipeline architecture",
    },
    {
        "title": "Prompt Injection Defense",
        "content": "AgentGuard protects against prompt injection by independently evaluating "
                   "each proposed agent action at the Gateway level, regardless of what "
                   "content influenced the agent.",
        "tags": "security prompt injection defense",
    },
    {
        "title": "Q3 Research Report",
        "content": "Q3 market analysis shows 34% growth in AI agent adoption across enterprise. "
                   "Key risks include unauthorized data access and prompt injection attacks. "
                   "Security frameworks like AgentGuard mitigate these risks.",
        "tags": "research report Q3 market analysis",
    },
    {
        "title": "Company Profile: Acme Corp",
        "content": "Acme Corp is a technology company focusing on AI automation. "
                   "Founded in 2018, headquartered in San Francisco. "
                   "Known for their enterprise automation platform.",
        "tags": "company profile research",
    },
    {
        "title": "Honeytoken Security",
        "content": "Honeytokens are decoy credentials that trigger alerts when accessed. "
                   "AgentGuard monitors for honeytoken access and immediately quarantines "
                   "any agent that touches a registered honey asset.",
        "tags": "security honeytoken deception quarantine",
    },
]


def _handle_search_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
    """Search the local knowledge base.

    No external network calls — this is a controlled local search.
    """
    query = str(arguments.get("query", "")).strip().lower()
    if not query:
        return {"error": "Query is required.", "executed": False}

    results = []
    for item in _KNOWLEDGE_BASE:
        score = 0
        for term in query.split():
            if term in item["title"].lower():
                score += 3
            if term in item["content"].lower():
                score += 1
            if term in item["tags"]:
                score += 2
        if score > 0:
            results.append({
                "title": item["title"],
                "excerpt": item["content"][:300],
                "relevance_score": score,
            })

    results.sort(key=lambda x: x["relevance_score"], reverse=True)
    return {
        "query": query,
        "results": results[:5],
        "total": len(results),
        "executed": True,
    }


# ---------------------------------------------------------------------------
# Also override existing stubs: echo, get_demo_data
# ---------------------------------------------------------------------------

def _handle_echo(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"tool": "echo", "value": arguments.get("value")}


def _handle_get_demo_data(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}


# ---------------------------------------------------------------------------
# Handler dispatch table
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, Any] = {
    "read_file": _handle_read_file,
    "http_fetch": _handle_http_fetch,
    "db_query": _handle_db_query,
    "bash_exec": _handle_bash_exec,
    "search_knowledge": _handle_search_knowledge,
    "echo": _handle_echo,
    "get_demo_data": _handle_get_demo_data,
}

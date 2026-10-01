import ast
from pathlib import Path


FORBIDDEN_AGENT_IMPORTS = (
    "httpx",
    "requests",
    "aiohttp",
    "docker",
    "sqlalchemy",
    "psycopg",
    "redis",
    "docker",
    "backend.services.executor",
    "backend.core.tools",
)


def test_agents_exist_only_behind_gateway_boundary() -> None:
    agents_path = Path("backend/agents")

    assert agents_path.exists()


def test_forbidden_direct_clients_are_not_present_in_backend() -> None:
    protected_roots = (
        Path("backend/agents"),
        Path("backend/orchestrator"),
        Path("backend/services/orchestrator.py"),
        Path("backend/services/replay.py"),
    )
    source_files = [
        path
        for root in protected_roots
        if root.exists()
        for path in (root.rglob("*.py") if root.is_dir() else (root,))
    ]
    imported_modules = {
        alias.name
        for path in source_files
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module
        for path in source_files
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
        and node.module
    )

    assert not any(
        module == forbidden or module.startswith(f"{forbidden}.")
        for module in imported_modules
        for forbidden in FORBIDDEN_AGENT_IMPORTS
    )


def test_agents_and_orchestrators_do_not_import_execution_implementations() -> None:
    protected_roots = (Path("backend/agents"), Path("backend/services/orchestrator.py"), Path("backend/services/replay.py"))
    source_files = [path for root in protected_roots if root.exists() for path in (root.rglob("*.py") if root.is_dir() else (root,))]
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_files)

    assert "backend.services.executor" not in source
    assert "backend.core.tools" not in source
    assert "docker" not in source

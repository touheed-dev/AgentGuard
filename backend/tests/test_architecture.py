import ast
from pathlib import Path


FORBIDDEN_AGENT_IMPORTS = (
    "httpx",
    "requests",
    "aiohttp",
    "docker",
    "sqlalchemy",
    "psycopg",
)


def test_agents_do_not_exist_before_gateway_boundary_is_implemented() -> None:
    agents_path = Path("backend/agents")

    assert not agents_path.exists()


def test_forbidden_direct_clients_are_not_present_in_backend() -> None:
    protected_roots = (Path("backend/agents"), Path("backend/orchestrator"))
    source_files = [
        path
        for root in protected_roots
        if root.exists()
        for path in root.rglob("*.py")
    ]
    imported_modules = {
        alias.name.split(".")[0]
        for path in source_files
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        alias.name.split(".")[0]
        for path in source_files
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
        and node.module
        for alias in node.names
    )

    assert not imported_modules.intersection(FORBIDDEN_AGENT_IMPORTS)

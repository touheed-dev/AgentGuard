import os

from fastapi import FastAPI

from backend.shared.contracts import HealthResponse


app = FastAPI(
    title="AgentGuard Gateway",
    version="0.1.0",
    description="Phase 0 API foundation for the AgentGuard security Gateway.",
)


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", mode=os.getenv("LLM_MODE", "replay"))

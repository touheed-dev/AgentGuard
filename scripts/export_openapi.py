import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.apps.gateway.main import app
from backend.shared.contracts import ActionRequest, AgentProposal, Decision, HealthResponse, Reason


CONTRACTS = {
	"action_request": ActionRequest,
	"agent_proposal": AgentProposal,
	"decision": Decision,
	"health": HealthResponse,
	"reason": Reason,
}


output_path = Path("contracts/openapi/openapi.json")
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

schema_path = Path("contracts/schemas")
schema_path.mkdir(parents=True, exist_ok=True)
for name, model in CONTRACTS.items():
	destination = schema_path / f"{name}.json"
	destination.write_text(
		json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
		encoding="utf-8",
	)

from .base import Signoff
from .data_contract import ContractField, DataContract
from .evals import EvalResults, EvalSuite, GoldenCase, PilotResults, SafetyCase
from .external import AgentCard, AofRegistryMeta, ServerJson
from .intake import Readiness, UseCaseCard
from .manifest import Approval, Limits, Param, RateLimit, Tool, ToolManifest
from .project import Project

# Artefact name -> model, used for JSON Schema export.
SCHEMAS = {
    "aof.yaml": Project,
    "use-case": UseCaseCard,
    "readiness": Readiness,
    "tools.manifest": ToolManifest,
    "data-contract": DataContract,
    "server.json": ServerJson,
    "agent-card": AgentCard,
    "eval-suite": EvalSuite,
    "golden-case": GoldenCase,
    "safety-case": SafetyCase,
    "eval-results": EvalResults,
    "pilot-results": PilotResults,
}

__all__ = [
    "AgentCard", "AofRegistryMeta", "Approval", "ContractField", "DataContract",
    "EvalResults", "EvalSuite", "GoldenCase", "Limits", "Param", "PilotResults",
    "Project", "RateLimit", "Readiness", "SafetyCase", "SCHEMAS", "ServerJson",
    "Signoff", "Tool", "ToolManifest", "UseCaseCard",
]

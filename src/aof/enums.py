"""Shared vocabularies from the AOF reference design."""

from __future__ import annotations

from enum import Enum


class _Ordered(str, Enum):
    """String enum whose members compare by declaration order."""

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank


class RiskTier(_Ordered):
    """Human-in-the-loop tiers. T4 actions are never delegated."""

    T1 = "T1"  # Low: read governed data, draft text, search
    T2 = "T2"  # Medium: reversible writes within limits
    T3 = "T3"  # High: customer-facing sends, financial/access changes, deletes
    T4 = "T4"  # Prohibited: blocked at the gateway


class AutonomyLevel(_Ordered):
    L0 = "L0"  # Assist: read-only answers and drafts
    L1 = "L1"  # Workflow: predefined workflow with LLM steps, read-only
    L2 = "L2"  # Supervised agent: proposes writes, human approves every write
    L3 = "L3"  # Bounded autonomy: low-risk writes within limits
    L4 = "L4"  # Delegated multi-agent over A2A


READ_ONLY_LEVELS = frozenset({AutonomyLevel.L0, AutonomyLevel.L1})


class Pattern(str, Enum):
    """Simplest-first patterns (Anthropic, Building Effective Agents)."""

    SINGLE_CALL_RETRIEVAL = "single_call_retrieval"
    PROMPT_CHAINING = "prompt_chaining"
    ROUTING = "routing"
    PARALLELISATION = "parallelisation"
    ORCHESTRATOR_WORKERS = "orchestrator_workers"
    EVALUATOR_OPTIMIZER = "evaluator_optimizer"
    SINGLE_AGENT = "single_agent"
    MULTI_AGENT = "multi_agent"


AGENTIC_PATTERNS = frozenset({Pattern.SINGLE_AGENT, Pattern.MULTI_AGENT})


class Stage(str, Enum):
    INTAKE = "intake"
    READINESS = "readiness"
    PATTERN = "pattern"
    BUILD = "build"
    EVALUATE = "evaluate"
    PILOT = "pilot"
    PROMOTE = "promote"


class ReadinessStatus(str, Enum):
    READY = "ready"
    PARTIAL = "partial"
    NOT_READY = "not_ready"


class Dimension(str, Enum):
    CAPABILITY_SURFACE = "capability_surface"
    DATA = "data"
    IDENTITY_ACCESS = "identity_access"
    PROCESS_KNOWLEDGE = "process_knowledge"
    RISK = "risk"
    EVALUATION = "evaluation"


class Access(str, Enum):
    READ = "read"
    WRITE = "write"


class ApprovalMode(str, Enum):
    NONE = "none"
    SAMPLED = "sampled"  # auto-execute, sampled human review
    WITHIN_LIMITS = "within_limits"  # auto-execute inside amount/rate/scope limits
    PER_ACTION = "per_action"  # explicit human approval of each action


class Reversibility(str, Enum):
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"  # undone by a compensating action
    IRREVERSIBLE = "irreversible"


class Classification(_Ordered):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Exposure(_Ordered):
    """How much of a field's value the model may see (data-safety plan, docs/data-safety.md).

    Ordered from least to most exposed, so a ceiling is a simple comparison.
    """

    NONE = "none"            # column name and type only; values stay in the result vault
    TOKEN = "token"          # a per-run token the gateway swaps back for the value
    MASKED = "masked"        # a partial value (****1234, year only)
    AGGREGATE = "aggregate"  # only aggregates over at least min_group_size rows
    ALLOWED = "allowed"      # the value itself


class DataSafetyMode(str, Enum):
    METADATA_ONLY = "metadata_only"  # every field behaves as none or token
    CONTRACT = "contract"            # each data contract opens fields up to the ceiling


# OWASP Top 10 for Agentic Applications 2026 (published December 2025).
ASI_RISKS: dict[str, str] = {
    "ASI01": "Agent goal hijack",
    "ASI02": "Tool misuse and exploitation",
    "ASI03": "Identity and privilege abuse",
    "ASI04": "Agentic supply chain",
    "ASI05": "Unexpected code execution",
    "ASI06": "Memory and context poisoning",
    "ASI07": "Insecure inter-agent communication",
    "ASI08": "Cascading failures",
    "ASI09": "Human-agent trust exploitation",
    "ASI10": "Rogue agents",
}

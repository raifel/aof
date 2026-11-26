"""Load an app repo's contract artefacts, turning every parse problem into a Finding."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from .findings import Finding, error
from .models import (
    AgentCard,
    DataContract,
    EvalResults,
    EvalSuite,
    GoldenCase,
    PilotResults,
    Project,
    Readiness,
    SafetyCase,
    ServerJson,
    ToolManifest,
    UseCaseCard,
)

M = TypeVar("M", bound=BaseModel)
PROJECT_FILE = "aof.yaml"


@dataclass
class LoadedProject:
    root: Path
    project: Project | None = None
    use_case: UseCaseCard | None = None
    readiness: Readiness | None = None
    manifest: ToolManifest | None = None
    data_contracts: list[DataContract] = field(default_factory=list)
    server_json: ServerJson | None = None
    agent_card: AgentCard | None = None
    eval_suite: EvalSuite | None = None
    golden_cases: list[GoldenCase] = field(default_factory=list)
    safety_cases: list[SafetyCase] = field(default_factory=list)
    eval_results: EvalResults | None = None
    pilot_results: PilotResults | None = None
    load_findings: list[Finding] = field(default_factory=list)

    def path(self, rel: str) -> Path:
        return self.root / rel


def _read_data(path: Path) -> object:
    text = path.read_text()
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _schema_findings(rel: str, exc: ValidationError) -> list[Finding]:
    out = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "(root)"
        out.append(error("AOF-S003", rel, f"{loc}: {e['msg']}"))
    return out


def _load(
    lp: LoadedProject, rel: str, model: type[M], *, required: bool, missing_hint: str | None = None
) -> M | None:
    path = lp.path(rel)
    if not path.exists():
        if required:
            lp.load_findings.append(error("AOF-S001", rel, "required artefact is missing", missing_hint))
        return None
    try:
        data = _read_data(path)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        lp.load_findings.append(error("AOF-S002", rel, f"cannot parse: {exc}"))
        return None
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        lp.load_findings.extend(_schema_findings(rel, exc))
        return None


def _load_jsonl(lp: LoadedProject, rel: str, model: type[M]) -> list[M]:
    path = lp.path(rel)
    if not path.exists():
        lp.load_findings.append(error("AOF-S001", rel, "case file is missing"))
        return []
    out: list[M] = []
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(model.model_validate(json.loads(line)))
        except json.JSONDecodeError as exc:
            lp.load_findings.append(error("AOF-S002", f"{rel}:{n}", f"cannot parse: {exc}"))
        except ValidationError as exc:
            lp.load_findings.extend(_schema_findings(f"{rel}:{n}", exc))
    return out


def load_project(root: str | Path) -> LoadedProject:
    lp = LoadedProject(root=Path(root).resolve())
    lp.project = _load(lp, PROJECT_FILE, Project, required=True, missing_hint="run `aof init` to scaffold one")
    if lp.project is None:
        return lp
    a = lp.project.artefacts

    lp.use_case = _load(lp, a.use_case, UseCaseCard, required=True)
    lp.readiness = _load(lp, a.readiness, Readiness, required=True)
    lp.manifest = _load(lp, a.manifest, ToolManifest, required=True)
    lp.server_json = _load(lp, a.registry, ServerJson, required=True)
    lp.agent_card = _load(lp, a.agent_card, AgentCard, required=lp.project.hosts_agent)
    lp.eval_suite = _load(lp, a.eval_suite, EvalSuite, required=True)
    lp.eval_results = _load(lp, a.eval_results, EvalResults, required=False)
    lp.pilot_results = _load(lp, a.pilot_results, PilotResults, required=False)

    dc_dir = lp.path(a.data_contracts)
    if dc_dir.is_dir():
        for f in sorted(dc_dir.iterdir()):
            if f.suffix in (".yaml", ".yml", ".json"):
                rel = str(f.relative_to(lp.root))
                dc = _load(lp, rel, DataContract, required=True)
                if dc is not None:
                    lp.data_contracts.append(dc)

    if lp.eval_suite is not None:
        lp.golden_cases = _load_jsonl(lp, lp.eval_suite.golden_set, GoldenCase)
        lp.safety_cases = _load_jsonl(lp, lp.eval_suite.safety_cases, SafetyCase)
    return lp

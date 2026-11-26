"""aof: the onboarding CLI app teams and CI run.

Exit codes: 0 pass, 1 checks failed, 2 usage or setup error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
from importlib import resources
from pathlib import Path

from . import __version__
from .checks import validate
from .conformance import check_server
from .enums import Stage
from .findings import Finding, Report
from .gates import GATE_NAMES, run_gate, status
from .loader import load_project
from .models import SCHEMAS
from .platform import load_platform
from .policy import PolicyError, compile_policy

PLACEHOLDER_SUFFIXES = {".yaml", ".yml", ".json", ".jsonl", ".md", ".py", ".toml", ".txt"}


def _print_findings(findings: list[Finding], as_json: bool, strict: bool = False) -> int:
    report = Report(list(findings))
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for f in sorted(report.findings, key=lambda f: (f.severity.value != "error", f.severity.value, f.code)):
            print(f)
        print(f"\n{len(report.errors)} error(s), {len(report.warnings)} warning(s)")
    return 0 if report.ok(strict) else 1


def cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.dir)
    if dest.exists() and any(dest.iterdir()) and not args.force:
        print(f"{dest} is not empty (use --force to scaffold into it)", file=sys.stderr)
        return 2
    platform = load_platform(args.platform)
    values = {
        "{{app_name}}": args.name,
        "{{app_title}}": args.name.replace("-", " ").title(),
        "{{owner}}": args.owner,
        "{{on_call}}": args.on_call or f"{args.name}-oncall",
        "{{namespace}}": args.namespace or platform.registry.namespace_prefix,
        "{{date}}": dt.date.today().isoformat(),
    }
    with resources.as_file(resources.files("aof") / "templates" / "app") as src:
        shutil.copytree(src, dest, dirs_exist_ok=True)
    gh = dest / "_github"
    if gh.exists():
        shutil.copytree(gh, dest / ".github", dirs_exist_ok=True)
        shutil.rmtree(gh)
    for f in dest.rglob("*"):
        if f.is_file() and f.suffix in PLACEHOLDER_SUFFIXES:
            text = f.read_text()
            for k, v in values.items():
                text = text.replace(k, v)
            f.write_text(text)
    print(f"Scaffolded {args.name} in {dest}. Next: fill aof/use-case.yaml, then run `aof status {dest}`.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    lp = load_project(args.dir)
    return _print_findings(validate(lp, load_platform(args.platform)).findings, args.json, args.strict)


def cmd_gate(args: argparse.Namespace) -> int:
    stage = Stage(args.stage)
    res = run_gate(stage, load_project(args.dir), load_platform(args.platform))
    if not args.json:
        print(f"Gate {stage.value}: {GATE_NAMES[stage]}\n")
    code = _print_findings(res.findings, args.json)
    if not args.json:
        print("PASS" if res.passed else "FAIL")
    return code


def cmd_status(args: argparse.Namespace) -> int:
    results = status(load_project(args.dir), load_platform(args.platform))
    if args.json:
        print(json.dumps([{"stage": r.stage.value, "passed": r.passed,
                           "findings": [f.to_dict() for f in r.findings]} for r in results], indent=2))
    else:
        for i, r in enumerate(results, start=1):
            n_err = sum(f.severity.value == "error" for f in r.findings)
            n_warn = sum(f.severity.value == "warning" for f in r.findings)
            mark = "PASS" if r.passed else "FAIL"
            extra = f"  ({n_err} error(s), {n_warn} warning(s))" if (n_err or n_warn) else ""
            print(f"{i}. {r.stage.value:10} {mark}  {GATE_NAMES[r.stage]}{extra}")
        nxt = next((r.stage.value for r in results if not r.passed), None)
        print(f"\nNext blocking gate: {nxt}. Run `aof gate {nxt}` for details." if nxt else "\nAll gates pass.")
    return 0


def cmd_readiness(args: argparse.Namespace) -> int:
    lp = load_project(args.dir)
    if lp.readiness is None:
        return _print_findings(lp.load_findings, False)
    print(f"Assessed by {lp.readiness.assessed_by} on {lp.readiness.date}\n")
    print(f"{'Dimension':20} {'Status':10} {'Evidence':>8}  Remediation")
    for d, s in lp.readiness.dimensions.items():
        print(f"{d.value:20} {s.status.value:10} {len(s.evidence):>8}  {s.remediation or ''}")
    res = run_gate(Stage.READINESS, lp, load_platform(args.platform))
    print("\nGate: " + ("PASS" if res.passed else "FAIL (a dimension is not ready)"))
    return 0 if res.passed else 1


def cmd_compile_policy(args: argparse.Namespace) -> int:
    lp = load_project(args.dir)
    if lp.project is None or lp.manifest is None:
        return _print_findings(lp.load_findings, False) or 1
    try:
        policy = compile_policy(lp.project, lp.manifest, load_platform(args.platform))
    except PolicyError as exc:
        print("Policy compile failed:\n", file=sys.stderr)
        _print_findings(exc.findings, False)
        return 1
    text = json.dumps(policy, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n")
        print(f"Wrote {args.output}")
    else:
        print(text)
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    for name, model in SCHEMAS.items():
        path = out / f"{name.replace('.', '-')}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(by_alias=True), indent=2) + "\n")
    print(f"Wrote {len(SCHEMAS)} JSON Schemas to {out}")
    return 0


def cmd_check_server(args: argparse.Namespace) -> int:
    lp = load_project(args.dir)
    if lp.project is None or lp.manifest is None:
        return _print_findings(lp.load_findings, False) or 1
    command = args.command or lp.project.mcp_server.command
    if not command:
        print("No server command: pass one after -- or set mcp_server.command in aof.yaml", file=sys.stderr)
        return 2
    return _print_findings(check_server(lp.manifest, command, lp.root), args.json)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aof", description="Agentic Onboarding Framework CLI")
    p.add_argument("--version", action="version", version=f"aof {__version__}")
    p.add_argument("--platform", help="platform.yaml to check against (default: bundled)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="scaffold an app repo with the seven contract artefacts")
    s.add_argument("dir")
    s.add_argument("--name", required=True, help="app name, kebab-case")
    s.add_argument("--owner", required=True, help="owning team")
    s.add_argument("--on-call", help="on-call rota alias")
    s.add_argument("--namespace", help="registry namespace (default: platform prefix)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    for name, fn, hlp in (
        ("validate", cmd_validate, "run every contract check (what CI runs)"),
        ("status", cmd_status, "show all seven gates"),
        ("readiness", cmd_readiness, "print the readiness scorecard"),
    ):
        s = sub.add_parser(name, help=hlp)
        s.add_argument("dir", nargs="?", default=".")
        s.add_argument("--json", action="store_true")
        if name == "validate":
            s.add_argument("--strict", action="store_true", help="fail on warnings too")
        s.set_defaults(fn=fn)

    s = sub.add_parser("gate", help="evaluate one lifecycle gate")
    s.add_argument("stage", choices=[st.value for st in Stage])
    s.add_argument("dir", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_gate)

    s = sub.add_parser("compile-policy", help="compile the gateway policy document")
    s.add_argument("dir", nargs="?", default=".")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_compile_policy)

    s = sub.add_parser("schema", help="export JSON Schemas for every artefact")
    s.add_argument("-o", "--output", default="schemas")
    s.set_defaults(fn=cmd_schema)

    s = sub.add_parser("check-server", help="compare the running MCP server with the manifest")
    s.add_argument("dir", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.add_argument("command", nargs=argparse.REMAINDER, help="-- <server command>")
    s.set_defaults(fn=cmd_check_server)

    from .gateway.cli import register as register_gateway

    register_gateway(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        return args.fn(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

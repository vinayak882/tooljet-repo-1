#!/usr/bin/env python3
"""Security checks for ToolJet git-sync exports.

ToolJet stores SQL and JavaScript as strings inside JSON, so general-purpose
scanners (CodeQL, SonarQube) never see them as code. This script reads the
export layout directly:

    apps/<app>/queries/*.json     data queries
    apps/<app>/components/*.json  widgets
    apps/<app>/pages/*.json       pages
    apps/<app>/events/*.json      event handlers

Rules
  TJ001  SQL injection: user-controlled {{ }} value interpolated into SQL text
  TJ002  Dynamic SQL: other {{ }} expression interpolated into SQL text
  TJ003  Client-side access control: visibility/disabled/hidden driven by
         globals.currentUser (UI-only; the query behind it still runs for anyone)
  TJ004  Client-side access control inside RunJS/RunPy code

Usage
  python3 scripts/tooljet_security_check.py [PATH ...] [--sarif out.sarif] [--github]

  Run from the repo root. PATH is an app folder (apps/<app>) or any folder
  containing apps; the default is the whole repo.

Exits 1 if any error-level finding is reported.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SQL_KINDS = {
    "postgresql", "mysql", "mariadb", "mssql", "oracledb", "snowflake",
    "redshift", "bigquery", "clickhouse", "cockroachdb", "saphana",
    "databricks", "athena", "duckdb", "sqlite", "tooljetdb",
}
CODE_KINDS = {"runjs", "runpy"}

BINDING = re.compile(r"\{\{(.*?)\}\}", re.S)
# JS template-literal interpolation inside a {{`...`}} binding
TEMPLATE_INTERP = re.compile(r"\$\{(.*?)\}", re.S)
USER_INPUT = re.compile(
    r"\b(?:components|queries|variables|page\.variables|parameters|"
    r"globals\.urlparams|globals\.currentUser|inputs)\b"
)
CURRENT_USER = re.compile(r"globals\.currentUser\b")
ACCESS_PROPS = ("visibility", "disabledState", "hidden", "disabled")

RULES = {
    "TJ001": ("error", "SQL injection: user input is concatenated into SQL. "
              "Use SQL parameters (:name) with values set in query_params."),
    "TJ002": ("warning", "Dynamic SQL: a {{ }} expression is concatenated into SQL. "
              "Prefer SQL parameters unless this is a trusted constant."),
    "TJ003": ("warning", "Client-side access control: this is decided in the browser from "
              "globals.currentUser. Hiding UI does not stop the underlying query from running; "
              "enforce the check on the server (ToolJet permissions, DB grants/RLS)."),
    "TJ004": ("warning", "Client-side access control in query code: globals.currentUser checks "
              "in RunJS/RunPy run in the browser and can be bypassed."),
}


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: could not parse {path}: {exc}", file=sys.stderr)
        return None


def line_of(path, needle):
    """1-based line of the first line containing needle, else 1."""
    try:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if needle in line:
                return i
    except OSError:
        pass
    return 1


def expressions(text):
    """Every JS expression evaluated inside {{ }} (including ${} in template literals)."""
    for body in BINDING.findall(text):
        yield from TEMPLATE_INTERP.findall(body)
        yield body


def check_query(path, q, findings):
    kind = q.get("kind")
    opts = q.get("options") or {}
    name = q.get("name", path.stem)

    if kind in SQL_KINDS and isinstance(opts.get("query"), str):
        sql = opts["query"]
        exprs = list(expressions(sql))
        if exprs:
            user = [e for e in exprs if USER_INPUT.search(e)]
            rule = "TJ001" if user else "TJ002"
            sample = (user or exprs)[0].strip().replace("\n", " ")[:80]
            findings.append((rule, path, line_of(path, '"query"'),
                             f"query '{name}' ({kind}): {sample}"))

    if kind in CODE_KINDS and isinstance(opts.get("code"), str):
        if CURRENT_USER.search(opts["code"]):
            findings.append(("TJ004", path, line_of(path, '"code"'),
                             f"query '{name}' ({kind}) checks globals.currentUser"))


def walk_access_props(obj, prefix=""):
    """Yield (prop, value) for access-controlling properties anywhere in obj."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in ACCESS_PROPS:
                v = val.get("value") if isinstance(val, dict) else val
                if isinstance(v, str):
                    yield f"{prefix}{key}", v
            yield from walk_access_props(val, f"{prefix}{key}.")
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_access_props(item, prefix)


def check_app(app_dir, findings):
    queries = {}
    for p in sorted((app_dir / "queries").glob("*.json")):
        q = load(p)
        if isinstance(q, dict):
            queries[q.get("id")] = q.get("name")
            check_query(p, q, findings)

    # component/page id -> names of queries its events run
    triggers = {}
    for p in sorted((app_dir / "events").glob("*.json")):
        e = load(p)
        if isinstance(e, dict):
            ev = e.get("event") or {}
            if ev.get("actionId") == "run-query":
                qname = ev.get("queryName") or queries.get(ev.get("queryId"))
                triggers.setdefault(e.get("sourceId"), set()).add(qname)

    for folder, label in (("components", "component"), ("pages", "page")):
        for p in sorted((app_dir / folder).glob("*.json")):
            obj = load(p)
            if not isinstance(obj, dict):
                continue
            for prop, value in walk_access_props(obj):
                if CURRENT_USER.search(value):
                    runs = sorted(n for n in triggers.get(obj.get("id"), ()) if n)
                    extra = f"; runs queries {', '.join(runs)} (verify server-side)" if runs else ""
                    findings.append(("TJ003", p, line_of(p, f'"{prop.split(".")[-1]}"'),
                                     f"{label} '{obj.get('name')}' {prop} = {value.strip()[:80]}{extra}"))


def to_sarif(findings, root):
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "tooljet-security-check",
                "informationUri": "https://docs.tooljet.com",
                "rules": [{
                    "id": rid,
                    "shortDescription": {"text": desc.split(":")[0]},
                    "fullDescription": {"text": desc},
                    "defaultConfiguration": {"level": level},
                } for rid, (level, desc) in RULES.items()],
            }},
            "results": [{
                "ruleId": rid,
                "level": RULES[rid][0],
                "message": {"text": f"{msg}. {RULES[rid][1]}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": path.relative_to(root).as_posix()},
                    "region": {"startLine": line},
                }}],
            } for rid, path, line, msg in findings],
        }],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["."],
                    help="app folders or folders containing apps (default: .)")
    ap.add_argument("--sarif", help="write SARIF report to this path")
    ap.add_argument("--github", action="store_true",
                    help="also print GitHub Actions annotations (inline on the PR diff)")
    args = ap.parse_args()

    root = Path.cwd().resolve()
    app_dirs = set()
    for arg in args.paths:
        base = Path(arg).resolve()
        if not base.is_dir():
            print(f"skipping {arg}: not a directory (deleted in this change?)", file=sys.stderr)
            continue
        app_dirs |= {p.parent.parent for p in base.rglob("queries/*.json")}
        app_dirs |= {p.parent.parent for p in base.rglob("components/*.json")}
    app_dirs = sorted(app_dirs)
    findings = []
    for app_dir in app_dirs:
        check_app(app_dir, findings)

    for rid, path, line, msg in findings:
        rel = path.relative_to(root).as_posix()
        level, desc = RULES[rid]
        print(f"{rel}:{line}: {level} {rid}: {msg}")
        if args.github:
            text = f"{msg}. {desc}".replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            file_prop = rel.replace("%", "%25").replace(",", "%2C").replace(":", "%3A")
            print(f"::{level} file={file_prop},line={line},title={rid}::{text}")
    errors = sum(RULES[f[0]][0] == "error" for f in findings)
    print(f"\n{len(app_dirs)} app(s) scanned, {len(findings)} finding(s), {errors} error(s)")

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(findings, root), indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

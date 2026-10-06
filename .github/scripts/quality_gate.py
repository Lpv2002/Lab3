#!/usr/bin/env python3
"""Quality Gate: lee los reportes de seguridad y falla si hay hallazgos criticos.

Uso:
    python quality_gate.py --reports <carpeta> --require semgrep,spotbugs[,depcheck]

Criterio de hallazgo critico por herramienta:
    Semgrep           severidad ERROR
    SpotBugs          prioridad 1 (High)
    Dependency-Check  severidad CRITICAL (CVSS >= 9.0)

Un reporte requerido que no existe tambien hace fallar el gate: sin reporte
no hay evidencia de que el analisis se haya ejecutado.
"""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def find(reports: Path, name: str):
    matches = sorted(reports.rglob(name))
    return matches[0] if matches else None


def semgrep(reports: Path):
    path = find(reports, "semgrep-results.json")
    if not path:
        return None
    results = json.loads(path.read_text(encoding="utf-8")).get("results", [])
    critical = [
        f"{r['check_id']} - {r['path']}:{r['start']['line']}"
        for r in results
        if r.get("extra", {}).get("severity", "").upper() == "ERROR"
    ]
    return len(results), critical


def spotbugs(reports: Path):
    path = find(reports, "spotbugsXml.xml")
    if not path:
        return None
    bugs = ET.parse(path).getroot().findall("BugInstance")
    critical = []
    for bug in bugs:
        if bug.get("priority") == "1":
            line = bug.find("SourceLine")
            where = line.get("sourcepath", "?") if line is not None else "?"
            critical.append(f"{bug.get('type')} - {where}")
    return len(bugs), critical


def depcheck(reports: Path):
    path = find(reports, "dependency-check-report.json")
    if not path:
        return None
    total, critical = 0, []
    for dep in json.loads(path.read_text(encoding="utf-8")).get("dependencies", []):
        for vuln in dep.get("vulnerabilities", []):
            total += 1
            if vuln.get("severity", "").upper() == "CRITICAL":
                critical.append(f"{vuln.get('name')} - {dep.get('fileName')}")
    return total, critical


TOOLS = {
    "semgrep": ("Semgrep", "ERROR", semgrep),
    "spotbugs": ("SpotBugs", "prioridad High", spotbugs),
    "depcheck": ("Dependency-Check", "CRITICAL", depcheck),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--require", default="semgrep,spotbugs")
    args = parser.parse_args()

    reports = Path(args.reports)
    failed = False
    lines = [
        "## Quality Gate",
        "",
        "| Herramienta | Criterio critico | Hallazgos totales | Criticos | Estado |",
        "|---|---|---|---|---|",
    ]
    details = []

    for key in [k.strip() for k in args.require.split(",") if k.strip()]:
        label, criterion, reader = TOOLS[key]
        result = reader(reports)
        if result is None:
            failed = True
            lines.append(f"| {label} | {criterion} | - | - | FALLA (reporte no encontrado) |")
            print(f"::error::{label}: no se encontro el reporte")
            continue
        total, critical = result
        status = "FALLA" if critical else "OK"
        lines.append(f"| {label} | {criterion} | {total} | {len(critical)} | {status} |")
        if critical:
            failed = True
            print(f"::error::{label}: {len(critical)} hallazgos criticos")
            details.append(f"### {label}: {len(critical)} hallazgos criticos")
            details.extend(f"- `{item}`" for item in critical)
            details.append("")

    lines.append("")
    lines.append("**Resultado: " + ("BLOQUEADO**" if failed else "APROBADO**"))
    lines.append("")
    summary = "\n".join(lines + details)

    print(summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    Path("quality-gate-summary.md").write_text(summary + "\n", encoding="utf-8")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

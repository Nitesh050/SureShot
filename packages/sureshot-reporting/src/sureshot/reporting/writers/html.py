from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sureshot.reporting.builder import ReportData

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "jinja"]),
)


def write(report: ReportData) -> str:
    template = _env.get_template("report.html.jinja")
    return template.render(report=report)

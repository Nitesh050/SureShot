from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from sureshot.reporting.builder import ReportData


def write(report: ReportData) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=f"SureShot Report - {report.project_id}")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("SureShot Report", styles["Title"]))
    story.append(Paragraph(
        f"{report.project_id} &middot; scan {report.scan_id} &middot; "
        f"generated {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))
    story.append(Paragraph(
        f"{report.profile.scanned_files} files scanned &middot; "
        f"{report.profile.primary_language or 'unknown'}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 12))

    if not report.issues:
        story.append(Paragraph("No findings.", styles["Normal"]))
    else:
        story.append(Paragraph(
            f"{len(report.issues)} issue(s) &middot; {len(report.actionable_issues)} actionable",
            styles["Normal"],
        ))
        story.append(Spacer(1, 8))

        rows = [["Risk", "Severity", "Verdict", "Rule", "Location"]]
        for issue in report.issues:
            f = issue.primary.finding
            rows.append([
                f"{issue.primary.score:.0f}",
                f.severity.value,
                issue.primary.verdict.value.replace("_", " "),
                f.title[:60],
                f"{f.location.file_path}:{f.location.line_start}",
            ])
        table = Table(rows, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)

    doc.build(story)
    return buffer.getvalue()

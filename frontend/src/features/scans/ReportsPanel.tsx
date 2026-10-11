import { Braces, Download, Eye, FileCode2, FileText, Github, Globe } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { ReportFile, ReportFormat } from "../../api/types";

const FORMATS: Record<ReportFormat, { title: string; blurb: string; icon: typeof FileText; viewable: boolean }> = {
  pdf: { title: "PDF report", blurb: "Shareable summary for reviewers, managers or audits.", icon: FileText, viewable: true },
  html: { title: "HTML report", blurb: "Self-contained page you can open in any browser.", icon: Globe, viewable: true },
  sarif: { title: "SARIF", blurb: "Upload to GitHub code scanning to see findings in the Security tab.", icon: Github, viewable: false },
  json: { title: "JSON", blurb: "Every finding with AI analysis, for scripts and other tools.", icon: Braces, viewable: false },
};
const ORDER: ReportFormat[] = ["pdf", "html", "sarif", "json"];

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function ReportsPanel({ scanId }: { scanId: string }) {
  const [files, setFiles] = useState<ReportFile[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.reports(scanId).then(setFiles).catch((err) => setError(err.message));
  }, [scanId]);

  if (error) return <div className="banner banner-error">{error}</div>;
  if (!files) return <p className="muted">Loading reports…</p>;
  if (files.length === 0) {
    return <div className="list-empty card"><FileCode2 size={22} /><p>No reports were generated for this scan.</p></div>;
  }

  const byFormat = new Map(files.map((f) => [f.format, f]));
  return (
    <div className="reports-grid">
      {ORDER.filter((fmt) => byFormat.has(fmt)).map((fmt) => {
        const file = byFormat.get(fmt)!;
        const meta = FORMATS[fmt];
        const Icon = meta.icon;
        return (
          <div key={fmt} className="card report-card">
            <div className="report-top">
              <span className="report-icon"><Icon size={20} /></span>
              <span className="mono muted">.{fmt} · {size(file.size_bytes)}</span>
            </div>
            <h3>{meta.title}</h3>
            <p>{meta.blurb}</p>
            <p className="report-file mono" title={file.filename}>{file.filename}</p>
            <div className="report-actions">
              <a className="btn btn-accent" href={api.reportUrl(scanId, fmt)} download={file.filename}>
                <Download size={15} /> Download
              </a>
              {meta.viewable && (
                <a className="btn" href={api.reportUrl(scanId, fmt, true)} target="_blank" rel="noreferrer">
                  <Eye size={15} /> View
                </a>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

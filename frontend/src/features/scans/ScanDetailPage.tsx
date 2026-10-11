import { ChevronDown, ChevronRight, Download, ExternalLink, FileArchive, GitCommit, Github, Info, RotateCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../../api/client";
import type { FindingsReport, ReportFormat, Scan } from "../../api/types";
import { StatusPill } from "../../components/Badges";
import { duration, scanDuration, timeAgo } from "../../lib/format";
import { usePoll } from "../../lib/usePoll";
import { FindingsView } from "./FindingsView";
import { PipelineTrace } from "./PipelineTrace";
import { ReportsPanel } from "./ReportsPanel";
import { CleanCard, NoiseFunnel, ProfileCard, SeverityCard } from "./ScanOverview";

const active = (s: Scan) => s.status === "queued" || s.status === "running";

type Tab = "findings" | "reports" | "trace";

export function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const { data: scan, error } = usePoll(() => api.getScan(scanId), 1200, active, [scanId]);
  const [report, setReport] = useState<FindingsReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "reports" || params.get("tab") === "trace" ? (params.get("tab") as Tab) : "findings";
  const setTab = (next: Tab) => {
    const p = new URLSearchParams(params);
    if (next === "findings") p.delete("tab");
    else p.set("tab", next);
    setParams(p, { replace: true });
  };
  const [rescanning, setRescanning] = useState(false);

  const completed = scan?.status === "completed";
  useEffect(() => {
    setReport(null);
    setReportError(null);
    if (!completed) return;
    api.findings(scanId).then(setReport).catch((err) => setReportError(err.message));
  }, [scanId, completed]);

  const rescan = async () => {
    if (!scan?.source.url) return;
    setRescanning(true);
    try {
      const next = await api.scanUrl(scan.source.url, scan.source.ref, scan.options);
      navigate(`/scans/${next.id}`);
    } catch (err) {
      setReportError((err as Error).message);
    } finally {
      setRescanning(false);
    }
  };

  if (error && !scan) {
    return (
      <div className="page">
        <div className="banner banner-error">{error.message}</div>
        <Link to="/" className="btn">Back to scans</Link>
      </div>
    );
  }
  if (!scan) return <div className="page"><p className="muted">Loading scan…</p></div>;

  const ms = scanDuration(scan);

  return (
    <div className="page page-wide">
      <nav className="crumbs mono" aria-label="Breadcrumb">
        <Link to="/">Scans</Link><ChevronRight size={12} /><span>{scan.id}</span>
      </nav>

      <header className="scan-head">
        <div className="scan-title">
          <span className="scan-icon">{scan.source.kind === "url" ? <Github size={20} /> : <FileArchive size={20} />}</span>
          <div>
            <h1 className="page-title">{scan.source.label}</h1>
            <div className="scan-meta">
              <StatusPill status={scan.status} step={scan.current_step} />
              {scan.source.commit && <span className="mono"><GitCommit size={13} /> {scan.source.commit.slice(0, 7)}</span>}
              {scan.source.ref && <span className="mono">{scan.source.ref}</span>}
              {scan.source.url && (
                <a href={scan.source.url} target="_blank" rel="noreferrer" className="mono">source <ExternalLink size={11} /></a>
              )}
              <span>{timeAgo(scan.created_at)}</span>
              {ms !== null && <span className="mono">{duration(ms)}</span>}
            </div>
          </div>
        </div>
        <div className="scan-actions">
          {scan.source.kind === "url" && !active(scan) && (
            <button type="button" className="btn" onClick={rescan} disabled={rescanning}>
              <RotateCw size={15} className={rescanning ? "spin" : undefined} /> Rescan
            </button>
          )}
          {completed && scan.reports.length > 0 && <ReportMenu scanId={scan.id} formats={scan.reports} onShowAll={() => setTab("reports")} />}
        </div>
      </header>

      {scan.status === "failed" && (
        <div className="banner banner-error"><strong>Scan failed.</strong> {scan.error}</div>
      )}
      {scan.notes.map((note) => (
        <div key={note} className="banner banner-info"><Info size={15} /> {note}</div>
      ))}

      {!completed ? (
        <section className="card live-card">
          <div className="card-head">
            <p className="mono-label">{active(scan) ? "Pipeline · live" : "Pipeline"}</p>
            {active(scan) && <span className="live-dot">LIVE</span>}
          </div>
          <PipelineTrace scan={scan} />
        </section>
      ) : (
        <>
          {scan.summary && (
            <section className="overview-grid">
              {scan.summary.raw_findings === 0 ? (
                <CleanCard scanners={scan.steps.filter((s) => s.step.startsWith("scan:")).map((s) => s.step.slice(5))} />
              ) : (
                <>
                  <NoiseFunnel summary={scan.summary} triaged={scan.options.triage && !scan.notes.some((n) => n.startsWith("AI triage unavailable"))} />
                  <SeverityCard summary={scan.summary} />
                </>
              )}
              {scan.profile && <ProfileCard profile={scan.profile} />}
            </section>
          )}

          <div className="tabs" role="tablist">
            <button type="button" role="tab" aria-selected={tab === "findings"} className={tab === "findings" ? "on" : ""} onClick={() => setTab("findings")}>
              Findings {scan.summary && <span className="count">{scan.summary.issues}</span>}
            </button>
            <button type="button" role="tab" aria-selected={tab === "reports"} className={tab === "reports" ? "on" : ""} onClick={() => setTab("reports")}>
              Reports <span className="count">{scan.reports.length}</span>
            </button>
            <button type="button" role="tab" aria-selected={tab === "trace"} className={tab === "trace" ? "on" : ""} onClick={() => setTab("trace")}>
              Pipeline trace <span className="count">{scan.steps.length}</span>
            </button>
          </div>

          {tab === "reports" ? (
            <ReportsPanel scanId={scan.id} />
          ) : tab === "trace" ? (
            <section className="card live-card"><PipelineTrace scan={scan} /></section>
          ) : reportError ? (
            <div className="banner banner-error">{reportError}</div>
          ) : report ? (
            <FindingsView issues={report.issues} triageEnabled={scan.options.triage} />
          ) : (
            <p className="muted">Loading findings…</p>
          )}
        </>
      )}
    </div>
  );
}

const FORMAT_LABELS: Record<ReportFormat, string> = {
  pdf: "PDF report",
  html: "HTML report",
  sarif: "SARIF (GitHub code scanning)",
  json: "JSON (raw data)",
};

function ReportMenu({ scanId, formats, onShowAll }: { scanId: string; formats: ReportFormat[]; onShowAll: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const ordered = (["pdf", "html", "sarif", "json"] as ReportFormat[]).filter((f) => formats.includes(f));
  return (
    <div className="menu" ref={ref}>
      <button type="button" className="btn btn-accent" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Download size={15} /> Export <ChevronDown size={14} />
      </button>
      {open && (
        <div className="menu-pop" role="menu">
          {ordered.map((fmt) => (
            <a key={fmt} role="menuitem" href={api.reportUrl(scanId, fmt)} download onClick={() => setOpen(false)}>
              <span className="mono menu-fmt">.{fmt}</span> {FORMAT_LABELS[fmt]}
            </a>
          ))}
          <button type="button" className="menu-all" onClick={() => { setOpen(false); onShowAll(); }}>
            All reports & sizes →
          </button>
        </div>
      )}
    </div>
  );
}

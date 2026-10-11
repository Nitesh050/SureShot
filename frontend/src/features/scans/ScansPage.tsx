import { FileArchive, Github, Plus, Radar } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Scan } from "../../api/types";
import { StatusPill } from "../../components/Badges";
import { SeverityBar } from "../../components/SeverityBar";
import { duration, noiseReduction, pct, scanDuration, timeAgo } from "../../lib/format";
import { usePoll } from "../../lib/usePoll";

const inFlight = (scans: Scan[]) => scans.some((s) => s.status === "queued" || s.status === "running");

/** Latest completed scan per repo, so rescans don't double-count issues. */
function latestPerRepo(scans: Scan[]): Scan[] {
  const seen = new Map<string, Scan>();
  for (const scan of scans) {
    if (scan.status === "completed" && !seen.has(scan.source.label)) seen.set(scan.source.label, scan);
  }
  return [...seen.values()];
}

export function ScansPage() {
  const { data: scans, error } = usePoll(api.listScans, 2000, inFlight, []);
  const navigate = useNavigate();

  const latest = latestPerRepo(scans ?? []);
  const raw = latest.reduce((n, s) => n + (s.summary?.raw_findings ?? 0), 0);
  const actionable = latest.reduce((n, s) => n + (s.summary?.actionable ?? 0), 0);
  const urgent = latest.reduce((n, s) => n + (s.summary?.by_severity.critical ?? 0) + (s.summary?.by_severity.high ?? 0), 0);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="mono-label">Workspace · local</p>
          <h1 className="page-title">Scans</h1>
        </div>
        <Link to="/new" className="btn btn-accent"><Plus size={16} /> New scan</Link>
      </header>

      {error && <div className="banner banner-error">{error.message}</div>}

      <section className="stat-strip" aria-label="Summary">
        <Stat label="Repositories" value={latest.length} hint={`${scans?.length ?? 0} scans total`} />
        <Stat label="Open issues" value={actionable} hint="after dedup + AI triage" />
        <Stat label="Critical + high" value={urgent} tone={urgent ? "danger" : undefined} hint="fix these first" />
        <Stat label="Noise removed" value={raw ? pct(1 - actionable / raw) : "—"} tone="accent"
          hint={raw ? `${raw} raw → ${actionable} actionable` : "run a scan to measure"} />
      </section>

      {scans && scans.length === 0 ? (
        <section className="empty">
          <Radar size={34} />
          <h2>No scans yet</h2>
          <p>Point SureShot at a repository link or upload a zip. Scanners run, duplicates collapse, and AI triage
            separates real issues from noise.</p>
          <Link to="/new" className="btn btn-accent"><Plus size={16} /> Start your first scan</Link>
        </section>
      ) : (
        <section className="card table-card">
          <table className="scan-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Status</th>
                <th>Severity mix</th>
                <th className="num">Issues</th>
                <th className="num">Noise cut</th>
                <th className="num">Duration</th>
                <th className="num">Started</th>
              </tr>
            </thead>
            <tbody>
              {(scans ?? []).map((scan) => {
                const nr = noiseReduction(scan);
                const ms = scanDuration(scan);
                return (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} className="clickable">
                    <td>
                      <Link to={`/scans/${scan.id}`} className="repo-cell" onClick={(e) => e.stopPropagation()}>
                        {scan.source.kind === "url" ? <Github size={16} /> : <FileArchive size={16} />}
                        <span>
                          <strong>{scan.source.label}</strong>
                          <small className="mono">
                            {scan.source.commit ? scan.source.commit.slice(0, 7) : scan.source.filename ?? scan.source.ref ?? "default branch"}
                            {" · "}{scan.id}
                          </small>
                        </span>
                      </Link>
                    </td>
                    <td><StatusPill status={scan.status} step={scan.current_step} /></td>
                    <td className="sev-cell">
                      {scan.summary ? <SeverityBar counts={scan.summary.by_severity} /> : <span className="muted">—</span>}
                    </td>
                    <td className="num">{scan.summary ? scan.summary.actionable : "—"}</td>
                    <td className="num accent">{nr === null ? "—" : pct(nr)}</td>
                    <td className="num mono">{ms === null ? "—" : duration(ms)}</td>
                    <td className="num muted">{timeAgo(scan.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!scans && !error && <p className="table-loading">Loading scans…</p>}
        </section>
      )}
    </div>
  );
}

function Stat({ label, value, hint, tone }: { label: string; value: number | string; hint: string; tone?: "danger" | "accent" }) {
  return (
    <div className="stat">
      <p className="mono-label">{label}</p>
      <strong className={tone ? `stat-${tone}` : undefined}>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}

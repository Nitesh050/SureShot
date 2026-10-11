import { ShieldCheck } from "lucide-react";
import type { RepoProfile, ScanSummary } from "../../api/types";
import { SEVERITIES, pct } from "../../lib/format";

/** Raw scanner output → deduped issues → what a human actually has to look at. */
export function NoiseFunnel({ summary, triaged }: { summary: ScanSummary; triaged: boolean }) {
  const stages = [
    { label: "Raw findings", value: summary.raw_findings, note: "from all scanners" },
    { label: "After dedup", value: summary.issues, note: `${summary.raw_findings - summary.issues} duplicates merged` },
    {
      label: "Actionable",
      value: summary.actionable,
      note: triaged ? `${summary.dismissed} dismissed by AI` : "AI triage off",
    },
  ];
  const max = Math.max(summary.raw_findings, 1);
  const reduction = summary.raw_findings ? 1 - summary.actionable / summary.raw_findings : 0;

  return (
    <div className="card funnel">
      <div className="card-head">
        <p className="mono-label">Noise funnel</p>
        <span className="funnel-total">{pct(reduction)} <small>noise cut</small></span>
      </div>
      <div className="funnel-rows">
        {stages.map((s, i) => (
          <div key={s.label} className="funnel-row">
            <span className="funnel-label">{s.label}</span>
            <div className="funnel-track">
              <span className={`funnel-fill funnel-${i}`} style={{ width: `${Math.max((s.value / max) * 100, s.value ? 2 : 0)}%` }} />
            </div>
            <strong className="num">{s.value}</strong>
            <small className="funnel-note">{s.note}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SeverityCard({ summary }: { summary: ScanSummary }) {
  const max = Math.max(...SEVERITIES.map((s) => summary.by_severity[s] ?? 0), 1);
  return (
    <div className="card sev-card">
      <div className="card-head">
        <p className="mono-label">Actionable by severity</p>
        {summary.multi_tool > 0 && <span className="chip">{summary.multi_tool} confirmed by 2+ tools</span>}
      </div>
      <div className="sev-columns">
        {SEVERITIES.map((s) => (
          <div key={s} className="sev-col">
            <strong>{summary.by_severity[s] ?? 0}</strong>
            <div className="sev-col-track">
              <span className={`sev-bg-${s}`} style={{ height: `${((summary.by_severity[s] ?? 0) / max) * 100}%` }} />
            </div>
            <small>{s}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ProfileCard({ profile }: { profile: RepoProfile }) {
  const langBytes = profile.languages.reduce((n, l) => n + l.bytes, 0) || 1;
  const langs = [...profile.languages].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
  return (
    <div className="card profile-card">
      <div className="card-head">
        <p className="mono-label">Repository profile</p>
        <span className="muted mono">{profile.scanned_files} files</span>
      </div>
      <div className="lang-bar">
        {langs.map((l, i) => (
          <span key={l.name} className={`lang-${i}`} style={{ flexGrow: l.bytes }} title={l.name} />
        ))}
      </div>
      <ul className="lang-list">
        {langs.map((l, i) => (
          <li key={l.name}><i className={`lang-${i}`} />{l.name}<span className="mono muted">{pct(l.bytes / langBytes)}</span></li>
        ))}
      </ul>
      <div className="coverage">
        {profile.coverage.map((c) => (
          <span key={c.domain} className={`cov cov-${c.coverage}`} title={c.reason}>
            {c.domain.toUpperCase()} · {c.coverage}
          </span>
        ))}
        {profile.ecosystems.map((e) => (
          <span key={e.name} className="cov">{e.name}{e.lockfiles.length ? " · locked" : ""}</span>
        ))}
      </div>
    </div>
  );
}

export function CleanCard({ scanners }: { scanners: string[] }) {
  return (
    <div className="card clean-card">
      <ShieldCheck size={34} />
      <div>
        <h2>No findings</h2>
        <p>
          {scanners.length ? `${scanners.join(", ")} ran` : "Scanners ran"} without reporting anything. Check the
          coverage notes and pipeline trace: a scanner that ran with limited rules can also come back empty.
        </p>
      </div>
    </div>
  );
}

import { ArrowRight, BookOpen, Copy, ExternalLink, KeyRound, Layers, Package, Sparkles, Wrench } from "lucide-react";
import type { Issue } from "../../api/types";
import { DomainTag, SeverityBadge, VerdictBadge } from "../../components/Badges";

const CONTRIBUTION_LABELS: Record<string, string> = {
  severity: "Scanner severity",
  path_role: "File role (test, vendor…)",
  verdict: "AI verdict",
  dependency: "Direct dependency / fix available",
  policy_floor: "Policy floor",
};

export function FindingDetail({ issue, triageEnabled }: { issue: Issue; triageEnabled: boolean }) {
  const f = issue.finding;
  const a = issue.analysis;

  return (
    <article className="detail">
      <header className="detail-head">
        <div className="detail-badges">
          <SeverityBadge severity={f.severity} />
          <DomainTag domain={f.domain} />
          <VerdictBadge verdict={a?.verdict ?? "needs_human"} triaged={a !== null} />
        </div>
        <h2>{f.package ? `${f.package.name} ${f.package.installed_version}` : f.title}</h2>
        <p className="mono detail-loc">
          {f.location.file_path}:{f.location.line_start}
          {f.location.line_end !== f.location.line_start && `-${f.location.line_end}`}
        </p>
        <div className="detail-meta">
          {f.rule_id !== f.cve_id && <span className="mono">{f.rule_id}</span>}
          {f.cwe_ids.map((cwe) => (
            <a key={cwe} className="chip chip-link" target="_blank" rel="noreferrer"
              href={`https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html`}>
              {cwe} <ExternalLink size={11} />
            </a>
          ))}
          {f.cve_id && (
            <a className="chip chip-link" target="_blank" rel="noreferrer" href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}>
              {f.cve_id} <ExternalLink size={11} />
            </a>
          )}
        </div>
      </header>

      <section className={`ai-card${a ? ` ai-${a.verdict}` : ""}`}>
        <div className="ai-head">
          <span><Sparkles size={15} /> AI analysis</span>
          {a && <span className="mono muted">{a.model_id} · prompt {a.prompt_version}</span>}
        </div>
        {a ? (
          <>
            <div className="confidence">
              <span>Confidence</span>
              <div className="confidence-track"><span style={{ width: `${a.confidence * 100}%` }} /></div>
              <strong className="mono">{Math.round(a.confidence * 100)}%</strong>
            </div>
            <p className="ai-rationale">{a.rationale}</p>
            {a.guard_holds.length > 0 && (
              <p className="inline-warn">Held for human review by guard: {a.guard_holds.join(", ")}</p>
            )}
            {a.evidence.length > 0 && (
              <div className="evidence">
                <p className="mono-label">Evidence cited</p>
                {a.evidence.map((ev, i) => (
                  <div key={i} className="evidence-row">
                    <span className="mono">{ev.location.file_path}:{ev.location.line_start}</span>
                    <p>{ev.note}</p>
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <p className="ai-empty">
            {triageEnabled
              ? "The model didn't return an analysis for this finding, so it's queued for human review."
              : "AI triage was off for this scan. Enable it on the next scan to get a verdict, confidence and cited evidence."}
          </p>
        )}
      </section>

      {issue.snippet && <CodeBlock issue={issue} />}

      {f.package && (
        <section className="detail-section">
          <h3><Package size={14} /> Affected package</h3>
          <div className="pkg">
            <span className="mono">{f.package.name}</span>
            <span className="pkg-version pkg-bad mono">{f.package.installed_version}</span>
            <ArrowRight size={14} className="muted" />
            {f.package.fixed_version ? (
              <span className="pkg-version pkg-good mono">{f.package.fixed_version}</span>
            ) : (
              <span className="muted">no fixed version yet</span>
            )}
          </div>
        </section>
      )}

      {f.secret && (
        <section className="detail-section">
          <h3><KeyRound size={14} /> Secret</h3>
          <p className="mono">{f.secret.kind} · ends in ••••{f.secret.last_four}</p>
          <p className="muted small">Rotate this credential. Removing it from the code doesn't remove it from git history.</p>
        </section>
      )}

      {a?.impact && (
        <section className="detail-section">
          <h3>Impact</h3>
          <p>{a.impact}</p>
        </section>
      )}
      {(a?.remediation || f.package?.fixed_version) && (
        <section className="detail-section">
          <h3><Wrench size={14} /> Fix</h3>
          <p>{a?.remediation || `Upgrade ${f.package!.name} to ${f.package!.fixed_version} or later.`}</p>
        </section>
      )}

      <section className="detail-section">
        <h3>Risk score <span className="mono score-big">{issue.score.toFixed(0)}</span></h3>
        <Contributions values={issue.contributions} />
      </section>

      {(issue.duplicates.length > 0 || issue.tools.length > 1) && (
        <section className="detail-section">
          <h3><Layers size={14} /> Merged findings · {issue.occurrences}</h3>
          <p className="muted small">Reported by {issue.tools.join(" + ")}. Duplicates were folded into this issue.</p>
          <ul className="dupes">
            {issue.duplicates.map((d) => (
              <li key={d.instance_id}>
                <span className="mono">{d.tool}</span>
                <span>{d.title}</span>
                <span className="mono muted">{d.location}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {f.description && f.description !== f.title && (
        <section className="detail-section">
          <h3><BookOpen size={14} /> Scanner description</h3>
          <p className="description">{f.description}</p>
        </section>
      )}

      <footer className="detail-foot mono muted">
        {f.tool} {f.tool_version} · issue {issue.issue_id.slice(0, 12)}
      </footer>
    </article>
  );
}

function CodeBlock({ issue }: { issue: Issue }) {
  const snip = issue.snippet!;
  const { line_start, line_end, file_path } = issue.finding.location;
  const lines = snip.context.split("\n");
  return (
    <section className="code">
      <div className="code-head">
        <span className="mono">{file_path}</span>
        <button type="button" className="icon-btn" aria-label="Copy code" title="Copy"
          onClick={() => navigator.clipboard?.writeText(snip.context)}>
          <Copy size={13} />
        </button>
      </div>
      <pre>
        {lines.map((line, i) => {
          const n = snip.context_start + i;
          const hit = n >= line_start && n <= line_end;
          return (
            <div key={n} className={hit ? "code-line hit" : "code-line"}>
              <span className="ln">{n}</span>
              <code>{line || " "}</code>
            </div>
          );
        })}
      </pre>
      {snip.truncated && <p className="code-note">Context truncated.</p>}
    </section>
  );
}

function Contributions({ values }: { values: Record<string, number> }) {
  const entries = Object.entries(values).filter(([, v]) => v !== 0);
  if (entries.length === 0) return <p className="muted small">No score breakdown recorded.</p>;
  const max = Math.max(...entries.map(([, v]) => Math.abs(v)), 1);
  return (
    <div className="contrib">
      {entries.map(([key, v]) => (
        <div key={key} className="contrib-row">
          <span>{CONTRIBUTION_LABELS[key] ?? key.replace(/_/g, " ")}</span>
          <div className="contrib-track">
            <span className={v < 0 ? "neg" : "pos"} style={{ width: `${(Math.abs(v) / max) * 50}%` }} />
          </div>
          <span className="mono num">{v > 0 ? "+" : ""}{v.toFixed(1)}</span>
        </div>
      ))}
    </div>
  );
}

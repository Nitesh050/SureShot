import { Search, SearchX } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { Domain, Issue, Severity, Verdict } from "../../api/types";
import { DomainTag, SeverityBadge, VerdictBadge } from "../../components/Badges";
import { SEVERITIES } from "../../lib/format";
import { FindingDetail } from "./FindingDetail";

type VerdictFilter = "actionable" | Verdict | "all";

const VERDICT_FILTERS: { value: VerdictFilter; label: string }[] = [
  { value: "actionable", label: "Actionable" },
  { value: "true_positive", label: "Confirmed" },
  { value: "needs_human", label: "Needs review" },
  { value: "false_positive", label: "Dismissed" },
  { value: "all", label: "All" },
];

const DOMAINS: { value: Domain; label: string }[] = [
  { value: "sast", label: "Code" },
  { value: "sca", label: "Dependencies" },
  { value: "secret", label: "Secrets" },
];

const verdictOf = (i: Issue): Verdict => i.analysis?.verdict ?? "needs_human";

export function FindingsView({ issues, triageEnabled }: { issues: Issue[]; triageEnabled: boolean }) {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [domain, setDomain] = useState<Domain | null>(null);
  const [verdict, setVerdict] = useState<VerdictFilter>("actionable");

  const sorted = useMemo(() => [...issues].sort((a, b) => b.score - a.score), [issues]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sorted.filter((i) => {
      const v = verdictOf(i);
      if (verdict === "actionable" && v === "false_positive") return false;
      if (verdict !== "actionable" && verdict !== "all" && v !== verdict) return false;
      if (severities.length && !severities.includes(i.finding.severity)) return false;
      if (domain && i.finding.domain !== domain) return false;
      if (!q) return true;
      const f = i.finding;
      return [f.title, f.location.file_path, f.rule_id, f.cve_id ?? "", f.package?.name ?? "", ...f.cwe_ids]
        .some((s) => s.toLowerCase().includes(q));
    });
  }, [sorted, query, severities, domain, verdict]);

  const counts = useMemo(() => {
    const c: Record<VerdictFilter, number> = { actionable: 0, true_positive: 0, needs_human: 0, false_positive: 0, all: issues.length };
    for (const i of issues) {
      const v = verdictOf(i);
      c[v] += 1;
      if (v !== "false_positive") c.actionable += 1;
    }
    return c;
  }, [issues]);

  const selectedId = params.get("issue");
  const selected = filtered.find((i) => i.issue_id === selectedId) ?? filtered[0] ?? null;

  const select = (id: string) => {
    const next = new URLSearchParams(params);
    next.set("issue", id);
    setParams(next, { replace: true });
  };

  // Keep keyboard navigation through the filtered list.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!selected || (e.target as HTMLElement).closest("input, textarea")) return;
      if (e.key !== "j" && e.key !== "k") return;
      const idx = filtered.indexOf(selected);
      const next = filtered[idx + (e.key === "j" ? 1 : -1)];
      if (next) select(next.issue_id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const toggleSeverity = (s: Severity) =>
    setSeverities((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  if (issues.length === 0) {
    return (
      <div className="list-empty card">
        <SearchX size={22} />
        <p>No findings in this scan.</p>
      </div>
    );
  }

  return (
    <div className="findings">
      <div className="toolbar">
        <div className="tabs-inline" role="tablist">
          {VERDICT_FILTERS.map((f) => (
            <button key={f.value} type="button" role="tab" aria-selected={verdict === f.value}
              className={verdict === f.value ? "on" : ""} onClick={() => setVerdict(f.value)}>
              {f.label} <span className="count">{counts[f.value]}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-row">
          <div className="input input-sm search">
            <Search size={14} />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search title, file, CVE, package…" />
          </div>
          <div className="chip-group" aria-label="Severity filter">
            {SEVERITIES.filter((s) => s !== "info").map((s) => (
              <button key={s} type="button" className={`chip chip-sev-${s}${severities.includes(s) ? " on" : ""}`} onClick={() => toggleSeverity(s)}>
                {s}
              </button>
            ))}
          </div>
          <div className="chip-group" aria-label="Type filter">
            {DOMAINS.map((d) => (
              <button key={d.value} type="button" className={`chip${domain === d.value ? " on" : ""}`}
                onClick={() => setDomain(domain === d.value ? null : d.value)}>
                {d.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="split">
        <div className="issue-list" role="listbox" aria-label="Findings">
          {filtered.length === 0 ? (
            <div className="list-empty">
              <SearchX size={22} />
              <p>Nothing matches these filters.</p>
            </div>
          ) : (
            filtered.map((issue) => {
              const f = issue.finding;
              return (
                <button key={issue.issue_id} type="button" role="option" aria-selected={issue === selected}
                  className={`issue-row${issue === selected ? " selected" : ""}`} onClick={() => select(issue.issue_id)}>
                  <span className={`score-pill score-${f.severity}`}>{issue.score.toFixed(0)}</span>
                  <span className="issue-main">
                    <strong>{f.package ? `${f.package.name} ${f.package.installed_version}` : f.title}</strong>
                    <small className="mono">
                      {f.package ? f.cve_id ?? f.rule_id : `${f.location.file_path}:${f.location.line_start}`}
                    </small>
                    <span className="issue-tags">
                      <SeverityBadge severity={f.severity} />
                      <DomainTag domain={f.domain} />
                      {issue.tools.length > 1 && <span className="chip chip-xs">{issue.tools.length} tools</span>}
                    </span>
                  </span>
                  <VerdictBadge verdict={verdictOf(issue)} triaged={issue.analysis !== null} />
                </button>
              );
            })
          )}
        </div>
        <div className="detail-pane">
          {selected ? <FindingDetail key={selected.issue_id} issue={selected} triageEnabled={triageEnabled} /> : null}
        </div>
      </div>
      <p className="kbd-hint mono">j / k to move through findings</p>
    </div>
  );
}

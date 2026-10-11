import type { Severity } from "../api/types";
import { SEVERITIES } from "../lib/format";

/** A thin stacked bar of issue counts by severity. */
export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) return <div className="sev-bar sev-bar-empty" aria-label="no actionable issues" />;
  return (
    <div className="sev-bar" role="img"
      aria-label={SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}>
      {SEVERITIES.map((s) =>
        counts[s] ? <span key={s} className={`sev-seg sev-bg-${s}`} style={{ flexGrow: counts[s] }} /> : null,
      )}
    </div>
  );
}

import type { Scan, StepRecord } from "../../api/types";
import { StepIcon } from "../../components/Badges";
import { PIPELINE, duration, stepLabel } from "../../lib/format";

type RowStatus = StepRecord["status"] | "running" | "pending";
interface Row {
  key: string;
  label: string;
  status: RowStatus;
  detail: string;
  ms: number | null;
}

/** Expand recorded steps against the full pipeline so pending and in-flight
 * stages show up too. "scan" fans out into one row per scanner. */
function buildRows(scan: Scan): Row[] {
  const byName = new Map(scan.steps.map((s) => [s.step, s]));
  const active = scan.status === "running" || scan.status === "queued";
  const rows: Row[] = [];

  for (const stage of PIPELINE) {
    const recorded = stage === "scan" ? scan.steps.filter((s) => s.step.startsWith("scan:")) : byName.has(stage) ? [byName.get(stage)!] : [];
    for (const s of recorded) {
      rows.push({ key: s.step, label: stepLabel(s.step), status: s.status, detail: s.detail, ms: s.duration_ms });
    }
    const running = active && scan.current_step === stage;
    if (recorded.length === 0 || (running && stage === "scan")) {
      rows.push({
        key: `${stage}-live`,
        label: stepLabel(stage),
        status: running ? "running" : "pending",
        detail: running ? scan.progress ?? "in progress…" : "",
        ms: null,
      });
    }
  }
  // A failed scan never reaches the later stages; don't show them as waiting.
  return scan.status === "failed" ? rows.filter((r) => r.status !== "pending") : rows;
}

export function PipelineTrace({ scan }: { scan: Scan }) {
  const rows = buildRows(scan);
  const total = rows.reduce((sum, r) => sum + (r.ms ?? 0), 0) || 1;
  let offset = 0;

  return (
    <div className="trace">
      <div className="trace-head mono-label">
        <span>Stage</span>
        <span>Timeline</span>
        <span className="num">Time</span>
      </div>
      {rows.map((row) => {
        const left = (offset / total) * 100;
        const width = row.ms ? Math.max((row.ms / total) * 100, 0.6) : 0;
        offset += row.ms ?? 0;
        return (
          <div key={row.key} className={`trace-row trace-${row.status}`}>
            <div className="trace-name">
              <StepIcon status={row.status} />
              <span>
                <strong>{row.label}</strong>
                {row.detail && <small>{row.detail}</small>}
              </span>
            </div>
            <div className="trace-track">
              {row.status === "running" ? (
                <span className="trace-bar trace-bar-live" />
              ) : row.ms !== null ? (
                <span className="trace-bar" style={{ left: `${left}%`, width: `${width}%` }} />
              ) : null}
            </div>
            <span className="num mono trace-ms">{row.ms !== null ? duration(row.ms) : ""}</span>
          </div>
        );
      })}
    </div>
  );
}

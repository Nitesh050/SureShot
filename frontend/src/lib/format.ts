import type { Scan, Severity } from "../api/types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function timeAgo(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 45) return "just now";
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)}h ago`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function duration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export function scanDuration(scan: Scan): number | null {
  if (!scan.started_at) return null;
  const end = scan.finished_at ? new Date(scan.finished_at) : new Date();
  return end.getTime() - new Date(scan.started_at).getTime();
}

/** Share of raw scanner output that never reaches a human as actionable. */
export function noiseReduction(scan: Scan): number | null {
  const s = scan.summary;
  if (!s || s.raw_findings === 0) return null;
  return 1 - s.actionable / s.raw_findings;
}

export function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export const STEP_LABELS: Record<string, string> = {
  fetch: "Fetch source",
  profile: "Profile repository",
  scan: "Run scanners",
  fingerprint: "Fingerprint & context",
  redact: "Redact secrets",
  triage: "AI triage",
  score: "Risk scoring",
  report: "Dedupe & report",
};

export function stepLabel(step: string): string {
  if (step.startsWith("scan:")) return `Scan · ${step.slice(5)}`;
  return STEP_LABELS[step] ?? step;
}

export const PIPELINE: string[] = ["fetch", "profile", "scan", "fingerprint", "redact", "triage", "score", "report"];

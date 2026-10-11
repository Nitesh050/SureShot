export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "true_positive" | "false_positive" | "needs_human";
export type Domain = "sast" | "sca" | "secret" | "iac";
export type LlmBackend = "anthropic" | "ollama";
export type ReportFormat = "json" | "sarif" | "html" | "pdf";

export interface ScanSource {
  kind: "url" | "upload";
  label: string;
  url: string | null;
  ref: string | null;
  commit: string | null;
  filename: string | null;
}

export interface ScanOptions {
  scanners: string[] | null;
  triage: boolean;
  llm: LlmBackend;
}

export interface StepRecord {
  step: string;
  status: "ok" | "degraded" | "failed";
  detail: string;
  duration_ms: number;
}

export interface ScanSummary {
  raw_findings: number;
  issues: number;
  actionable: number;
  dismissed: number;
  needs_review: number;
  multi_tool: number;
  by_severity: Record<Severity, number>;
}

export interface RepoProfile {
  total_files: number;
  scanned_files: number;
  skipped_files: number;
  total_bytes: number;
  languages: { name: string; files: number; bytes: number }[];
  ecosystems: { name: string; manifests: string[]; lockfiles: string[] }[];
  coverage: { domain: Domain; coverage: "full" | "partial" | "none"; reason: string }[];
}

export interface Scan {
  id: string;
  status: ScanStatus;
  source: ScanSource;
  options: ScanOptions;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  current_step: string | null;
  progress: string | null;
  steps: StepRecord[];
  profile: RepoProfile | null;
  summary: ScanSummary | null;
  notes: string[];
  error: string | null;
  reports: ReportFormat[];
}

export interface Location {
  file_path: string;
  line_start: number;
  line_end: number;
}

export interface Finding {
  instance_id: string;
  issue_id: string;
  tool: string;
  tool_version: string;
  rule_id: string;
  domain: Domain;
  title: string;
  description: string;
  severity: Severity;
  cwe_ids: string[];
  cve_id: string | null;
  location: Location;
  package: { name: string; installed_version: string; fixed_version: string | null; is_direct: boolean | null } | null;
  secret: { kind: string; last_four: string } | null;
}

export interface Analysis {
  verdict: Verdict;
  confidence: number;
  rationale: string;
  evidence: { location: Location; note: string }[];
  impact: string;
  remediation: string;
  model_id: string;
  prompt_version: string;
  guard_holds: string[];
}

export interface Issue {
  issue_id: string;
  occurrences: number;
  tools: string[];
  confirmed_by_multiple_tools: boolean;
  finding: Finding;
  analysis: Analysis | null;
  score: number;
  contributions: Record<string, number>;
  holds: string[];
  duplicates: {
    instance_id: string;
    tool: string;
    rule_id: string;
    title: string;
    severity: Severity;
    cwe_ids: string[];
    score: number;
    location: string;
  }[];
  snippet: { context: string; context_start: number; truncated: boolean } | null;
}

export interface FindingsReport {
  scan_id: string;
  generated_at: string;
  provenance: { model_id: string | null; tools: { name: string; version: string }[] };
  issues: Issue[];
}

export interface Capabilities {
  scanners: { name: string; installed: boolean }[];
  llm: Record<LlmBackend, boolean>;
}

import { AlertTriangle, CheckCircle2, CircleDashed, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion, XCircle } from "lucide-react";
import type { Domain, ScanStatus, Severity, Verdict } from "../api/types";
import { stepLabel } from "../lib/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev sev-${severity}`}>{severity}</span>;
}

const VERDICT: Record<Verdict, { label: string; icon: typeof ShieldAlert }> = {
  true_positive: { label: "Confirmed", icon: ShieldAlert },
  false_positive: { label: "Dismissed", icon: ShieldCheck },
  needs_human: { label: "Needs review", icon: ShieldQuestion },
};

export function VerdictBadge({ verdict, triaged }: { verdict: Verdict; triaged: boolean }) {
  if (!triaged) return <span className="verdict verdict-none">Not triaged</span>;
  const { label, icon: Icon } = VERDICT[verdict];
  return (
    <span className={`verdict verdict-${verdict}`}>
      <Icon size={12} /> {label}
    </span>
  );
}

const DOMAIN_LABEL: Record<Domain, string> = { sast: "Code", sca: "Dependency", secret: "Secret", iac: "IaC" };

export function DomainTag({ domain }: { domain: Domain }) {
  return <span className={`domain domain-${domain}`}>{DOMAIN_LABEL[domain]}</span>;
}

export function StatusPill({ status, step }: { status: ScanStatus; step?: string | null }) {
  if (status === "running" || status === "queued") {
    return (
      <span className="status status-running">
        <Loader2 size={12} className="spin" />
        {status === "queued" ? "Queued" : step ? stepLabel(step) : "Running"}
      </span>
    );
  }
  if (status === "failed") return <span className="status status-failed"><XCircle size={12} /> Failed</span>;
  return <span className="status status-done"><CheckCircle2 size={12} /> Completed</span>;
}

export function StepIcon({ status }: { status: "ok" | "degraded" | "failed" | "running" | "pending" }) {
  if (status === "ok") return <CheckCircle2 size={15} className="step-ok" />;
  if (status === "degraded") return <AlertTriangle size={15} className="step-degraded" />;
  if (status === "failed") return <XCircle size={15} className="step-failed" />;
  if (status === "running") return <Loader2 size={15} className="spin step-running" />;
  return <CircleDashed size={15} className="step-pending" />;
}

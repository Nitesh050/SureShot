import { Activity, ArrowUpRight, CheckCircle2, LockKeyhole } from "lucide-react";
import { useState } from "react";
import { BrandMark } from "../../components/BrandMark";
import { AuthProviderButtons } from "./AuthProviderButtons";
import { EmailLoginForm } from "./EmailLoginForm";

export function LoginPage() {
  const [notice, setNotice] = useState("");

  return (
    <main className="auth-layout">
      <section className="auth-visual" aria-label="SureShot product overview">
        <div className="visual-content">
          <BrandMark />
          <div className="eyebrow"><span className="eyebrow-dot" /> Security that keeps up</div>
          <h1>Ship with confidence.<br /><em>Find risk before it finds you.</em></h1>
          <p className="visual-copy">
            One clear view of every vulnerability across your codebase, dependencies, and cloud.
          </p>
          <div className="signal-card">
            <div className="signal-header">
              <span><Activity size={15} /> Live security posture</span>
              <span className="live-badge">LIVE</span>
            </div>
            <div className="signal-score"><strong>94</strong><span>/ 100</span><small>+8.4% this month</small></div>
            <div className="signal-bars"><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /></div>
            <div className="signal-footer"><span><CheckCircle2 size={14} /> 12 checks passed today</span><ArrowUpRight size={15} /></div>
          </div>
          <div className="trust-row">
            <span><LockKeyhole size={14} /> SOC 2 Type II ready</span>
            <span>Trusted by teams building what’s next</span>
          </div>
        </div>
        <div className="visual-glow glow-one" /><div className="visual-glow glow-two" />
      </section>

      <section className="auth-panel">
        <div className="mobile-brand"><BrandMark /></div>
        <div className="auth-card">
          <div className="auth-heading">
            <p className="welcome">WELCOME BACK</p>
            <h2>Sign in to your workspace</h2>
            <p>New to SureShot? <a href="#create-account">Create an account</a></p>
          </div>
          <AuthProviderButtons onProviderSelect={(provider) => setNotice(`${provider} sign-in will connect here.`)} />
          <div className="divider"><span>or continue with email</span></div>
          <EmailLoginForm onSubmit={(email) => setNotice(`Sign-in submitted for ${email}.`)} />
          {notice && <p className="form-notice" role="status">{notice}</p>}
          <p className="legal">By continuing, you agree to our <a href="#terms">Terms of Service</a> and <a href="#privacy">Privacy Policy</a>.</p>
        </div>
        <footer className="auth-footer"><span>© 2025 SureShot, Inc.</span><a href="#help">Need help? <ArrowUpRight size={13} /></a></footer>
      </section>
    </main>
  );
}

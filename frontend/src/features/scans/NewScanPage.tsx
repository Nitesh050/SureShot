import { ArrowRight, FileArchive, GitBranch, Github, Link2, Loader2, Sparkles, UploadCloud, X } from "lucide-react";
import { useEffect, useRef, useState, type DragEvent, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Capabilities, LlmBackend } from "../../api/types";

type SourceMode = "url" | "upload";
type ScannerMode = "auto" | "custom";

const SCANNERS = [
  { name: "semgrep", title: "Semgrep", kind: "SAST", blurb: "Vulnerable code patterns: injection, XSS, unsafe APIs.", auto: "always runs" },
  { name: "trivy", title: "Trivy", kind: "SCA + Secrets", blurb: "Known CVEs in lockfiles, plus hardcoded credentials.", auto: "always runs" },
  { name: "codeql", title: "CodeQL", kind: "Deep SAST", blurb: "Semantic dataflow analysis. Slower; builds a database.", auto: "runs when the language is supported" },
];

const ARCHIVE_TYPES = ".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz";
const MAX_MB = 200;

export function NewScanPage() {
  const navigate = useNavigate();
  const fileInput = useRef<HTMLInputElement>(null);

  const [mode, setMode] = useState<SourceMode>("url");
  const [repoUrl, setRepoUrl] = useState("");
  const [ref, setRef] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);

  const [scannerMode, setScannerMode] = useState<ScannerMode>("auto");
  const [selected, setSelected] = useState<string[]>(["semgrep", "trivy"]);
  const [triage, setTriage] = useState(true);
  const [llm, setLlm] = useState<LlmBackend>("anthropic");

  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.capabilities()
      .then((c) => {
        setCaps(c);
        // Without an API key Claude can't triage; default to the local model.
        if (!c.llm.anthropic) setLlm("ollama");
      })
      .catch(() => setCaps(null));
  }, []);

  const installed = (name: string) => caps?.scanners.find((s) => s.name === name)?.installed ?? true;

  const toggleScanner = (name: string) =>
    setSelected((cur) => (cur.includes(name) ? cur.filter((n) => n !== name) : [...cur, name]));

  const pickFile = (f: File | undefined | null) => {
    if (!f) return;
    if (f.size > MAX_MB * 1024 * 1024) {
      setError(`That archive is ${(f.size / 1024 / 1024).toFixed(0)} MB; the limit is ${MAX_MB} MB.`);
      return;
    }
    setError(null);
    setFile(f);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    pickFile(e.dataTransfer.files?.[0]);
  };

  const canSubmit =
    !submitting &&
    (mode === "url" ? repoUrl.trim().length > 0 : file !== null) &&
    (scannerMode === "auto" || selected.length > 0);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    const opts = { scanners: scannerMode === "auto" ? null : selected, triage, llm };
    try {
      const scan = mode === "url"
        ? await api.scanUrl(repoUrl.trim(), ref.trim() || null, opts)
        : await api.scanUpload(file!, opts);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError((err as Error).message);
      setSubmitting(false);
    }
  };

  const claudeMissing = caps !== null && !caps.llm.anthropic && llm === "anthropic" && triage;

  return (
    <div className="page page-narrow">
      <header className="page-head">
        <div>
          <p className="mono-label">New scan</p>
          <h1 className="page-title">What should we scan?</h1>
        </div>
      </header>

      <form className="new-scan" onSubmit={submit}>
        <div className="new-scan-main">
          <section className="card form-section">
            <div className="segmented" role="tablist" aria-label="Source">
              <button type="button" role="tab" aria-selected={mode === "url"} className={mode === "url" ? "on" : ""} onClick={() => setMode("url")}>
                <Link2 size={15} /> Repository link
              </button>
              <button type="button" role="tab" aria-selected={mode === "upload"} className={mode === "upload" ? "on" : ""} onClick={() => setMode("upload")}>
                <UploadCloud size={15} /> Upload archive
              </button>
            </div>

            {mode === "url" ? (
              <div className="field-stack">
                <label className="field">
                  <span>Repository URL</span>
                  <div className="input">
                    <Github size={16} />
                    <input autoFocus value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo" spellCheck={false} />
                  </div>
                  <small>Public repositories on GitHub, GitLab or Bitbucket. A <code>/tree/branch</code> link works too.</small>
                </label>
                <label className="field">
                  <span>Branch or tag <em>optional</em></span>
                  <div className="input">
                    <GitBranch size={16} />
                    <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="default branch" spellCheck={false} />
                  </div>
                </label>
              </div>
            ) : (
              <div
                className={`dropzone${dragging ? " dragging" : ""}${file ? " has-file" : ""}`}
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                onClick={() => !file && fileInput.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && !file && fileInput.current?.click()}
              >
                <input ref={fileInput} type="file" accept={ARCHIVE_TYPES} hidden onChange={(e) => pickFile(e.target.files?.[0])} />
                {file ? (
                  <div className="file-chip">
                    <FileArchive size={20} />
                    <span><strong>{file.name}</strong><small>{(file.size / 1024 / 1024).toFixed(1)} MB</small></span>
                    <button type="button" className="icon-btn" aria-label="Remove file" onClick={(e) => { e.stopPropagation(); setFile(null); }}>
                      <X size={16} />
                    </button>
                  </div>
                ) : (
                  <>
                    <UploadCloud size={28} />
                    <strong>Drop a .zip or .tar.gz here</strong>
                    <small>or click to browse · up to {MAX_MB} MB · works for private code</small>
                  </>
                )}
              </div>
            )}
          </section>

          <section className="card form-section">
            <div className="section-head">
              <div>
                <h2>Scanners</h2>
                <p>Auto mode picks scanners from the repo's languages and lockfiles.</p>
              </div>
              <div className="segmented segmented-sm">
                <button type="button" className={scannerMode === "auto" ? "on" : ""} onClick={() => setScannerMode("auto")}>Auto</button>
                <button type="button" className={scannerMode === "custom" ? "on" : ""} onClick={() => setScannerMode("custom")}>Custom</button>
              </div>
            </div>
            <div className={`scanner-grid${scannerMode === "auto" ? " is-auto" : ""}`}>
              {SCANNERS.map((s) => {
                const ok = installed(s.name);
                const on = scannerMode === "auto" ? ok && s.name !== "codeql" : selected.includes(s.name);
                return (
                  <label key={s.name} className={`scanner-card${on ? " on" : ""}${ok ? "" : " missing"}`}>
                    {scannerMode === "custom" && (
                      <input type="checkbox" checked={on} disabled={!ok} onChange={() => toggleScanner(s.name)} />
                    )}
                    <span className="scanner-top">
                      <strong>{s.title}</strong>
                      <em className="mono">{s.kind}</em>
                    </span>
                    <small>{ok ? s.blurb : "Not installed on this server."}</small>
                    {scannerMode === "auto" && ok && <small className="auto-note">{s.auto}</small>}
                  </label>
                );
              })}
            </div>
          </section>

          <section className="card form-section">
            <div className="section-head">
              <div>
                <h2><Sparkles size={16} className="accent" /> AI triage</h2>
                <p>An LLM reads each finding with its code context and decides: real issue, false positive, or needs a human.</p>
              </div>
              <button type="button" role="switch" aria-checked={triage} className={`switch${triage ? " on" : ""}`} onClick={() => setTriage(!triage)}>
                <span />
              </button>
            </div>
            {triage && (
              <div className="llm-options">
                <label className={`radio-card${llm === "anthropic" ? " on" : ""}`}>
                  <input type="radio" name="llm" checked={llm === "anthropic"} onChange={() => setLlm("anthropic")} />
                  <strong>Claude</strong><small>Anthropic API · best accuracy</small>
                </label>
                <label className={`radio-card${llm === "ollama" ? " on" : ""}`}>
                  <input type="radio" name="llm" checked={llm === "ollama"} onChange={() => setLlm("ollama")} />
                  <strong>Ollama</strong><small>Local model · code never leaves this machine</small>
                </label>
              </div>
            )}
            {claudeMissing && (
              <p className="inline-warn">ANTHROPIC_API_KEY isn't set on the API server, so this scan will run without triage.</p>
            )}
          </section>
        </div>

        <aside className="new-scan-side">
          <div className="card pipeline-preview">
            <p className="mono-label">Pipeline</p>
            <ol>
              <li><b>Fetch</b> shallow clone or safe unpack into an isolated workdir</li>
              <li><b>Profile</b> languages, lockfiles, coverage</li>
              <li><b>Scan</b> tools run sandboxed with time and output limits</li>
              <li><b>Fingerprint</b> stable IDs that survive line shifts</li>
              <li><b>Redact</b> secrets stripped before any LLM sees code</li>
              <li><b>Triage</b> verdict, confidence and cited evidence</li>
              <li><b>Report</b> cross-tool dedup → JSON, SARIF, HTML, PDF</li>
            </ol>
          </div>
          {error && <div className="banner banner-error">{error}</div>}
          <button type="submit" className="btn btn-accent btn-block" disabled={!canSubmit}>
            {submitting ? <><Loader2 size={16} className="spin" /> Starting…</> : <>Start scan <ArrowRight size={16} /></>}
          </button>
        </aside>
      </form>
    </div>
  );
}

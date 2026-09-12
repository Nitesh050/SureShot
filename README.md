# SureShot

An LLM-assisted security scanning pipeline: ingest a repository, run static
scanners, normalize and fingerprint findings, and (eventually) triage them
with an LLM to cut false-positive noise before a human ever sees them.

This is a `uv` workspace of small, single-purpose packages plus a set of
services. Most of the scaffolding for the full system exists; only some of
it is implemented so far. This README reflects the current state, not the
target architecture.

## Layout

```
packages/
  sureshot-domain       pydantic models: findings, scan state, repo profile, enums
  sureshot-engine       ingest, scanners, normalization, LLM triage
  sureshot-contracts    versioning (stub)
  sureshot-persistence  outbox / retention / row-level security (stub)
  sureshot-platform     config, logging, ids, secrets (stub)
  sureshot-reporting    HTML/JSON/PDF/SARIF writers (stub)
services/
  cli                   `sureshot scan <path>` — working end to end
  api / worker / scheduler   stubs, not yet implemented
eval/
  harness.py, gates.py, metrics.py   scan-and-score eval loop against
                                      hand-labeled fixtures
tests/unit/            mirrors the package layout
```

## What actually works today

- **Ingest** (`sureshot.engine.ingest`): safe zip/tar extraction with
  size/count/symlink/path-escape limits (`safety.py`, `unpack.py`), an
  isolated scan workdir with guaranteed teardown (`workdir.py`), and a
  repo profiler that detects languages, dependency ecosystems, and
  SAST/SCA coverage (`profiler.py`).
- **Scanning** (`sureshot.engine.scanners`): a sandboxed subprocess runner
  with timeouts, rlimits, and output truncation (`sandbox.py`), and a full
  Semgrep integration (`semgrep/scanner.py`, `rulesets.py`, `adapter.py`)
  that maps raw Semgrep JSON into normalized `SecurityFinding`s — CWE
  extraction, severity mapping, repo-relative paths, secret redaction.
- **Context** (`sureshot.engine.context.snippet`): extracts matched source
  + surrounding context per finding, batched to read each file once.
- **Normalization** (`sureshot.engine.normalize.fingerprint`): stable
  `instance_id`/`issue_id` fingerprints that survive line shifts and
  formatting-only diffs, so re-scans don't churn.
- **LLM triage schema** (`sureshot.engine.intelligence`): the prompt
  template (`prompts/triage.v3.md`) and the response schema
  (`llm/schemas.py`) that enforces the triage invariants (a dismissal
  can't claim untrusted input reachability, high confidence requires
  determinate reachability, decisive verdicts require citations). The
  actual Anthropic API client (`llm/client.py`, `llm/triage.py`) is not
  implemented yet — this is next.
- **CLI** (`services/cli`): `sureshot scan <path>` stages a repo or
  archive, profiles it, runs Semgrep, fingerprints the findings, and
  prints a Rich table — or writes `--json`. Verified working end to end.
- **Eval harness** (`eval/`): scans a small hand-labeled fixture set
  (`eval/datasets/internal/`) and scores precision/recall/hold-rate/noise
  reduction against `eval/labels/internal.yaml`, with pass/fail gates in
  `eval/gates.py`.

## Not implemented yet (empty stubs)

`ingest/fetch.py`, `context/{budget,related,symbols}.py`,
`normalize/{dedupe,grouping}.py`, `pipeline/*` (no orchestration wiring
ingest → scan → triage together yet), `guards/*` (injection/redaction/
policy/evidence), `risk/*`, `scanners/{orchestrator,registry}.py`,
`scanners/trivy/*`, `intelligence/llm/{client,triage,budget,cache}.py`,
`intelligence/knowledge/*`, and all of `sureshot-persistence`,
`sureshot-platform`, `sureshot-reporting`, `sureshot-contracts`, and the
`api`/`worker`/`scheduler` services.

## Setup

Requires [uv](https://docs.astral.sh/uv/) and Python ≥3.12.

```bash
uv sync
```

## Running the CLI

```bash
uv run sureshot scan <path-to-repo-or-archive>
uv run sureshot scan <path> --json findings.json --timeout 300
```

Requires a `semgrep` binary on `PATH`.

## Tests

```bash
uv run pytest
```

146 tests across `tests/unit/{domain,ingest,context,normalize,scanners,
intelligence}`. Two known non-failures on this machine, not code bugs:

- `test_semgrep_real.py::test_real_scan_finds_sql_injection` — requires an
  authenticated local `semgrep` (`semgrep login`); the unauthenticated
  registry rule set doesn't include the rule this fixture needs.
- `test_sandbox.py::test_memory_limit_kills_runaway_allocation` — skipped
  on macOS, which doesn't enforce `RLIMIT_AS`.

## Eval

```bash
uv run python -m eval.harness   # scan + score, writes eval/runs/<ts>-baseline.json
uv run python -m eval.gates     # pass/fail against the latest run
```

Gates: recall ≥ 0.95, hold_rate ≤ 0.40, noise_reduction ≥ 0.15. On this
machine the baseline run currently scores `n=0` — the same unauthenticated
`semgrep` registry limitation noted above means the scanner finds nothing
in the eval fixtures either, so the gates fail on recall and noise
reduction by having no signal at all, not by real triage behavior. With
an authenticated `semgrep`, the `keep_everything` baseline (no triage)
should satisfy recall trivially while failing noise_reduction/hold_rate
by design — it exists to be beaten once real triage lands.

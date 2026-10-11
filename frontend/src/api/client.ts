import type { Capabilities, FindingsReport, LlmBackend, ReportFormat, Scan } from "./types";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`/api${path}`, init);
  } catch {
    throw new ApiError("Can't reach the SureShot API. Is it running? (uv run sureshot-api)", 0);
  }
  if (!resp.ok) {
    let message = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, resp.status);
  }
  return resp.json() as Promise<T>;
}

export interface ScanRequestOptions {
  scanners: string[] | null;
  triage: boolean;
  llm: LlmBackend;
}

export const api = {
  capabilities: () => request<Capabilities>("/capabilities"),
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  findings: (id: string) => request<FindingsReport>(`/scans/${id}/findings`),

  scanUrl: (repoUrl: string, ref: string | null, opts: ScanRequestOptions) =>
    request<Scan>("/scans", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl, ref, ...opts }),
    }),

  scanUpload: (file: File, opts: ScanRequestOptions) => {
    const form = new FormData();
    form.append("file", file);
    if (opts.scanners) form.append("scanners", opts.scanners.join(","));
    form.append("triage", String(opts.triage));
    form.append("llm", opts.llm);
    return request<Scan>("/scans/upload", { method: "POST", body: form });
  },

  reportUrl: (id: string, fmt: ReportFormat) => `/api/scans/${id}/report/${fmt}`,
};

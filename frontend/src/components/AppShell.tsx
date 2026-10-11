import { Cpu, LayoutList, Plus, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api/client";
import type { Capabilities } from "../api/types";
import { BrandMark } from "./BrandMark";

export function AppShell() {
  const [caps, setCaps] = useState<Capabilities | null>(null);

  useEffect(() => {
    api.capabilities().then(setCaps).catch(() => setCaps(null));
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <BrandMark />
        <nav className="side-nav" aria-label="Main">
          <NavLink to="/" end className="side-link">
            <LayoutList size={16} /> Scans
          </NavLink>
          <NavLink to="/new" className="side-link">
            <Plus size={16} /> New scan
          </NavLink>
        </nav>

        <section className="engine-status" aria-label="Engine status">
          <p className="mono-label">Engine</p>
          {caps ? (
            <>
              {caps.scanners.map((s) => (
                <div key={s.name} className="engine-row">
                  <Cpu size={13} />
                  <span>{s.name}</span>
                  <i className={s.installed ? "dot dot-ok" : "dot dot-off"} title={s.installed ? "installed" : "not installed"} />
                </div>
              ))}
              <div className="engine-row">
                <Sparkles size={13} />
                <span>Claude</span>
                <i className={caps.llm.anthropic ? "dot dot-ok" : "dot dot-off"} title={caps.llm.anthropic ? "API key set" : "ANTHROPIC_API_KEY not set"} />
              </div>
            </>
          ) : (
            <p className="engine-offline">API offline</p>
          )}
        </section>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

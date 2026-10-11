import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { LoginPage } from "./features/auth/LoginPage";
import { NewScanPage } from "./features/scans/NewScanPage";
import { ScanDetailPage } from "./features/scans/ScanDetailPage";
import { ScansPage } from "./features/scans/ScansPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Auth is not wired to a backend yet; the page stays reachable for design work. */}
        <Route path="/login" element={<LoginPage />} />
        <Route element={<AppShell />}>
          <Route index element={<ScansPage />} />
          <Route path="new" element={<NewScanPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

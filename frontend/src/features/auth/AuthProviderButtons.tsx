import { Github, KeyRound } from "lucide-react";

type Provider = "google" | "github" | "sso" | "passkey";

type AuthProviderButtonsProps = {
  onProviderSelect: (provider: Provider) => void;
};

export function AuthProviderButtons({
  onProviderSelect,
}: AuthProviderButtonsProps) {
  return (
    <div className="provider-grid">
      <button className="provider-button" onClick={() => onProviderSelect("google")}>
        <span className="google-g" aria-hidden="true">G</span>
        Continue with Google
      </button>
      <button className="provider-button" onClick={() => onProviderSelect("github")}>
        <Github size={18} aria-hidden="true" />
        Continue with GitHub
      </button>
      <button className="provider-button" onClick={() => onProviderSelect("sso")}>
        <span className="provider-icon" aria-hidden="true"><KeyRound size={17} /></span>
        Continue with SSO
      </button>
      <button className="provider-button" onClick={() => onProviderSelect("passkey")}>
        <span className="provider-icon" aria-hidden="true"><KeyRound size={17} /></span>
        Sign in with a passkey
      </button>
    </div>
  );
}

import { ShieldCheck } from "lucide-react";

export function BrandMark() {
  return (
    <a className="brand-mark" href="/" aria-label="SureShot home">
      <span className="brand-icon" aria-hidden="true">
        <ShieldCheck size={21} strokeWidth={2.4} />
      </span>
      <span>SureShot</span>
    </a>
  );
}

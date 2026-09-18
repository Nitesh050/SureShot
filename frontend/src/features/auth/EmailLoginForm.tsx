import { ArrowRight, Eye, EyeOff, Mail } from "lucide-react";
import { FormEvent, useState } from "react";

type EmailLoginFormProps = {
  onSubmit: (email: string) => void;
};

export function EmailLoginForm({ onSubmit }: EmailLoginFormProps) {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(email);
  }

  return (
    <form className="login-form" onSubmit={handleSubmit}>
      <label htmlFor="email">Work email</label>
      <div className="input-wrap">
        <Mail size={17} aria-hidden="true" />
        <input
          id="email"
          type="email"
          autoComplete="email"
          placeholder="you@company.com"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
      </div>
      <div className="password-label">
        <label htmlFor="password">Password</label>
        <a href="#forgot-password">Forgot password?</a>
      </div>
      <div className="input-wrap">
        <input
          id="password"
          type={showPassword ? "text" : "password"}
          autoComplete="current-password"
          placeholder="Enter your password"
          required
        />
        <button
          className="icon-button"
          type="button"
          aria-label={showPassword ? "Hide password" : "Show password"}
          onClick={() => setShowPassword((visible) => !visible)}
        >
          {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
        </button>
      </div>
      <label className="checkbox-label">
        <input type="checkbox" />
        <span>Keep me signed in for 30 days</span>
      </label>
      <button className="primary-button" type="submit">
        Sign in <ArrowRight size={17} aria-hidden="true" />
      </button>
    </form>
  );
}

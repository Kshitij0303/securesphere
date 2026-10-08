import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { resetPassword } from "../api";
import AuthCard from "../components/AuthCard";
import ErrorBox from "../components/ErrorBox";

// Opened from the link in the reset email: /reset-password?token=...
export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (password.length < 8) return setError("Password must be at least 8 characters.");
    if (password !== confirm) return setError("The passwords do not match.");
    setError("");
    setLoading(true);
    try {
      await resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <AuthCard icon="alert" title="Reset link missing">
        <p className="mt-2 text-muted">
          Open the link from your email, or{" "}
          <Link to="/forgot-password" className="link">ask for a new one</Link>.
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthCard icon="key" title="Choose a new password">
      {done ? (
        <div role="status" className="notice mt-6 border-ok/30 bg-ok-soft text-base text-fg">
          <p>Your password has been changed.</p>
          <Link to="/login" className="link mt-2 inline-block">Log in with your new password</Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
          <label className="label">
            New password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" className="input" />
          </label>
          <label className="label">
            Confirm new password
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" className="input" />
          </label>
          <ErrorBox message={error} />
          {error.includes("expired") && (
            <Link to="/forgot-password" className="link block">Ask for a new reset link</Link>
          )}
          <button type="submit" disabled={loading} className="btn-primary w-full py-3">
            {loading ? "Saving…" : "Save new password"}
          </button>
        </form>
      )}
    </AuthCard>
  );
}

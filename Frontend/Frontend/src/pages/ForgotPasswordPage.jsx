import { useState } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../api";
import AuthCard from "../components/AuthCard";
import EmailTypoHint from "../components/EmailTypoHint";
import ErrorBox from "../components/ErrorBox";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!/^\S+@\S+\.\S+$/.test(email)) return setError("Enter a valid email address.");
    setError("");
    setLoading(true);
    try {
      await forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard
      icon="key"
      title="Forgot your password?"
      subtitle={sent ? null : "Enter your account email and we will send you a link to choose a new password."}
      footer={<>Remembered it? <Link to="/login" className="link">Log in</Link></>}
    >
      {sent ? (
        <div role="status" className="notice mt-6 border-ok/30 bg-ok-soft text-base text-fg">
          <p>If an account exists for <strong>{email}</strong>, we have sent a link to reset the password.</p>
          <p className="mt-2 text-sm text-muted">The link works once and expires in 30 minutes. Check your spam folder too.</p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
          <label className="label">
            Email
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" className="input" />
            <EmailTypoHint email={email} onAccept={setEmail} />
          </label>
          <ErrorBox message={error} />
          <button type="submit" disabled={loading} className="btn-primary w-full py-3">
            {loading ? "Please wait…" : "Send reset link"}
          </button>
        </form>
      )}
    </AuthCard>
  );
}

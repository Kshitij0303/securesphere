import { useState } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../api";
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
    <div className="max-w-sm">
      <h1 className="text-3xl font-bold">Forgot your password?</h1>
      {sent ? (
        <div role="status" className="mt-6 rounded-md border border-teal-200 bg-teal-50 px-4 py-3 text-slate-800">
          <p>If an account exists for <strong>{email}</strong>, we have sent a link to reset the password.</p>
          <p className="mt-2 text-sm text-slate-600">The link works once and expires in 30 minutes. Check your spam folder too.</p>
        </div>
      ) : (
        <>
          <p className="mt-2 text-slate-600">Enter your account email and we will send you a link to choose a new password.</p>
          <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
            <label className="block">
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                className="mt-1 w-full rounded-md border border-slate-300 bg-white px-4 py-3 outline-none focus:border-teal-700 focus:ring-2 focus:ring-teal-700/30"
              />
              <EmailTypoHint email={email} onAccept={setEmail} />
            </label>
            <ErrorBox message={error} />
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md bg-teal-700 px-6 py-3 font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
            >
              {loading ? "Please wait…" : "Send reset link"}
            </button>
          </form>
        </>
      )}
      <p className="mt-4 text-slate-600">
        Remembered it? <Link to="/login" className="font-medium text-teal-700 underline">Log in</Link>
      </p>
    </div>
  );
}

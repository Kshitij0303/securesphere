import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { resetPassword } from "../api";
import ErrorBox from "../components/ErrorBox";

const inputClass =
  "mt-1 w-full rounded-md border border-slate-300 bg-white px-4 py-3 outline-none focus:border-teal-700 focus:ring-2 focus:ring-teal-700/30";

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
      <div className="max-w-sm">
        <h1 className="text-3xl font-bold">Reset link missing</h1>
        <p className="mt-2 text-slate-600">
          Open the link from your email, or{" "}
          <Link to="/forgot-password" className="font-medium text-teal-700 underline">ask for a new one</Link>.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-sm">
      <h1 className="text-3xl font-bold">Choose a new password</h1>
      {done ? (
        <div role="status" className="mt-6 rounded-md border border-teal-200 bg-teal-50 px-4 py-3 text-slate-800">
          <p>Your password has been changed.</p>
          <Link to="/login" className="mt-2 inline-block font-medium text-teal-700 underline">Log in with your new password</Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
          <label className="block">
            New password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" className={inputClass} />
          </label>
          <label className="block">
            Confirm new password
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" className={inputClass} />
          </label>
          <ErrorBox message={error} />
          {error.includes("expired") && (
            <Link to="/forgot-password" className="block font-medium text-teal-700 underline">Ask for a new reset link</Link>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-md bg-teal-700 px-6 py-3 font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
          >
            {loading ? "Saving…" : "Save new password"}
          </button>
        </form>
      )}
    </div>
  );
}

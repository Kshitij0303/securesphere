import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { login, signup, saveToken } from "../api";
import EmailTypoHint from "../components/EmailTypoHint";
import ErrorBox from "../components/ErrorBox";

// mode = "login" or "signup"
export default function AuthPage({ mode, onAuth }) {
  const isLogin = mode === "login";
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    if (!isLogin && !name.trim()) return setError("Enter your name.");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setError("Enter a valid email address.");
    if (password.length < 8) return setError("Password must be at least 8 characters.");
    setError("");
    setLoading(true);
    try {
      const res = isLogin ? await login(email, password) : await signup(email, password, name.trim());
      saveToken(res.access_token);
      onAuth();
      navigate("/scan");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "mt-1 w-full rounded-md border border-slate-300 bg-white px-4 py-3 outline-none focus:border-teal-700 focus:ring-2 focus:ring-teal-700/30";

  return (
    <div className="max-w-sm">
      <h1 className="text-3xl font-bold">{isLogin ? "Log in" : "Create your account"}</h1>
      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        {!isLogin && (
          <label className="block">
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={50} autoComplete="name" className={inputClass} />
          </label>
        )}
        <label className="block">
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" className={inputClass} />
          {!isLogin && <EmailTypoHint email={email} onAccept={setEmail} />}
        </label>
        <label className="block">
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputClass} />
        </label>
        {isLogin && (
          <p className="text-right">
            <Link to="/forgot-password" className="text-sm font-medium text-teal-700 underline">Forgot password?</Link>
          </p>
        )}
        <ErrorBox message={error} />
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-md bg-teal-700 px-6 py-3 font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
        >
          {loading ? "Please wait…" : isLogin ? "Log in" : "Sign up"}
        </button>
      </form>
      <p className="mt-4 text-slate-600">
        {isLogin ? "New here? " : "Already have an account? "}
        <Link to={isLogin ? "/signup" : "/login"} className="font-medium text-teal-700 underline">
          {isLogin ? "Create an account" : "Log in"}
        </Link>
      </p>
    </div>
  );
}
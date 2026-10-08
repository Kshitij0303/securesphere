import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { login, signup, saveToken } from "../api";
import AuthCard from "../components/AuthCard";
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

  return (
    <AuthCard
      icon={isLogin ? "lock" : "user"}
      title={isLogin ? "Log in" : "Create your account"}
      subtitle={isLogin ? "Welcome back. Scan, monitor and track your sites." : "Free. Scan sites, get PDF reports and alerts."}
      footer={
        <>
          {isLogin ? "New here? " : "Already have an account? "}
          <Link to={isLogin ? "/signup" : "/login"} className="link">
            {isLogin ? "Create an account" : "Log in"}
          </Link>
        </>
      }
    >
      <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4">
        {!isLogin && (
          <label className="label">
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={50} autoComplete="name" className="input" />
          </label>
        )}
        <label className="label">
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" className="input" />
          {!isLogin && <EmailTypoHint email={email} onAccept={setEmail} />}
        </label>
        <label className="label">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={isLogin ? "current-password" : "new-password"}
            className="input"
          />
          {!isLogin && <span className="mt-1.5 block text-xs font-normal text-subtle">At least 8 characters.</span>}
        </label>
        {isLogin && (
          <p className="text-right">
            <Link to="/forgot-password" className="link text-sm">Forgot password?</Link>
          </p>
        )}
        <ErrorBox message={error} />
        <button type="submit" disabled={loading} className="btn-primary w-full py-3">
          {loading ? "Please wait…" : isLogin ? "Log in" : "Sign up"}
        </button>
      </form>
    </AuthCard>
  );
}

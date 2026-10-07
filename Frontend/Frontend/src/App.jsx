import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { clearToken, getProfile, getToken, getUnreadCount, resendVerification } from "./api";
import Assistant from "./components/Assistant";
import Avatar from "./components/Avatar";
import ProtectedRoute from "./components/ProtectedRoute";
import LandingPage from "./pages/LandingPage";
import ScanPage from "./pages/ScanPage";
import HistoryPage from "./pages/HistoryPage";
import MonitoringPage from "./pages/MonitoringPage";
import AlertsPage from "./pages/AlertsPage";
import AuthPage from "./pages/AuthPage";
import ProfilePage from "./pages/ProfilePage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import ScanResultPage from "./pages/ScanResultPage";
import VerifyEmailPage from "./pages/VerifyEmailPage";

// Shown until the user confirms their email; alerts are only emailed to confirmed addresses.
function VerifyBanner({ email }) {
  const [state, setState] = useState("");
  async function resend() {
    setState("sending");
    try {
      setState((await resendVerification()).message);
    } catch (e) {
      setState(e.message);
    }
  }
  return (
    <div role="status" className="border-b border-amber-200 bg-amber-50">
      <p className="mx-auto max-w-4xl px-4 py-2 text-sm text-amber-900">
        Please confirm your email address ({email}) so we can send you security alerts. Check your inbox for our link.{" "}
        {state && state !== "sending" ? (
          <span className="font-medium">{state}</span>
        ) : (
          <button onClick={resend} disabled={state === "sending"} className="font-semibold underline">
            {state === "sending" ? "Sending…" : "Send a new link"}
          </button>
        )}
      </p>
    </div>
  );
}

const linkClass = ({ isActive }) =>
  `rounded px-3 py-2 ${isActive ? "bg-teal-50 font-semibold text-teal-800" : "text-slate-600 hover:text-slate-900"}`;

export default function App() {
  const [loggedIn, setLoggedIn] = useState(Boolean(getToken()));
  const [profile, setProfile] = useState(null);
  const [unread, setUnread] = useState(0);
  const navigate = useNavigate();
  const location = useLocation();

  // Load name/email for the avatar whenever someone logs in.
  useEffect(() => {
    if (!loggedIn) return setProfile(null);
    getProfile().then(setProfile).catch(() => {});
  }, [loggedIn]);

  // Unread alerts badge: refreshed on every page change and when the Alerts page marks one as read.
  useEffect(() => {
    if (!loggedIn) return setUnread(0);
    const refresh = () => getUnreadCount().then(setUnread).catch(() => {});
    refresh();
    window.addEventListener("alerts-changed", refresh);
    return () => window.removeEventListener("alerts-changed", refresh);
  }, [loggedIn, location.pathname]);

  function handleLogout() {
    clearToken();
    setLoggedIn(false);
    navigate("/login");
  }

  const guard = (page) => <ProtectedRoute loggedIn={loggedIn}>{page}</ProtectedRoute>;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <nav className="mx-auto flex max-w-4xl flex-wrap items-center gap-1 px-4 py-3">
          <NavLink to="/" end className="mr-4 text-xl font-bold">SecureSphere</NavLink>
          {loggedIn && (
            <>
              <NavLink to="/scan" className={linkClass}>Scan</NavLink>
              <NavLink to="/history" className={linkClass}>History</NavLink>
              <NavLink to="/monitoring" className={linkClass}>Monitoring</NavLink>
              <NavLink to="/alerts" className={linkClass}>
                Alerts
                {unread > 0 && (
                  <span className="ml-1.5 rounded-full bg-red-700 px-1.5 py-0.5 text-xs font-semibold text-white">
                    {unread}<span className="sr-only"> unread</span>
                  </span>
                )}
              </NavLink>
              <NavLink to="/profile" className={linkClass}>Profile</NavLink>
            </>
          )}
          <span className="flex-1" />
          {loggedIn ? (
            <>
              <button onClick={handleLogout} className="rounded px-3 py-2 text-slate-600 hover:text-slate-900">Log out</button>
              <NavLink
                to="/profile"
                aria-label="Your profile"
                title={profile ? `${profile.name} (${profile.email})` : "Your profile"}
                className={({ isActive }) => `ml-1 rounded-full ${isActive ? "ring-2 ring-teal-700 ring-offset-2" : "hover:opacity-90"}`}
              >
                <Avatar name={profile?.name} />
              </NavLink>
            </>
          ) : (
            <>
              <NavLink to="/login" className={linkClass}>Log in</NavLink>
              <NavLink to="/signup" className={linkClass}>Sign up</NavLink>
            </>
          )}
        </nav>
      </header>
      {loggedIn && profile && !profile.email_verified && location.pathname !== "/verify-email" && (
        <VerifyBanner email={profile.email} />
      )}

      <main className="mx-auto max-w-4xl px-4 py-10">
        <Routes>
          <Route path="/" element={<LandingPage loggedIn={loggedIn} />} />
          <Route path="/scan" element={guard(<ScanPage />)} />
          <Route path="/history" element={guard(<HistoryPage />)} />
          <Route path="/scans/:id" element={guard(<ScanResultPage />)} />
          <Route path="/monitoring" element={guard(<MonitoringPage />)} />
          <Route path="/alerts" element={guard(<AlertsPage />)} />
          <Route path="/profile" element={guard(<ProfilePage onProfile={setProfile} />)} />
          <Route path="/login" element={<AuthPage mode="login" onAuth={() => setLoggedIn(true)} />} />
          <Route path="/signup" element={<AuthPage mode="signup" onAuth={() => setLoggedIn(true)} />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route
            path="/verify-email"
            element={<VerifyEmailPage onVerified={() => loggedIn && getProfile().then(setProfile).catch(() => {})} />}
          />
          <Route path="*" element={<p className="text-slate-600">Page not found.</p>} />
        </Routes>
      </main>
      {loggedIn && <Assistant />}
    </div>
  );
}
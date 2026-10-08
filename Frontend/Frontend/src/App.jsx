import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { clearToken, getProfile, getToken, getUnreadCount, resendVerification } from "./api";
import { useScan } from "./ScanContext";
import Assistant from "./components/Assistant";
import Avatar from "./components/Avatar";
import EmptyState from "./components/EmptyState";
import Icon from "./components/Icon";
import Logo from "./components/Logo";
import ThemeToggle from "./components/ThemeToggle";
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
    <div role="status" className="border-b border-warn/30 bg-warn-soft">
      <p className="mx-auto flex max-w-6xl items-start gap-2 px-4 py-2.5 text-sm text-fg sm:px-6">
        <Icon name="mail" className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
        <span>
          Please confirm your email address ({email}) so we can send you security alerts. Check your inbox for our link.{" "}
          {state && state !== "sending" ? (
            <span className="font-medium">{state}</span>
          ) : (
            <button onClick={resend} disabled={state === "sending"} className="font-semibold text-warn underline">
              {state === "sending" ? "Sending…" : "Send a new link"}
            </button>
          )}
        </span>
      </p>
    </div>
  );
}

const NAV = [
  ["/scan", "Scan", "search"],
  ["/history", "History", "history"],
  ["/monitoring", "Monitoring", "radar"],
  ["/alerts", "Alerts", "bell"],
  ["/profile", "Profile", "user"],
];

const linkClass = ({ isActive }) =>
  `flex shrink-0 items-center gap-1.5 rounded-xl px-3 py-2 text-sm font-medium transition-colors ${
    isActive ? "bg-accent-soft text-accent" : "text-muted hover:bg-surface-2 hover:text-fg"
  }`;

export default function App() {
  const [loggedIn, setLoggedIn] = useState(Boolean(getToken()));
  const [profile, setProfile] = useState(null);
  const [unread, setUnread] = useState(0);
  const [serverSlow, setServerSlow] = useState(false);

  // Shown while the free backend host wakes up (first request after it slept can take up to a minute).
  useEffect(() => {
    const onSlow = (e) => setServerSlow(e.detail);
    window.addEventListener("server-slow", onSlow);
    return () => window.removeEventListener("server-slow", onSlow);
  }, []);
  const navigate = useNavigate();
  const location = useLocation();
  const { setLastScan } = useScan();

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
    setLastScan(null); // the next person on this browser must not see this scan in the assistant
    setLoggedIn(false);
    navigate("/login");
  }

  const guard = (page) => <ProtectedRoute loggedIn={loggedIn}>{page}</ProtectedRoute>;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b border-line bg-surface/80 backdrop-blur-md">
        <nav className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-1 gap-y-2 px-4 py-3 sm:px-6">
          <NavLink to="/" end aria-label="SecureSphere home" className="mr-3 shrink-0 rounded-xl">
            <Logo />
          </NavLink>
          {loggedIn && (
            <div className="order-last -mx-1 flex w-full gap-1 overflow-x-auto px-1 md:order-none md:mx-0 md:w-auto md:px-0">
              {NAV.map(([to, label, icon]) => (
                <NavLink key={to} to={to} className={linkClass}>
                  <Icon name={icon} className="h-4 w-4" />
                  {label}
                  {to === "/alerts" && unread > 0 && (
                    <span className="rounded-full bg-bad px-1.5 py-0.5 text-xs font-semibold leading-none text-white dark:text-bg">
                      {unread}<span className="sr-only"> unread</span>
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          )}
          <span className="flex-1" />
          <ThemeToggle />
          {loggedIn ? (
            <>
              <button onClick={handleLogout} aria-label="Log out" className="btn-ghost text-sm">
                <Icon name="logout" className="h-4 w-4" />
                <span className="hidden sm:inline">Log out</span>
              </button>
              <NavLink
                to="/profile"
                aria-label="Your profile"
                title={profile ? `${profile.name} (${profile.email})` : "Your profile"}
                className={({ isActive }) => `ml-1 rounded-full ${isActive ? "ring-2 ring-accent ring-offset-2 ring-offset-surface" : "hover:opacity-90"}`}
              >
                <Avatar name={profile?.name} />
              </NavLink>
            </>
          ) : (
            <>
              <NavLink to="/login" className={linkClass}>Log in</NavLink>
              <NavLink to="/signup" className="btn-primary ml-1 px-4 py-2 text-sm">Sign up</NavLink>
            </>
          )}
        </nav>
      </header>
      {serverSlow && (
        <div role="status" className="border-b border-info/30 bg-info-soft">
          <p className="mx-auto flex max-w-6xl items-center gap-2 px-4 py-2.5 text-sm text-fg sm:px-6">
            <span className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-info" aria-hidden="true" />
            The SecureSphere server is waking up after being idle. This can take up to a minute; your request will continue by itself.
          </p>
        </div>
      )}
      {loggedIn && profile && !profile.email_verified && location.pathname !== "/verify-email" && (
        <VerifyBanner email={profile.email} />
      )}

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-12">
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
          <Route path="*" element={<EmptyState icon="help" title="Page not found." text="The page you opened does not exist." />} />
        </Routes>
      </main>
      <footer className="border-t border-line">
        <p className="mx-auto max-w-6xl px-4 py-6 text-sm text-subtle sm:px-6">
          SecureSphere checks HTTPS configuration only. A high score is not a guarantee of security.
        </p>
      </footer>
      {loggedIn && <Assistant />}
    </div>
  );
}

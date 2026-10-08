import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { changePassword, getProfile, resendVerification, updateProfile } from "../api";
import Avatar from "../components/Avatar";
import ErrorBox from "../components/ErrorBox";
import Icon from "../components/Icon";
import { ScorePill } from "./HistoryPage";

const inputClass = "input py-2.5";
const buttonClass = "btn-primary";

function Stat({ label, value, to, icon }) {
  return (
    <Link to={to} className="card group flex items-center gap-4 transition-colors hover:border-accent/60">
      <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">
        <Icon name={icon} className="h-5 w-5" />
      </span>
      <span>
        <span className="block text-3xl font-bold tracking-tight text-fg">{value}</span>
        <span className="block text-sm text-muted">{label}</span>
      </span>
      <Icon name="arrowRight" className="ml-auto h-4 w-4 text-subtle transition-transform group-hover:translate-x-1" />
    </Link>
  );
}

function Section({ title, icon, children }) {
  return (
    <section className="card">
      <h2 className="card-title mb-4 flex items-center gap-2 text-lg">
        {icon && <Icon name={icon} className="h-5 w-5 text-accent" />}
        {title}
      </h2>
      {children}
    </section>
  );
}

function EditName({ current, onSaved }) {
  const [name, setName] = useState(current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  async function save(e) {
    e.preventDefault();
    if (!name.trim()) return setError("Name cannot be empty.");
    setBusy(true);
    setError("");
    setDone(false);
    try {
      onSaved(await updateProfile(name.trim()));
      setDone(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={save} className="space-y-3">
      <label className="label">
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={50} className={inputClass} />
      </label>
      <ErrorBox message={error} />
      {done && <p role="status" className="text-sm font-medium text-ok">Name updated.</p>}
      <button type="submit" disabled={busy || name.trim() === current} className={buttonClass}>
        {busy ? "Saving…" : "Save name"}
      </button>
    </form>
  );
}

function ChangePassword() {
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  async function save(e) {
    e.preventDefault();
    setDone(false);
    if (form.next.length < 8) return setError("New password must be at least 8 characters.");
    if (form.next !== form.confirm) return setError("The new passwords do not match.");
    setBusy(true);
    setError("");
    try {
      await changePassword(form.current, form.next);
      setForm({ current: "", next: "", confirm: "" });
      setDone(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={save} className="space-y-3">
      <label className="label">
        Current password
        <input type="password" value={form.current} onChange={set("current")} autoComplete="current-password" className={inputClass} />
      </label>
      <label className="label">
        New password
        <input type="password" value={form.next} onChange={set("next")} autoComplete="new-password" className={inputClass} />
      </label>
      <label className="label">
        Confirm new password
        <input type="password" value={form.confirm} onChange={set("confirm")} autoComplete="new-password" className={inputClass} />
      </label>
      <ErrorBox message={error} />
      {done && <p role="status" className="text-sm font-medium text-ok">Password changed.</p>}
      <button type="submit" disabled={busy || !form.current} className={buttonClass}>
        {busy ? "Saving…" : "Change password"}
      </button>
    </form>
  );
}

function ResendLink() {
  const [message, setMessage] = useState("");
  async function resend() {
    try {
      setMessage((await resendVerification()).message);
    } catch (e) {
      setMessage(e.message);
    }
  }
  return message ? (
    <p className="mt-1 text-sm text-muted">{message}</p>
  ) : (
    <button onClick={resend} className="link mt-1 text-sm">Send confirmation email again</button>
  );
}

// onProfile keeps the avatar in the top bar in sync after a name change.
export default function ProfilePage({ onProfile }) {
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getProfile()
      .then((p) => { setProfile(p); onProfile(p); })
      .catch((e) => setError(e.message));
  }, [onProfile]);

  function handleNameSaved(updated) {
    const next = { ...profile, name: updated.name };
    setProfile(next);
    onProfile(next);
  }

  if (error) return <ErrorBox message={error} />;
  if (!profile) return <div className="card h-40 animate-pulse" aria-label="Loading" />;

  const { stats, recent_scans: recent } = profile;

  return (
    <div className="space-y-6">
      <div className="card fade-up relative flex flex-col items-center gap-5 overflow-hidden sm:flex-row">
        <div className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full blur-3xl" style={{ background: "var(--glow)" }} />
        <Avatar name={profile.name} size="h-20 w-20 text-3xl" />
        <div className="relative text-center sm:text-left">
          <h1 className="text-3xl font-bold tracking-tight text-fg">{profile.name}</h1>
          <p className="mt-1 flex flex-wrap items-center justify-center gap-2 text-muted sm:justify-start">
            {profile.email}
            {profile.email_verified ? (
              <span className="chip bg-ok-soft text-ok"><Icon name="check" className="h-3 w-3" strokeWidth={3} />Confirmed</span>
            ) : (
              <span className="chip bg-warn-soft text-warn">Not confirmed</span>
            )}
          </p>
          {!profile.email_verified && <ResendLink />}
          {profile.created_at && (
            <p className="mt-1 text-sm text-subtle">Member since {new Date(profile.created_at).toLocaleDateString()}</p>
          )}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Scans run" value={stats.scans} to="/history" icon="search" />
        <Stat label="Sites monitored" value={stats.monitors} to="/monitoring" icon="radar" />
        <Stat label="Unread alerts" value={stats.unread_alerts} to="/alerts" icon="bell" />
      </div>

      <Section title="Recent scans" icon="history">
        {recent.length === 0 ? (
          <p className="text-muted">
            No scans yet. <Link to="/scan" className="link">Scan a website</Link>.
          </p>
        ) : (
          <ul>
            {recent.map((s) => (
              <li key={s.id} className="border-b border-line last:border-0">
                <Link
                  to={`/scans/${s.id}`}
                  className="-mx-2 flex items-center justify-between gap-4 rounded-lg px-2 py-3 transition-colors hover:bg-surface-2"
                >
                  <span className="min-w-0">
                    <span className="block truncate font-mono text-sm font-medium text-fg">{s.domain}</span>
                    <span className="block text-xs text-subtle">
                      {new Date(s.scanned_at).toLocaleString()}{s.source === "scheduled" ? " · scheduled" : ""}
                    </span>
                  </span>
                  <ScorePill score={s.score} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <div className="grid gap-6 md:grid-cols-2">
        <Section title="Edit profile" icon="user">
          <EditName current={profile.name} onSaved={handleNameSaved} />
          <p className="mt-3 text-sm text-subtle">Your email address is used to log in and cannot be changed here.</p>
        </Section>
        <Section title="Change password" icon="lock">
          <ChangePassword />
        </Section>
      </div>
    </div>
  );
}

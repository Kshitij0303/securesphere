import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { changePassword, getProfile, resendVerification, updateProfile } from "../api";
import Avatar from "../components/Avatar";
import ErrorBox from "../components/ErrorBox";
import { scoreColor } from "../components/ScanResults";

const inputClass =
  "mt-1 w-full rounded-md border border-slate-300 bg-white px-4 py-2.5 outline-none focus:border-teal-700 focus:ring-2 focus:ring-teal-700/30";
const buttonClass = "rounded-md bg-teal-700 px-5 py-2.5 font-semibold text-white hover:bg-teal-800 disabled:opacity-60";

function Stat({ label, value, to }) {
  return (
    <Link to={to} className="rounded-lg border border-slate-200 bg-white p-5 hover:border-teal-700">
      <p className="text-3xl font-bold text-slate-900">{value}</p>
      <p className="text-slate-600">{label}</p>
    </Link>
  );
}

function Section({ title, children }) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="mb-4 text-lg font-semibold text-slate-900">{title}</h2>
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
      <label className="block">
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={50} className={inputClass} />
      </label>
      <ErrorBox message={error} />
      {done && <p role="status" className="text-emerald-700">Name updated.</p>}
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
      <label className="block">
        Current password
        <input type="password" value={form.current} onChange={set("current")} autoComplete="current-password" className={inputClass} />
      </label>
      <label className="block">
        New password
        <input type="password" value={form.next} onChange={set("next")} autoComplete="new-password" className={inputClass} />
      </label>
      <label className="block">
        Confirm new password
        <input type="password" value={form.confirm} onChange={set("confirm")} autoComplete="new-password" className={inputClass} />
      </label>
      <ErrorBox message={error} />
      {done && <p role="status" className="text-emerald-700">Password changed.</p>}
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
    <p className="mt-1 text-sm text-slate-600">{message}</p>
  ) : (
    <button onClick={resend} className="mt-1 text-sm font-medium text-teal-700 underline">Send confirmation email again</button>
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
  if (!profile) return <p className="text-slate-600">Loading…</p>;

  const { stats, recent_scans: recent } = profile;

  return (
    <div className="space-y-6">
      <div className="flex flex-col items-center gap-5 rounded-lg border border-slate-200 bg-white p-6 sm:flex-row">
        <Avatar name={profile.name} size="h-20 w-20 text-3xl" />
        <div className="text-center sm:text-left">
          <h1 className="text-3xl font-bold">{profile.name}</h1>
          <p className="text-slate-600">
            {profile.email}{" "}
            {profile.email_verified ? (
              <span className="ml-1 rounded bg-emerald-50 px-2 py-0.5 text-sm font-medium text-emerald-800">Confirmed</span>
            ) : (
              <span className="ml-1 rounded bg-amber-50 px-2 py-0.5 text-sm font-medium text-amber-900">Not confirmed</span>
            )}
          </p>
          {!profile.email_verified && <ResendLink />}
          {profile.created_at && (
            <p className="mt-1 text-sm text-slate-500">Member since {new Date(profile.created_at).toLocaleDateString()}</p>
          )}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Scans run" value={stats.scans} to="/history" />
        <Stat label="Sites monitored" value={stats.monitors} to="/monitoring" />
        <Stat label="Unread alerts" value={stats.unread_alerts} to="/alerts" />
      </div>

      <Section title="Recent scans">
        {recent.length === 0 ? (
          <p className="text-slate-600">
            No scans yet. <Link to="/scan" className="font-medium text-teal-700 underline">Scan a website</Link>.
          </p>
        ) : (
          <ul>
            {recent.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-4 border-b border-slate-100 py-2.5 last:border-0">
                <div>
                  <p className="font-medium">{s.domain}</p>
                  <p className="text-sm text-slate-500">
                    {new Date(s.scanned_at).toLocaleString()}{s.source === "scheduled" ? " · scheduled" : ""}
                  </p>
                </div>
                <span className="font-semibold" style={{ color: scoreColor(s.score) }}>{s.score} / 100</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <div className="grid gap-6 md:grid-cols-2">
        <Section title="Edit profile">
          <EditName current={profile.name} onSaved={handleNameSaved} />
          <p className="mt-3 text-sm text-slate-500">Your email address is used to log in and cannot be changed here.</p>
        </Section>
        <Section title="Change password">
          <ChangePassword />
        </Section>
      </div>
    </div>
  );
}

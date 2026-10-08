import { useEffect, useState } from "react";
import { getMonitored, setMonitoring } from "../api";
import Icon from "./Icon";

export default function MonitorToggle({ domain }) {
  const [on, setOn] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    getMonitored()
      .then((list) => active && setOn(list.some((m) => m.domain === domain)))
      .catch(() => {})
      .finally(() => active && setBusy(false));
    return () => { active = false; };
  }, [domain]);

  async function toggle() {
    setBusy(true);
    setError("");
    try {
      await setMonitoring(domain, !on);
      setOn(!on);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card fade-up flex items-center justify-between gap-4">
      <div className="flex items-start gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <Icon name="radar" className="h-5 w-5" />
        </span>
        <div>
          <h2 className="card-title">Monitor this site</h2>
          <p className="text-sm text-muted">
            We rescan it regularly and alert you if the certificate is close to expiry or the score drops.
          </p>
          {error && <p role="alert" className="mt-1 text-sm text-bad">{error}</p>}
        </div>
      </div>
      <button
        role="switch"
        aria-checked={on}
        aria-label="Monitor this site"
        disabled={busy}
        onClick={toggle}
        className={`relative h-7 w-12 shrink-0 rounded-full transition-colors disabled:opacity-60 ${on ? "bg-accent" : "bg-line"}`}
      >
        <span className={`absolute top-0.5 h-6 w-6 rounded-full bg-white shadow transition-all ${on ? "left-5" : "left-0.5"}`} />
      </button>
    </div>
  );
}
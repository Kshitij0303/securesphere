import { useEffect, useState } from "react";
import { getMonitored, setMonitoring } from "../api";

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
    <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-white p-5">
      <div>
        <h2 className="font-semibold text-slate-900">Monitor this site</h2>
        <p className="text-sm text-slate-600">
          We rescan it regularly and alert you if the certificate is close to expiry or the score drops.
        </p>
        {error && <p role="alert" className="mt-1 text-sm text-red-700">{error}</p>}
      </div>
      <button
        role="switch"
        aria-checked={on}
        aria-label="Monitor this site"
        disabled={busy}
        onClick={toggle}
        className={`relative h-7 w-12 shrink-0 rounded-full transition-colors disabled:opacity-60 ${on ? "bg-teal-700" : "bg-slate-300"}`}
      >
        <span className={`absolute top-0.5 h-6 w-6 rounded-full bg-white transition-all ${on ? "left-5" : "left-0.5"}`} />
      </button>
    </div>
  );
}
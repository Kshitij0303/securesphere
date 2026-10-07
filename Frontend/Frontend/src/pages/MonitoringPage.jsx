import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getMonitored, setMonitoring } from "../api";
import { scoreColor } from "../components/ScanResults";
import ErrorBox from "../components/ErrorBox";

export default function MonitoringPage() {
  const [sites, setSites] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getMonitored().then(setSites).catch((e) => { setError(e.message); setSites([]); });
  }, []);

  async function stop(domain) {
    setError("");
    try {
      await setMonitoring(domain, false);
      setSites((list) => list.filter((s) => s.domain !== domain));
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <>
      <h1 className="text-3xl font-bold">Monitored sites</h1>
      <p className="mt-2 text-slate-600">These sites are scanned as soon as you add them, then again every night.</p>
      <ErrorBox message={error} />
      {sites === null && <p className="mt-6 text-slate-600">Loading…</p>}
      {sites && sites.length === 0 && (
        <p className="mt-6 text-slate-600">
          You are not monitoring any sites yet. <Link to="/scan" className="font-medium text-teal-700 underline">Scan a site</Link> and turn on "Monitor this site".
        </p>
      )}
      {sites && sites.length > 0 && (
        <ul className="mt-6 space-y-3">
          {sites.map((s) => (
            <li key={s.domain} className="flex items-center justify-between gap-4 rounded-lg border border-slate-200 bg-white p-4">
              <div>
                <p className="font-semibold">{s.domain}</p>
                <p className="text-sm text-slate-600">
                  {s.last_scanned_at ? `Last scanned ${new Date(s.last_scanned_at).toLocaleString()}` : "First scan in progress. Refresh in a minute."}
                </p>
              </div>
              <div className="flex items-center gap-4">
                {s.score != null && (
                  <span className="font-semibold" style={{ color: scoreColor(s.score) }}>{s.score} / 100</span>
                )}
                <button onClick={() => stop(s.domain)} className="rounded-md border border-slate-300 px-3 py-1.5 hover:bg-slate-100">
                  Stop monitoring
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
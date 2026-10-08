import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getMonitored, setMonitoring } from "../api";
import EmptyState from "../components/EmptyState";
import ErrorBox from "../components/ErrorBox";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
import { ScorePill } from "./HistoryPage";

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
      <PageHeader icon="radar" title="Monitored sites">
        These sites are scanned as soon as you add them, then again every night.
      </PageHeader>
      <ErrorBox message={error} />
      {sites === null && (
        <div className="mt-6 grid gap-4 sm:grid-cols-2" aria-label="Loading">
          {[0, 1].map((i) => <div key={i} className="card h-32 animate-pulse" />)}
        </div>
      )}
      {sites && sites.length === 0 && (
        <div className="mt-6">
          <EmptyState icon="radar" title="You are not monitoring any sites yet." text='Scan a site and turn on "Monitor this site".'>
            <Link to="/scan" className="btn-primary">Scan a site</Link>
          </EmptyState>
        </div>
      )}
      {sites && sites.length > 0 && (
        <ul className="mt-6 grid gap-4 sm:grid-cols-2">
          {sites.map((s) => (
            <li key={s.domain} className="card fade-up flex flex-col gap-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="relative flex h-3 w-3 shrink-0">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-40" />
                    <span className="relative inline-flex h-3 w-3 rounded-full bg-ok" />
                  </span>
                  <p className="truncate font-mono font-semibold text-fg">{s.domain}</p>
                </div>
                {s.score != null && <ScorePill score={s.score} />}
              </div>
              <p className="text-sm text-muted">
                {s.last_scanned_at ? `Last scanned ${new Date(s.last_scanned_at).toLocaleString()}` : "First scan in progress. Refresh in a minute."}
              </p>
              <button onClick={() => stop(s.domain)} className="btn-secondary mt-auto self-start px-3 py-1.5 text-sm">
                <Icon name="x" className="h-4 w-4" /> Stop monitoring
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

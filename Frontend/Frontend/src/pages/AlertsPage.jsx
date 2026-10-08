import { useEffect, useState } from "react";
import { getAlerts, markAlertRead } from "../api";
import EmptyState from "../components/EmptyState";
import ErrorBox from "../components/ErrorBox";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getAlerts().then(setAlerts).catch((e) => { setError(e.message); setAlerts([]); });
  }, []);

  async function markRead(id) {
    try {
      await markAlertRead(id);
      setAlerts((list) => list.map((a) => (a.id === id ? { ...a, read: true } : a)));
      window.dispatchEvent(new Event("alerts-changed"));
    } catch (e) {
      setError(e.message);
    }
  }

  const unread = alerts ? alerts.filter((a) => !a.read).length : 0;

  return (
    <>
      <PageHeader
        icon="bell"
        title="Alerts"
        action={alerts && <span className={`chip px-3 py-1 text-sm ${unread ? "bg-bad-soft text-bad" : "bg-surface-2 text-muted"}`}>{unread} unread</span>}
      />
      <ErrorBox message={error} />
      {alerts === null && (
        <div className="mt-6 space-y-3" aria-label="Loading">
          {[0, 1, 2].map((i) => <div key={i} className="card h-20 animate-pulse" />)}
        </div>
      )}
      {alerts && alerts.length === 0 && (
        <div className="mt-6">
          <EmptyState icon="bell" title="No alerts yet." text="Turn on monitoring for a site and we will tell you when something changes." />
        </div>
      )}
      {alerts && alerts.length > 0 && (
        <ul className="mt-6 space-y-3">
          {alerts.map((a) => (
            <li
              key={a.id}
              className={`card fade-up flex items-start justify-between gap-4 p-4 sm:p-5 ${a.read ? "" : "border-accent/40 bg-accent-soft"}`}
            >
              <div className="flex min-w-0 gap-3">
                <span className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${a.read ? "bg-surface-2 text-subtle" : "bg-warn-soft text-warn"}`}>
                  <Icon name={a.read ? "bell" : "alert"} className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <p className={a.read ? "text-muted" : "font-semibold text-fg"}>
                    {a.domain}: {a.message}
                  </p>
                  <p className="mt-0.5 text-xs text-subtle">{new Date(a.created_at).toLocaleString()}</p>
                </div>
              </div>
              {a.read ? (
                <span className="flex shrink-0 items-center gap-1 text-sm text-subtle"><Icon name="check" className="h-4 w-4" /> Read</span>
              ) : (
                <button onClick={() => markRead(a.id)} className="btn-secondary shrink-0 px-3 py-1.5 text-sm">
                  Mark as read
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

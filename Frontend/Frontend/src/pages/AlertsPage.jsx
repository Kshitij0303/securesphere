import { useEffect, useState } from "react";
import { getAlerts, markAlertRead } from "../api";
import ErrorBox from "../components/ErrorBox";

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
      <h1 className="text-3xl font-bold">Alerts</h1>
      {alerts && <p className="mt-2 text-slate-600">{unread} unread</p>}
      <ErrorBox message={error} />
      {alerts === null && <p className="mt-6 text-slate-600">Loading…</p>}
      {alerts && alerts.length === 0 && (
        <p className="mt-6 text-slate-600">No alerts yet. Turn on monitoring for a site and we will tell you when something changes.</p>
      )}
      {alerts && alerts.length > 0 && (
        <ul className="mt-6 space-y-3">
          {alerts.map((a) => (
            <li
              key={a.id}
              className={`flex items-start justify-between gap-4 rounded-lg border p-4 ${a.read ? "border-slate-200 bg-white" : "border-teal-200 bg-teal-50"}`}
            >
              <div>
                <p className={a.read ? "text-slate-700" : "font-semibold text-slate-900"}>
                  {a.domain}: {a.message}
                </p>
                <p className="text-sm text-slate-500">{new Date(a.created_at).toLocaleString()}</p>
              </div>
              {a.read ? (
                <span className="shrink-0 text-sm text-slate-500">Read</span>
              ) : (
                <button onClick={() => markRead(a.id)} className="shrink-0 rounded-md border border-slate-300 bg-white px-3 py-1.5 hover:bg-slate-100">
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
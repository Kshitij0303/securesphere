import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getHistory } from "../api";
import { scoreColor } from "../components/ScanResults";
import DomainForm from "../components/DomainForm";
import ErrorBox from "../components/ErrorBox";

export default function HistoryPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [rows, setRows] = useState(null);
  const [domain, setDomain] = useState(""); // "" = all sites
  const navigate = useNavigate();

  async function load(d) {
    setError("");
    setRows(null);
    setDomain(d);
    setLoading(true);
    try {
      setRows(await getHistory(d));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(""); }, []);

  // Chart needs oldest first; the table shows newest first.
  const chartData = rows && domain
    ? [...rows]
        .sort((a, b) => new Date(a.scanned_at) - new Date(b.scanned_at))
        .map((r) => ({ date: new Date(r.scanned_at).toLocaleDateString(), score: r.score }))
    : [];

  return (
    <>
      <h1 className="text-3xl font-bold">Scan history</h1>
      <p className="mt-2 max-w-xl text-slate-600">
        Open any scan to see the full report and what changed since the scan before it. Enter a domain to see its score over time.
      </p>
      <DomainForm
        buttonText="Show this site"
        loadingText="Loading…"
        loading={loading}
        onSubmit={load}
        onInvalid={(msg) => setError(msg)}
      />
      <ErrorBox message={error} />
      {domain && (
        <button onClick={() => load("")} className="mt-4 text-sm font-medium text-teal-700 underline">
          Show all sites
        </button>
      )}
      {loading && <p className="mt-6 text-slate-600">Loading history…</p>}

      {rows && rows.length === 0 && (
        <p className="mt-6 text-slate-600">
          {domain ? `No scans found for ${domain}. ` : "You have not scanned any site yet. "}
          <Link to="/scan" className="font-medium text-teal-700 underline">Scan a website</Link>.
        </p>
      )}

      {rows && rows.length > 0 && (
        <>
          {domain && rows.length > 1 && (
            <section className="mt-8 rounded-lg border border-slate-200 bg-white p-5">
              <h2 className="mb-4 text-lg font-semibold">Score over time for {domain}</h2>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid stroke="#e2e8f0" />
                    <XAxis dataKey="date" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip />
                    <Line type="monotone" dataKey="score" stroke="#0f766e" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </section>
          )}

          <div className="mt-6 overflow-x-auto rounded-lg border border-slate-200 bg-white">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-200 text-slate-600">
                  <th className="px-5 py-3 font-medium">Site</th>
                  <th className="px-5 py-3 font-medium">Date</th>
                  <th className="px-5 py-3 font-medium">Score</th>
                  <th className="px-5 py-3 font-medium"><span className="sr-only">Open</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => navigate(`/scans/${r.id}`)}
                    className="cursor-pointer border-b border-slate-100 last:border-0 hover:bg-slate-50"
                  >
                    <td className="px-5 py-3 font-medium">{r.domain}</td>
                    <td className="px-5 py-3">
                      {new Date(r.scanned_at).toLocaleString()}
                      {r.source === "scheduled" && <span className="ml-2 text-sm text-slate-500">· scheduled</span>}
                    </td>
                    <td className="px-5 py-3 font-semibold" style={{ color: scoreColor(r.score) }}>{r.score} / 100</td>
                    <td className="px-5 py-3 text-right">
                      <Link to={`/scans/${r.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-teal-700 underline">
                        View report
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

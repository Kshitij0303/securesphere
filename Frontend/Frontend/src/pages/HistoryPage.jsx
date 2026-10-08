import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getHistory } from "../api";
import { scoreColor, scoreGrade } from "../components/ScanResults";
import DomainForm from "../components/DomainForm";
import EmptyState from "../components/EmptyState";
import ErrorBox from "../components/ErrorBox";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

export function ScorePill({ score }) {
  const color = scoreColor(score);
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-lg px-2 py-0.5 font-mono text-sm font-semibold"
      style={{ color, background: "color-mix(in srgb, currentColor 12%, transparent)" }}
    >
      {score} / 100
      <span className="font-sans text-xs opacity-80">{scoreGrade(score)}</span>
    </span>
  );
}

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
      <PageHeader icon="history" title="Scan history">
        Open any scan to see the full report and what changed since the scan before it. Enter a domain to see its score over time.
      </PageHeader>
      <DomainForm
        buttonText="Show this site"
        loadingText="Loading…"
        loading={loading}
        onSubmit={load}
        onInvalid={(msg) => setError(msg)}
      />
      <ErrorBox message={error} />
      {domain && (
        <button onClick={() => load("")} className="btn-ghost -ml-3 mt-3 text-sm">
          <Icon name="arrowLeft" className="h-4 w-4" /> Show all sites
        </button>
      )}
      {loading && (
        <div className="card mt-6 space-y-3" aria-label="Loading history">
          <p className="sr-only">Loading history…</p>
          {[0, 1, 2, 3].map((i) => <div key={i} className="h-10 animate-pulse rounded-lg bg-surface-2" />)}
        </div>
      )}

      {rows && rows.length === 0 && (
        <div className="mt-6">
          <EmptyState
            icon="history"
            title={domain ? `No scans found for ${domain}. ` : "You have not scanned any site yet. "}
            text="Every scan you run is saved here with its full report."
          >
            <Link to="/scan" className="btn-primary">Scan a website</Link>
          </EmptyState>
        </div>
      )}

      {rows && rows.length > 0 && (
        <>
          {domain && rows.length > 1 && (
            <section className="card fade-up mt-8">
              <h2 className="card-title mb-4 text-lg">Score over time for {domain}</h2>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="var(--accent)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--line)" vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: "var(--subtle)", fontSize: 12 }} stroke="var(--line)" />
                    <YAxis domain={[0, 100]} tick={{ fill: "var(--subtle)", fontSize: 12 }} stroke="var(--line)" width={36} />
                    <Tooltip
                      contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 12, color: "var(--fg)" }}
                      labelStyle={{ color: "var(--muted)" }}
                    />
                    <Area type="monotone" dataKey="score" stroke="var(--accent)" strokeWidth={2.5} fill="url(#scoreFill)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
          )}

          <div className="card fade-up mt-6 overflow-x-auto p-0 sm:p-0">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-line text-xs uppercase tracking-wide text-subtle">
                  <th className="px-5 py-3 font-semibold">Site</th>
                  <th className="px-5 py-3 font-semibold">Date</th>
                  <th className="px-5 py-3 font-semibold">Score</th>
                  <th className="px-5 py-3 font-semibold"><span className="sr-only">Open</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => navigate(`/scans/${r.id}`)}
                    className="cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-surface-2"
                  >
                    <td className="px-5 py-3.5 font-mono text-sm font-medium text-fg">{r.domain}</td>
                    <td className="px-5 py-3.5 text-sm text-muted">
                      {new Date(r.scanned_at).toLocaleString()}
                      {r.source === "scheduled" && <span className="chip ml-2 bg-info-soft text-info">scheduled</span>}
                    </td>
                    <td className="px-5 py-3.5"><ScorePill score={r.score} /></td>
                    <td className="px-5 py-3.5 text-right">
                      <Link to={`/scans/${r.id}`} onClick={(e) => e.stopPropagation()} className="link whitespace-nowrap text-sm">
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

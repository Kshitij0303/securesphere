const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const BADGE = {
  critical: "border-red-300 bg-red-100 text-red-900",
  high: "border-red-200 bg-red-50 text-red-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-100 text-slate-700",
};

export default function Findings({ data }) {
  const items = [...(data.findings || [])].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="mb-3 text-lg font-semibold text-slate-900">What this means</h2>
      {items.length === 0 ? (
        <p className="text-slate-800">{data.ai_explanation || "No problems were found in this scan."}</p>
      ) : (
        <div className="space-y-4">
          {items.map((f, i) => (
            <article key={i} className="rounded-md border border-slate-200 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className={`rounded border px-2 py-0.5 text-sm font-semibold ${BADGE[f.severity]}`}>
                  {f.severity[0].toUpperCase() + f.severity.slice(1)}
                </span>
                <h3 className="font-semibold text-slate-900">{f.title}</h3>
                {f.points_lost != null && (
                  <span className="ml-auto text-sm text-slate-500">
                    {f.points_lost > 0 ? `−${f.points_lost} points` : "no extra points (category limit reached)"}
                  </span>
                )}
              </div>
              <dl className="mt-3 space-y-2 text-slate-800">
                {f.evidence && f.evidence !== f.problem && (
                  <div><dt className="font-medium">What we found</dt><dd>{f.evidence}</dd></div>
                )}
                <div><dt className="font-medium">Problem</dt><dd>{f.problem}</dd></div>
                <div><dt className="font-medium">Impact</dt><dd>{f.impact}</dd></div>
                <div><dt className="font-medium">Fix</dt><dd>{f.fix}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      )}
      <p className="mt-4 text-sm text-slate-500">Explanations are generated from the scan results above only.</p>
    </section>
  );
}
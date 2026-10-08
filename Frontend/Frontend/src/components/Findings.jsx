import { showEvidence } from "../findingText";
import Icon from "./Icon";

const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const STYLE = {
  critical: { badge: "bg-bad text-white dark:text-bg", bar: "bg-bad" },
  high: { badge: "bg-bad-soft text-bad", bar: "bg-bad" },
  medium: { badge: "bg-warn-soft text-warn", bar: "bg-warn" },
  low: { badge: "bg-surface-2 text-muted", bar: "bg-subtle" },
};

function Detail({ icon, term, children }) {
  return (
    <div className="flex gap-3">
      <Icon name={icon} className="mt-0.5 h-4 w-4 shrink-0 text-subtle" />
      <div>
        <dt className="text-xs font-semibold uppercase tracking-wide text-subtle">{term}</dt>
        <dd className="mt-0.5 text-fg">{children}</dd>
      </div>
    </div>
  );
}

export default function Findings({ data }) {
  const items = [...(data.findings || [])].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  return (
    <section className="card fade-up">
      <div className="mb-4 flex items-center gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <Icon name="wrench" className="h-5 w-5" />
        </span>
        <h2 className="card-title text-lg">What this means</h2>
        {items.length > 0 && <span className="chip ml-auto bg-surface-2 text-muted">{items.length} to review</span>}
      </div>
      {items.length === 0 ? (
        <p className="flex items-start gap-3 rounded-xl bg-ok-soft p-4 text-fg">
          <Icon name="shieldCheck" className="h-5 w-5 shrink-0 text-ok" />
          {data.ai_explanation || "No problems were found in this scan."}
        </p>
      ) : (
        <div className="space-y-3">
          {items.map((f, i) => (
            <article key={i} className="relative overflow-hidden rounded-xl border border-line bg-surface p-4 pl-5">
              <span className={`absolute inset-y-0 left-0 w-1 ${STYLE[f.severity].bar}`} aria-hidden="true" />
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className={`chip ${STYLE[f.severity].badge}`}>
                  {f.severity[0].toUpperCase() + f.severity.slice(1)}
                </span>
                <h3 className="font-semibold text-fg">{f.title}</h3>
                {f.points_lost != null && (
                  <span className="ml-auto font-mono text-xs text-subtle">
                    {f.points_lost > 0 ? `−${f.points_lost} points` : "no extra points (category limit reached)"}
                  </span>
                )}
              </div>
              <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                {showEvidence(f) && (
                  <div className="sm:col-span-2"><Detail icon="search" term="What we found">{f.evidence}</Detail></div>
                )}
                <Detail icon="alert" term="Problem">{f.problem}</Detail>
                <Detail icon="bug" term="Impact">{f.impact}</Detail>
                <div className="rounded-lg bg-accent-soft p-3 sm:col-span-2">
                  <Detail icon="wrench" term="Fix">{f.fix}</Detail>
                </div>
              </dl>
            </article>
          ))}
        </div>
      )}
      <p className="mt-4 text-xs text-subtle">Explanations are generated from the scan results above only.</p>
    </section>
  );
}

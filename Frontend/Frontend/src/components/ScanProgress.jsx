import Icon from "./Icon";

// Live checklist while a scan runs. Steps arrive from the backend as each check finishes.
const STEPS = [
  ["certificate", "Checking the certificate"],
  ["protocols", "Testing TLS versions"],
  ["ciphers", "Checking the cipher in use"],
  ["headers", "Reading security headers and cookies"],
  ["redirect", "Checking the HTTP to HTTPS redirect"],
  ["dns", "Checking DNS (CAA, DNSSEC, HSTS preload)"],
  ["variant", "Checking the www / non-www address"],
  ["deep", "Testing all ciphers and known vulnerabilities"],
];

export default function ScanProgress({ domain, steps }) {
  if (steps.includes("cached")) {
    return <p className="card mt-6 text-muted">Using a scan of {domain} from the last few minutes…</p>;
  }
  const done = new Set(steps);
  const nextKey = STEPS.find(([key]) => !done.has(key))?.[0];
  return (
    <section className="card fade-up mt-6" aria-live="polite">
      <div className="flex items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <Icon name="radar" className="h-5 w-5 animate-spin [animation-duration:3s]" />
        </span>
        <div>
          <h2 className="font-semibold text-fg">Scanning {domain}…</h2>
          <p className="text-sm text-subtle">
            {done.size} of {STEPS.length} checks done. A full scan can take up to a minute.
          </p>
        </div>
      </div>
      <div className="relative mt-5 h-2 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full rounded-full bg-accent transition-all duration-500" style={{ width: `${(done.size / STEPS.length) * 100}%` }} />
        <div className="scan-sweep absolute inset-y-0 left-0 w-1/3 bg-gradient-to-r from-transparent via-white/40 to-transparent" />
      </div>
      <ul className="mt-5 grid gap-2 sm:grid-cols-2">
        {STEPS.map(([key, label]) => {
          const isDone = done.has(key);
          const isNext = key === nextKey;
          return (
            <li
              key={key}
              className={`flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition-colors ${
                isDone ? "text-fg" : isNext ? "bg-surface-2 text-fg" : "text-subtle"
              }`}
            >
              <span
                aria-hidden="true"
                className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${isDone ? "bg-ok-soft text-ok" : "border border-line"}`}
              >
                {isDone ? (
                  <Icon name="check" className="h-3 w-3" strokeWidth={3} />
                ) : (
                  isNext && <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />
                )}
              </span>
              {label}
              <span className="sr-only">{isDone ? "(done)" : "(waiting)"}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

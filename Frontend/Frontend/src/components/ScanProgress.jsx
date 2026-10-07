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
    return <p className="mt-6 text-slate-600">Using a scan of {domain} from the last few minutes…</p>;
  }
  const done = new Set(steps);
  return (
    <section className="mt-6 rounded-lg border border-slate-200 bg-white p-5" aria-live="polite">
      <h2 className="font-semibold">Scanning {domain}…</h2>
      <p className="text-sm text-slate-500">
        {done.size} of {STEPS.length} checks done. A full scan can take up to a minute.
      </p>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-100">
        <div className="h-full bg-teal-700 transition-all" style={{ width: `${(done.size / STEPS.length) * 100}%` }} />
      </div>
      <ul className="mt-4 space-y-1.5">
        {STEPS.map(([key, label]) => (
          <li key={key} className={`flex items-center gap-2 ${done.has(key) ? "text-slate-900" : "text-slate-400"}`}>
            <span aria-hidden="true" className={done.has(key) ? "text-emerald-700" : ""}>{done.has(key) ? "✓" : "○"}</span>
            {label}
            <span className="sr-only">{done.has(key) ? "(done)" : "(waiting)"}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

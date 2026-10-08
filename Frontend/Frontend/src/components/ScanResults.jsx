import { Link } from "react-router-dom";
import { downloadReport } from "../reportPdf";
import Findings from "./Findings";
import Icon from "./Icon";
import MonitorToggle from "./MonitorToggle";

export function scoreColor(score) {
  // green 80+, orange 50-79, red below 50 (CSS variables, so the colour adapts to light and dark mode)
  return score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--bad)";
}

function Mark({ ok }) {
  if (ok == null) {
    return (
      <span title="Could not be tested" className="flex h-5 w-5 items-center justify-center rounded-full bg-surface-2 text-xs font-bold text-subtle">
        ?
      </span>
    );
  }
  return ok ? (
    <span role="img" aria-label="OK" className="flex h-5 w-5 items-center justify-center rounded-full bg-ok-soft text-ok">
      <Icon name="check" className="h-3.5 w-3.5" strokeWidth={3} />
    </span>
  ) : (
    <span role="img" aria-label="Warning" className="flex h-5 w-5 items-center justify-center rounded-full bg-warn-soft text-warn">
      <span aria-hidden="true" className="text-xs font-bold">!</span>
    </span>
  );
}

function Row({ label, ok, value }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-2.5 last:border-0">
      <span className="text-sm text-muted">{label}</span>
      <span className="flex min-w-0 items-center gap-2 text-right text-fg">
        {value !== undefined && <span className="truncate text-sm font-medium">{value}</span>}
        <Mark ok={ok} />
      </span>
    </div>
  );
}

function Card({ title, icon, children }) {
  return (
    <section className="card fade-up">
      <div className="mb-2 flex items-center gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent-soft text-accent">
          <Icon name={icon} className="h-5 w-5" />
        </span>
        <h2 className="card-title">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function Note({ tone = "subtle", children }) {
  const cls = { subtle: "text-subtle", warn: "text-warn" }[tone];
  return <p className={`mt-3 text-sm ${cls}`}>{children}</p>;
}

function ScoreCircle({ score }) {
  const color = scoreColor(score);
  const r = 52;
  const circ = 2 * Math.PI * r;
  return (
    <div className="relative h-44 w-44 shrink-0">
      <div className="absolute inset-4 rounded-full blur-2xl" style={{ background: color, opacity: 0.15 }} />
      <svg viewBox="0 0 120 120" className="relative h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" style={{ stroke: "var(--ring-track)" }} strokeWidth="9" />
        <circle
          cx="60" cy="60" r={r} fill="none" strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - score / 100)}
          style={{ stroke: color, transition: "stroke-dashoffset 0.8s ease-out" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-5xl font-extrabold tracking-tight" style={{ color }}>{score}</span>
        <span className="text-sm text-subtle">out of 100</span>
      </div>
    </div>
  );
}

const SEVERITIES = [
  ["critical", "Critical", "bg-bad text-white dark:text-bg"],
  ["high", "High", "bg-bad-soft text-bad"],
  ["medium", "Medium", "bg-warn-soft text-warn"],
  ["low", "Low", "bg-surface-2 text-muted"],
];

function SeverityCounts({ findings }) {
  if (!findings.length) {
    return (
      <span className="chip bg-ok-soft text-ok">
        <Icon name="check" className="h-3 w-3" strokeWidth={3} /> No problems found
      </span>
    );
  }
  return SEVERITIES.map(([key, label, cls]) => {
    const n = findings.filter((f) => f.severity === key).length;
    return n ? <span key={key} className={`chip ${cls}`}>{n} {label}</span> : null;
  });
}

// null = could not test. It must never be shown as "Off" or "Missing".
const not = (v) => (v == null ? null : !v);
const present = (v) => (v == null ? "Could not check" : v ? "Present" : "Missing");
const enabled = (v) => (v == null ? "Could not test" : v ? "Enabled" : "Off");
const vulnerable = (v) => (v == null ? "Could not test" : v ? "Vulnerable" : "Not vulnerable");

function duration(seconds) {
  if (!seconds) return "";
  const days = Math.round(seconds / 86400);
  return days >= 365 ? `${Math.round(days / 365)} year(s)` : `${days} days`;
}

function redirectText(r) {
  if (!r || r.http_open == null) return "Could not check";
  if (!r.http_open) return "HTTP not offered";
  return r.redirects_to_https ? `Yes (${r.status})` : "No";
}

function CookieRows({ cookies }) {
  if (!cookies.length) return <Row label="Cookies" ok={true} value="None set on the home page" />;
  const all = (test) => cookies.every(test);
  return (
    <>
      <Row label="Cookies set" ok={true} value={cookies.length} />
      <Row label="All have Secure" ok={all((k) => k.secure)} />
      <Row label="All have HttpOnly" ok={all((k) => k.httponly)} />
      <Row label="All have SameSite" ok={all((k) => k.samesite)} />
    </>
  );
}

function CompareBox({ compare }) {
  if (!compare) return null;
  if (!compare.previous) {
    return (
      <p className="card flex items-center gap-3 text-muted">
        <Icon name="history" className="h-5 w-5 text-accent" /> This is your first scan of this site.
      </p>
    );
  }
  const change = compare.score_change;
  const List = ({ items, empty }) =>
    items.length ? (
      <ul className="mt-2 space-y-1 text-sm">{items.map((f) => <li key={f.id} className="flex gap-2"><span aria-hidden="true">•</span>{f.title}</li>)}</ul>
    ) : (
      <p className="mt-2 text-sm text-subtle">{empty}</p>
    );
  return (
    <section className="card fade-up">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="card-title">
          Compared with the previous scan ({new Date(compare.previous.scanned_at).toLocaleDateString()})
        </h2>
        <Link to={`/scans/${compare.previous.id}`} className="link text-sm">Open the previous scan</Link>
      </div>
      <p className="mt-2 font-semibold" style={{ color: change > 0 ? "var(--ok)" : change < 0 ? "var(--bad)" : "var(--muted)" }}>
        Score {change > 0 ? `went up by ${change}` : change < 0 ? `went down by ${-change}` : "did not change"} ({compare.previous.score} → {compare.previous.score + change})
      </p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div className="rounded-xl bg-ok-soft p-4"><h3 className="font-medium text-ok">Fixed since then</h3><List items={compare.fixed_findings} empty="Nothing fixed." /></div>
        <div className="rounded-xl bg-bad-soft p-4"><h3 className="font-medium text-bad">New problems</h3><List items={compare.new_findings} empty="No new problems." /></div>
      </div>
    </section>
  );
}

const yesNoUnknown = (v, yes = "Yes", no = "No") => (v == null ? "Could not check" : v ? yes : no);

export default function ScanResults({ data, compare = null }) {
  const { certificate: c, tls, cipher, headers: h } = data;
  const hd = data.header_details || {};
  const v = data.vulnerabilities || {};
  const negotiatedWeak = cipher.weak_list?.includes(cipher.negotiated);
  const weakCiphersOk = cipher.weak ? false : cipher.untested?.length ? null : true;
  const grade = scoreGrade(data.score);
  return (
    <div className="mt-8 space-y-6">
      <section className="card fade-up relative overflow-hidden">
        <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full blur-3xl" style={{ background: "var(--glow)" }} />
        <div className="relative flex flex-col items-center gap-8 md:flex-row md:items-center">
          <ScoreCircle score={data.score} />
          <div className="min-w-0 flex-1 text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center gap-3 md:justify-start">
              <h2 className="break-all text-2xl font-bold tracking-tight text-fg sm:text-3xl">{data.domain}</h2>
              <p
                className="rounded-lg px-2.5 py-1 text-sm font-bold"
                style={{ color: scoreColor(data.score), background: "color-mix(in srgb, currentColor 12%, transparent)" }}
              >
                Grade {grade}
              </p>
            </div>
            <p className="mt-1 text-sm text-subtle">Scanned on {new Date(data.scanned_at).toLocaleString()}</p>
            <div className="mt-3 flex flex-wrap justify-center gap-2 md:justify-start">
              <SeverityCounts findings={data.findings || []} />
            </div>
            <div className="mt-4 space-y-2 text-left">
              {data.requested_domain && (
                <p className="notice border-line bg-surface-2 text-muted">
                  {data.requested_domain} has no website of its own, so we scanned {data.domain} instead.
                </p>
              )}
              {data.cached && (
                <p className="notice border-line bg-surface-2 text-muted">This site was scanned a few minutes ago, so that result was reused.</p>
              )}
              {data.untested?.length > 0 && (
                <p className="notice border-warn/30 bg-warn-soft text-fg">
                  <strong>Partial result:</strong> {data.untested.join(", ")} could not be checked. The score only counts the
                  checks that ran, so it may be higher than the site deserves.
                </p>
              )}
              {data.score_cap && (
                <p className="notice border-bad/30 bg-bad-soft font-medium text-bad">
                  Score capped at {data.score_cap.max_score} because: {data.score_cap.title}.
                </p>
              )}
            </div>
            <div className="mt-5 flex flex-wrap items-center justify-center gap-3 md:justify-start">
              <button onClick={() => downloadReport(data, grade)} className="btn-primary">
                <Icon name="download" className="h-4 w-4" />
                Download report (PDF)
              </button>
              <p className="text-xs text-subtle">
                This score comes from SecureSphere's own rules. It is not a guarantee of security.
              </p>
            </div>
          </div>
        </div>
      </section>

      <div className="grid gap-6 md:grid-cols-2">
        <Card title="Certificate" icon="cert">
          <Row label="Valid" ok={c.valid} />
          <Row label="Domain matches" ok={c.hostname_match} value={c.hostname_match == null ? "Unknown" : undefined} />
          <Row label="Not self-signed" ok={!c.self_signed} />
          <Row label="Days remaining" ok={c.days_remaining > 30} value={c.days_remaining} />
          {c.key && <Row label="Key" ok={not(c.weak_key)} value={c.key} />}
          {c.signature && <Row label="Signature" ok={not(c.weak_signature)} value={c.signature} />}
          {c.chain_complete != null && (
            <Row label="Full chain sent" ok={c.chain_complete} value={c.chain_complete ? undefined : "Intermediate missing"} />
          )}
          <Note>
            Issuer: {c.issuer} · Expires {c.expiry_date}
          </Note>
        </Card>

        <Card title="Protocol versions" icon="layers">
          {tls.ssl_2 != null && <Row label="SSL 2.0 (broken)" ok={not(tls.ssl_2)} value={enabled(tls.ssl_2)} />}
          {tls.ssl_3 != null && <Row label="SSL 3.0 (broken)" ok={not(tls.ssl_3)} value={enabled(tls.ssl_3)} />}
          <Row label="TLS 1.0 (outdated)" ok={not(tls.tls_1_0)} value={enabled(tls.tls_1_0)} />
          <Row label="TLS 1.1 (outdated)" ok={not(tls.tls_1_1)} value={enabled(tls.tls_1_1)} />
          <Row label="TLS 1.2" ok={tls.tls_1_2} value={enabled(tls.tls_1_2)} />
          <Row label="TLS 1.3 (preferred)" ok={tls.tls_1_3} value={enabled(tls.tls_1_3)} />
        </Card>

        <Card title="Cipher" icon="key">
          <Row label="Cipher in use" ok={cipher.negotiated === "Unknown" ? null : !negotiatedWeak} value={cipher.negotiated} />
          <Row label="Forward secrecy" ok={cipher.forward_secrecy} value={cipher.forward_secrecy == null ? "Could not test" : undefined} />
          <Row
            label="Weak ciphers accepted"
            ok={weakCiphersOk}
            value={cipher.weak ? cipher.weak_list.length : weakCiphersOk == null ? "Partly tested" : "None"}
          />
          {cipher.untested?.length > 0 && (
            <Note>Could not be tested from this server: {cipher.untested.join(", ")}.</Note>
          )}
        </Card>

        <Card title="Security headers" icon="file">
          <Row
            label="HSTS"
            ok={h.hsts == null ? null : h.hsts && !hd.hsts_max_age_too_short}
            value={h.hsts ? `Present (${duration(hd.hsts_max_age)})` : present(h.hsts)}
          />
          <Row
            label="CSP"
            ok={h.csp == null ? null : h.csp && !hd.csp_weaknesses?.length}
            value={hd.csp_report_only ? "Report-only" : h.csp && hd.csp_weaknesses?.length ? "Present (weak)" : present(h.csp)}
          />
          <Row label="X-Frame-Options" ok={h.x_frame_options} value={present(h.x_frame_options)} />
          <Row label="X-Content-Type-Options" ok={h.x_content_type_options} value={present(h.x_content_type_options)} />
          <Row label="Referrer-Policy" ok={h.referrer_policy} value={present(h.referrer_policy)} />
          {hd.redirects_to && (
            <Note tone="warn">
              This site sends visitors to {hd.redirects_to}, so its page headers were not checked here. Scan {hd.redirects_to} to see them.
            </Note>
          )}
          {hd.blocked_by && (
            <Note tone="warn">
              The site's firewall ({hd.blocked_by}) blocked the scanner's page request, so headers and cookies could not be checked. Try again later.
            </Note>
          )}
          {h.hsts && (
            <Note>
              HSTS: includeSubDomains {hd.hsts_include_subdomains ? "yes" : "no"} · preload {hd.hsts_preload ? "yes" : "no"}
            </Note>
          )}
        </Card>

        <Card title="HTTPS redirect and cookies" icon="cookie">
          <Row
            label="HTTP → HTTPS redirect"
            ok={data.redirect?.http_open === false ? true : data.redirect?.redirects_to_https ?? null}
            value={redirectText(data.redirect)}
          />
          <CookieRows cookies={data.cookies || []} />
        </Card>

        <Card title="Known vulnerabilities" icon="bug">
          <Row label="Heartbleed" ok={not(v.heartbleed)} value={vulnerable(v.heartbleed)} />
          <Row label="OpenSSL CCS injection" ok={not(v.ccs_injection)} value={vulnerable(v.ccs_injection)} />
          <Row label="ROBOT" ok={not(v.robot)} value={vulnerable(v.robot)} />
        </Card>

        {data.dns && (
          <Card title="DNS" icon="globe">
            <Row
              label="CAA record"
              ok={data.dns.caa ? data.dns.caa.present : null}
              value={data.dns.caa == null ? "Could not check" : data.dns.caa.present ? "Present" : "Missing"}
            />
            {/* DNSSEC and preload are good extras; most sites have neither, so "No" is not a warning. */}
            <Row label="DNSSEC" ok={data.dns.dnssec ? true : null} value={yesNoUnknown(data.dns.dnssec, "Enabled", "Not enabled")} />
            <Row label="HSTS preload list" ok={data.dns.hsts_preloaded ? true : null} value={yesNoUnknown(data.dns.hsts_preloaded, "Listed", "Not listed")} />
            {data.dns.caa?.issuers?.length > 0 && (
              <Note>Allowed certificate authorities: {data.dns.caa.issuers.join(", ")}</Note>
            )}
          </Card>
        )}

        {data.variant && (
          <Card title={`Other address: ${data.variant.host}`} icon="link">
            {data.variant.exists === false ? (
              <p className="text-sm text-muted">This address does not exist, so there is nothing to check.</p>
            ) : data.variant.exists == null ? (
              <p className="text-sm text-muted">Could not check this address.</p>
            ) : (
              <>
                <Row label="Serves HTTPS" ok={data.variant.https_ok} value={yesNoUnknown(data.variant.https_ok)} />
                <Row
                  label="Valid certificate"
                  ok={data.variant.chain_incomplete ? false : data.variant.cert_valid}
                  value={data.variant.chain_incomplete ? "Yes, but chain incomplete" : yesNoUnknown(data.variant.cert_valid)}
                />
                <Row
                  label="HTTP → HTTPS redirect"
                  ok={data.variant.redirects_to_https ?? null}
                  value={data.variant.redirects_to_https == null ? "HTTP not offered" : data.variant.redirects_to_https ? "Yes" : "No"}
                />
              </>
            )}
          </Card>
        )}
      </div>

      <CompareBox compare={compare} />

      <MonitorToggle domain={data.domain} />
      <Findings data={data} />
    </div>
  );
}

// Project-defined grade bands, not an industry standard.
export function scoreGrade(score) {
  return score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
}

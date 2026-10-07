import { Link } from "react-router-dom";
import { downloadReport } from "../reportPdf";
import Findings from "./Findings";
import MonitorToggle from "./MonitorToggle";

export function scoreColor(score) {
  // green 80+, orange 50-79, red below 50
  return score >= 80 ? "#047857" : score >= 50 ? "#d97706" : "#b91c1c";
}

function Mark({ ok }) {
  if (ok == null) return <span className="font-semibold text-slate-400" title="Could not be tested">?</span>;
  return ok ? (
    <span className="font-semibold text-emerald-700">✓</span>
  ) : (
    <span className="font-semibold text-amber-600">⚠</span>
  );
}

function Row({ label, ok, value }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-100 py-2 last:border-0">
      <span className="text-slate-600">{label}</span>
      <span className="flex items-center gap-2 text-slate-900">
        {value !== undefined && <span className="text-sm">{value}</span>}
        <Mark ok={ok} />
      </span>
    </div>
  );
}

function Card({ title, children }) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="mb-2 text-lg font-semibold text-slate-900">{title}</h2>
      {children}
    </section>
  );
}

function ScoreCircle({ score }) {
  const color = scoreColor(score);
  const r = 54;
  const circ = 2 * Math.PI * r;
  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e2e8f0" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - score / 100)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold" style={{ color }}>{score}</span>
        <span className="text-sm text-slate-500">out of 100</span>
      </div>
    </div>
  );
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
    return <p className="rounded-lg border border-slate-200 bg-white p-5 text-slate-600">This is your first scan of this site.</p>;
  }
  const change = compare.score_change;
  const List = ({ items, empty }) =>
    items.length ? (
      <ul className="mt-1 list-disc pl-5">{items.map((f) => <li key={f.id}>{f.title}</li>)}</ul>
    ) : (
      <p className="mt-1 text-slate-500">{empty}</p>
    );
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      <h2 className="text-lg font-semibold">
        Compared with the previous scan ({new Date(compare.previous.scanned_at).toLocaleDateString()})
      </h2>
      <p className="mt-1 font-semibold" style={{ color: change > 0 ? "#047857" : change < 0 ? "#b91c1c" : "#475569" }}>
        Score {change > 0 ? `went up by ${change}` : change < 0 ? `went down by ${-change}` : "did not change"} ({compare.previous.score} → {compare.previous.score + change})
      </p>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <div><h3 className="font-medium text-emerald-800">Fixed since then</h3><List items={compare.fixed_findings} empty="Nothing fixed." /></div>
        <div><h3 className="font-medium text-red-800">New problems</h3><List items={compare.new_findings} empty="No new problems." /></div>
      </div>
      <Link to={`/scans/${compare.previous.id}`} className="mt-3 inline-block text-sm font-medium text-teal-700 underline">Open the previous scan</Link>
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
  return (
    <div className="mt-8 space-y-6">
      <div className="flex flex-col items-center gap-6 rounded-lg border border-slate-200 bg-white p-6 sm:flex-row">
        <ScoreCircle score={data.score} />
        <div>
          <h2 className="text-2xl font-semibold text-slate-900">{data.domain}</h2>
          <p className="font-semibold" style={{ color: scoreColor(data.score) }}>
            Grade {scoreGrade(data.score)}
          </p>
          <p className="text-slate-600">Scanned on {new Date(data.scanned_at).toLocaleString()}</p>
          {data.cached && (
            <p className="text-sm text-slate-500">This site was scanned a few minutes ago, so that result was reused.</p>
          )}
          {data.score_cap && (
            <p className="mt-1 text-sm font-medium text-red-800">
              Score capped at {data.score_cap.max_score} because: {data.score_cap.title}.
            </p>
          )}
          <p className="mt-1 text-sm text-slate-500">
            This score comes from SecureSphere's own rules. It is not a guarantee of security.
          </p>
          <button
            onClick={() => downloadReport(data, scoreGrade(data.score))}
            className="mt-3 rounded-md border border-teal-700 px-4 py-2 font-semibold text-teal-800 hover:bg-teal-50"
          >
            Download report (PDF)
          </button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card title="Certificate">
          <Row label="Valid" ok={c.valid} />
          <Row label="Domain matches" ok={c.hostname_match} value={c.hostname_match == null ? "Unknown" : undefined} />
          <Row label="Not self-signed" ok={!c.self_signed} />
          <Row label="Days remaining" ok={c.days_remaining > 30} value={c.days_remaining} />
          {c.key && <Row label="Key" ok={not(c.weak_key)} value={c.key} />}
          {c.signature && <Row label="Signature" ok={not(c.weak_signature)} value={c.signature} />}
          <p className="mt-2 text-sm text-slate-500">
            Issuer: {c.issuer} · Expires {c.expiry_date}
          </p>
        </Card>

        <Card title="Protocol versions">
          {tls.ssl_2 != null && <Row label="SSL 2.0 (broken)" ok={not(tls.ssl_2)} value={enabled(tls.ssl_2)} />}
          {tls.ssl_3 != null && <Row label="SSL 3.0 (broken)" ok={not(tls.ssl_3)} value={enabled(tls.ssl_3)} />}
          <Row label="TLS 1.0 (outdated)" ok={not(tls.tls_1_0)} value={enabled(tls.tls_1_0)} />
          <Row label="TLS 1.1 (outdated)" ok={not(tls.tls_1_1)} value={enabled(tls.tls_1_1)} />
          <Row label="TLS 1.2" ok={tls.tls_1_2} value={enabled(tls.tls_1_2)} />
          <Row label="TLS 1.3 (preferred)" ok={tls.tls_1_3} value={enabled(tls.tls_1_3)} />
        </Card>

        <Card title="Cipher">
          <Row label="Cipher in use" ok={cipher.negotiated === "Unknown" ? null : !negotiatedWeak} value={cipher.negotiated} />
          <Row label="Forward secrecy" ok={cipher.forward_secrecy} value={cipher.forward_secrecy == null ? "Could not test" : undefined} />
          <Row
            label="Weak ciphers accepted"
            ok={weakCiphersOk}
            value={cipher.weak ? cipher.weak_list.length : weakCiphersOk == null ? "Partly tested" : "None"}
          />
          {cipher.untested?.length > 0 && (
            <p className="mt-2 text-sm text-slate-500">Could not be tested from this server: {cipher.untested.join(", ")}.</p>
          )}
        </Card>

        <Card title="Security headers">
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
          {hd.blocked_by && (
            <p className="mt-2 text-sm text-amber-800">
              The site's firewall ({hd.blocked_by}) blocked the scanner's page request, so headers and cookies could not be checked. Try again later.
            </p>
          )}
          {h.hsts && (
            <p className="mt-2 text-sm text-slate-500">
              HSTS: includeSubDomains {hd.hsts_include_subdomains ? "yes" : "no"} · preload {hd.hsts_preload ? "yes" : "no"}
            </p>
          )}
        </Card>

        <Card title="HTTPS redirect and cookies">
          <Row
            label="HTTP → HTTPS redirect"
            ok={data.redirect?.http_open === false ? true : data.redirect?.redirects_to_https ?? null}
            value={redirectText(data.redirect)}
          />
          <CookieRows cookies={data.cookies || []} />
        </Card>

        <Card title="Known vulnerabilities">
          <Row label="Heartbleed" ok={not(v.heartbleed)} value={vulnerable(v.heartbleed)} />
          <Row label="OpenSSL CCS injection" ok={not(v.ccs_injection)} value={vulnerable(v.ccs_injection)} />
          <Row label="ROBOT" ok={not(v.robot)} value={vulnerable(v.robot)} />
        </Card>

        {data.dns && (
          <Card title="DNS">
            <Row
              label="CAA record"
              ok={data.dns.caa ? data.dns.caa.present : null}
              value={data.dns.caa == null ? "Could not check" : data.dns.caa.present ? "Present" : "Missing"}
            />
            {/* DNSSEC and preload are good extras; most sites have neither, so "No" is not a warning. */}
            <Row label="DNSSEC" ok={data.dns.dnssec ? true : null} value={yesNoUnknown(data.dns.dnssec, "Enabled", "Not enabled")} />
            <Row label="HSTS preload list" ok={data.dns.hsts_preloaded ? true : null} value={yesNoUnknown(data.dns.hsts_preloaded, "Listed", "Not listed")} />
            {data.dns.caa?.issuers?.length > 0 && (
              <p className="mt-2 text-sm text-slate-500">Allowed certificate authorities: {data.dns.caa.issuers.join(", ")}</p>
            )}
          </Card>
        )}

        {data.variant && (
          <Card title={`Other address: ${data.variant.host}`}>
            {data.variant.exists === false ? (
              <p className="text-slate-600">This address does not exist, so there is nothing to check.</p>
            ) : data.variant.exists == null ? (
              <p className="text-slate-600">Could not check this address.</p>
            ) : (
              <>
                <Row label="Serves HTTPS" ok={data.variant.https_ok} value={yesNoUnknown(data.variant.https_ok)} />
                <Row label="Valid certificate" ok={data.variant.cert_valid} value={yesNoUnknown(data.variant.cert_valid)} />
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
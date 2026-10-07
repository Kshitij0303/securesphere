import { jsPDF } from "jspdf";

const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
// null = could not test. It must never be printed as "Off", "No" or "Missing".
const ok = (v) => (v == null ? "Unknown" : v ? "OK" : "Warning");
const yesNo = (v) => (v == null ? "Could not test" : v ? "Yes" : "No");
const oldTls = (v) => (v == null ? "Could not test" : v ? "Enabled - Warning" : "Off");
const tlsState = (v) => (v == null ? "Could not test" : v ? "Enabled" : "Off");
const header = (v) => (v == null ? "Could not check" : v ? "Present" : "Missing");

// Builds a PDF report from one scan result and downloads it.
export function downloadReport(data, grade) {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const M = 15;
  const maxW = 210 - 2 * M;
  let y = M;

  function text(str, { size = 11, bold = false, gap = 1.5, color = [30, 41, 59] } = {}) {
    doc.setFont("helvetica", bold ? "bold" : "normal");
    doc.setFontSize(size);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(String(str), maxW);
    const lh = size * 0.4057;
    if (y + lines.length * lh + gap > 282) {
      doc.addPage();
      y = M;
    }
    doc.text(lines, M, y + size * 0.35);
    y += lines.length * lh + gap;
  }
  const heading = (str) => { y += 3; text(str, { size: 13, bold: true, gap: 2 }); };
  const row = (label, value) => text(`${label}: ${value}`);

  const c = data.certificate, t = data.tls, ci = data.cipher, h = data.headers;

  text("SecureSphere Security Report", { size: 20, bold: true, gap: 3 });
  row("Domain", data.domain);
  row("Scanned on", new Date(data.scanned_at).toLocaleString());
  row("Score", `${data.score} / 100 (grade ${grade})`);
  if (data.untested?.length) {
    text(`Partial result: ${data.untested.join(", ")} could not be checked. The score only counts the checks that ran.`, { size: 9, color: [146, 64, 14] });
  }
  if (data.score_cap) row("Score capped", `at ${data.score_cap.max_score} because: ${data.score_cap.title}`);
  text("The score and grade come from SecureSphere's own rules. They are not an industry standard.", { size: 9, color: [100, 116, 139] });

  heading("Certificate");
  row("Valid", ok(c.valid));
  row("Domain matches certificate", ok(c.hostname_match));
  row("Self-signed", yesNo(c.self_signed));
  row("Issuer", c.issuer);
  row("Expires", `${c.expiry_date} (${c.days_remaining} days remaining)`);
  if (c.key) row("Key", `${c.key}${c.weak_key ? " - Warning: too short" : ""}`);
  if (c.signature) row("Signature", `${c.signature}${c.weak_signature ? " - Warning: outdated" : ""}`);

  heading("Protocol versions");
  if (t.ssl_2 != null) row("SSL 2.0 (broken)", oldTls(t.ssl_2));
  if (t.ssl_3 != null) row("SSL 3.0 (broken)", oldTls(t.ssl_3));
  row("TLS 1.0 (outdated)", oldTls(t.tls_1_0));
  row("TLS 1.1 (outdated)", oldTls(t.tls_1_1));
  row("TLS 1.2", tlsState(t.tls_1_2));
  row("TLS 1.3 (preferred)", tlsState(t.tls_1_3));

  heading("Cipher");
  row("Cipher in use", ci.negotiated);
  row("Weak ciphers accepted", ci.weak ? ci.weak_list.join(", ") : ci.untested?.length ? `None found (not tested: ${ci.untested.join(", ")})` : "None");
  row("Forward secrecy", yesNo(ci.forward_secrecy));

  heading("Security headers");
  row("HSTS", header(h.hsts));
  row("Content-Security-Policy", data.header_details?.csp_report_only ? "Report-only (blocks nothing) - Warning" : header(h.csp));
  row("X-Frame-Options", header(h.x_frame_options));
  row("X-Content-Type-Options", header(h.x_content_type_options));
  row("Referrer-Policy", header(h.referrer_policy));
  if (data.header_details?.blocked_by) {
    text(`The site's firewall (${data.header_details.blocked_by}) blocked the scanner, so headers and cookies could not be checked.`, { size: 9, color: [146, 64, 14] });
  }

  const r = data.redirect;
  heading("HTTPS redirect and cookies");
  row("HTTP to HTTPS redirect", !r || r.http_open == null ? "Could not check" : !r.http_open ? "HTTP not offered" : r.redirects_to_https ? `Yes (${r.status})` : "No - Warning");
  const cookies = data.cookies || [];
  row("Cookies set on home page", cookies.length);
  cookies.forEach((k) => row(`  ${k.name}`, `Secure ${yesNo(k.secure)}, HttpOnly ${yesNo(k.httponly)}, SameSite ${k.samesite || "not set"}`));

  const v = data.vulnerabilities || {};
  const vuln = (x) => (x == null ? "Could not test" : x ? "VULNERABLE" : "Not vulnerable");
  heading("Known vulnerabilities");
  row("Heartbleed", vuln(v.heartbleed));
  row("OpenSSL CCS injection", vuln(v.ccs_injection));
  row("ROBOT", vuln(v.robot));

  if (data.dns) {
    const d = data.dns;
    heading("DNS");
    row("CAA record", d.caa == null ? "Could not check" : d.caa.present ? `Present (${d.caa.issuers.join(", ") || "no issuers listed"})` : "Missing");
    row("DNSSEC", d.dnssec == null ? "Could not check" : d.dnssec ? "Enabled" : "Not enabled");
    row("HSTS preload list", d.hsts_preloaded == null ? "Could not check" : d.hsts_preloaded ? "Listed" : "Not listed");
  }
  if (data.variant) {
    const va = data.variant;
    heading(`Other address: ${va.host}`);
    if (va.exists === false) text("This address does not exist, so there is nothing to check.");
    else if (va.exists == null) text("Could not check this address.");
    else {
      row("Serves HTTPS", yesNo(va.https_ok));
      row("Valid certificate", yesNo(va.cert_valid));
      row("HTTP to HTTPS redirect", va.redirects_to_https == null ? "HTTP not offered" : va.redirects_to_https ? "Yes" : "No - Warning");
    }
  }

  heading("Findings and fixes");
  const findings = [...(data.findings || [])].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  if (findings.length === 0) {
    text("No problems were found in this scan.");
  } else {
    findings.forEach((f, i) => {
      const pts = f.points_lost == null ? "" : f.points_lost > 0 ? ` (-${f.points_lost} points)` : " (no extra points: category limit reached)";
      text(`${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${pts}`, { bold: true });
      if (f.evidence && f.evidence !== f.problem) row("What we found", f.evidence);
      row("Problem", f.problem);
      row("Impact", f.impact);
      text(`Fix: ${f.fix}`, { gap: 3 });
    });
  }

  y += 4;
  text(
    "SecureSphere analyses configuration only. It is not a penetration-testing tool, it does not fix servers, and a high score does not guarantee security.",
    { size: 9, color: [100, 116, 139] }
  );

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text(`Page ${i} of ${pages}`, 195, 290, { align: "right" });
  }

  doc.save(`securesphere-report-${data.domain.replace(/[^a-z0-9.-]/gi, "_")}.pdf`);
}
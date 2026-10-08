// Findings whose "What we found" line only repeats the title (e.g. "Outdated TLS 1.0 is enabled" /
// "Server accepts TLS 1.0"). For these the line is hidden; findings with real details (cookie names,
// cipher names, dates, addresses) keep it.
const RESTATES_TITLE = new Set([
  "SSL_2_ENABLED", "SSL_3_ENABLED", "TLS_1_0_ENABLED", "TLS_1_1_ENABLED", "NO_MODERN_TLS", "TLS_1_3_NOT_SUPPORTED",
  "NO_MODERN_CIPHERS", "CERT_SELF_SIGNED", "CERT_CHAIN_INCOMPLETE", "HTTPS_NO_PAGE", "ROBOT_VULNERABLE",
  "HSTS_MISSING", "CSP_MISSING", "CSP_REPORT_ONLY",
  "X_FRAME_OPTIONS_MISSING", "X_CONTENT_TYPE_OPTIONS_MISSING", "REFERRER_POLICY_MISSING",
]);

export const showEvidence = (f) => Boolean(f.evidence) && f.evidence !== f.problem && !RESTATES_TITLE.has(f.id);

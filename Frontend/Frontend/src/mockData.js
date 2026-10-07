// Fake data so the frontend works before the backend is ready.
// Field names are a proposal - confirm the final JSON format with Part 1 and Part 2.
export const mockScan = {
  domain: "github.com",
  scanned_at: "2026-10-02T10:30:00",
  score: 82,
  certificate: { valid: true, issuer: "DigiCert", expiry_date: "2027-03-10", days_remaining: 159, hostname_match: true, self_signed: false },
  tls: { tls_1_0: false, tls_1_1: false, tls_1_2: true, tls_1_3: true },
  cipher: { negotiated: "TLS_AES_128_GCM_SHA256", weak: false, forward_secrecy: true },
  headers: { hsts: true, csp: false, x_frame_options: true, x_content_type_options: true, referrer_policy: false },
  // severity: "high" | "medium" | "low". The page sorts them, high first.
  findings: [
    {
      severity: "low",
      title: "Referrer-Policy header is missing",
      problem: "The site does not tell browsers how much of the page address to share with other sites.",
      impact: "Visitors' page addresses may be sent to other websites when they click links.",
      fix: "Add the header Referrer-Policy: strict-origin-when-cross-origin in your web server settings.",
    },
    {
      severity: "medium",
      title: "Content-Security-Policy header is missing",
      problem: "The site does not limit which scripts a browser may run.",
      impact: "An attacker who injects a script into a page has an easier time running it.",
      fix: "Add a Content-Security-Policy header, starting with a simple policy such as default-src 'self'.",
    },
  ],
  ai_explanation: "",
};

export const mockHistory = [
  { scanned_at: "2026-10-02T10:30:00", score: 82 },
  { scanned_at: "2026-09-25T09:00:00", score: 85 },
  { scanned_at: "2026-09-18T09:00:00", score: 72 },
  { scanned_at: "2026-09-11T09:00:00", score: 45 },
];

export const mockAlerts = [
  { id: 1, domain: "github.com", message: "Score dropped from 85 to 82.", created_at: "2026-10-02T10:30:00", read: false },
  { id: 2, domain: "example.org", message: "Certificate expires in 12 days.", created_at: "2026-09-30T08:00:00", read: false },
  { id: 3, domain: "example.org", message: "TLS 1.0 is now enabled.", created_at: "2026-09-20T08:00:00", read: true },
];
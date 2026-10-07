// The built-in assistant: answers without any AI service, free and offline.
// Every statement about the user's site comes from their real scan result, so it can never invent problems.
// When the server has an AI key, the AI is used instead (see askAssistant in api.js).

const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// "could not be tested" must never be described as on/off.
const state = (v, yes, no) => (v == null ? "could not be tested" : v ? yes : no);

function findingsFor(scan, ids) {
  return (scan?.findings || []).filter((f) => ids.some((id) => f.id === id || f.id?.startsWith(id)));
}

function describeFinding(f) {
  const points = f.points_lost == null ? "" : f.points_lost > 0 ? ` (−${f.points_lost} points)` : " (no extra points: category limit reached)";
  return `• ${f.title}${points}\n  Found: ${f.evidence || f.problem}\n  Why it matters: ${f.impact || f.problem}\n  Fix: ${f.fix}`;
}

// Topics: what a term means, what this scan found about it, and which findings belong to it.
const TOPICS = [
  {
    words: ["certificate", "cert ", "ssl certificate", "expire", "expiry", "issuer", "renew"],
    ids: ["CERT_EXPIRED", "CERT_EXPIRES", "CERT_HOSTNAME", "CERT_SELF", "CERT_UNTRUSTED"],
    explain: "A certificate is the website's ID card. A trusted authority signs it to prove the site is really who it says it is, and it expires after a set time, so it must be renewed.",
    status: (s) => {
      const c = s.certificate;
      return `On ${s.domain}: issued by ${c.issuer}, expires ${c.expiry_date} (${c.days_remaining} days left). ` +
        `Trusted: ${state(c.valid, "yes", "no")}. Matches the domain: ${state(c.hostname_match, "yes", "no")}.`;
    },
  },
  {
    words: ["self-signed", "self signed", "certificate authority", "untrusted"],
    ids: ["CERT_SELF", "CERT_UNTRUSTED"],
    explain: "A certificate authority (CA) is a company browsers trust to check who owns a domain. A self-signed certificate was made by the server itself, so it proves nothing and browsers show a warning.",
  },
  {
    words: ["key size", "rsa", "short key", "weak key", "signature", "sha-1", "sha1", "md5"],
    ids: ["CERT_WEAK_KEY", "CERT_WEAK_SIGNATURE"],
    explain: "The certificate's key and signature protect it from forgery. Keys should be at least 2048-bit RSA or 256-bit EC, and signatures should use SHA-256; SHA-1 and MD5 are broken.",
    status: (s) => s.certificate.key && `On ${s.domain}: ${s.certificate.key} key, signed with ${s.certificate.signature}.`,
  },
  {
    words: ["tls", "ssl", "protocol", "version", "1.0", "1.1", "1.2", "1.3", "poodle", "drown"],
    ids: ["TLS_1_0", "TLS_1_1", "TLS_1_3", "NO_MODERN_TLS", "SSL_2", "SSL_3"],
    explain: "SSL and TLS are the technology behind the padlock: they scramble data between visitors and the site. TLS 1.3 is best, TLS 1.2 is fine, and SSL 2/3 and TLS 1.0/1.1 are outdated and should be switched off.",
    status: (s) => {
      const t = s.tls;
      const parts = [["SSL 3.0", t.ssl_3], ["TLS 1.0", t.tls_1_0], ["TLS 1.1", t.tls_1_1], ["TLS 1.2", t.tls_1_2], ["TLS 1.3", t.tls_1_3]];
      return `On ${s.domain}: ` + parts.map(([n, v]) => `${n} ${state(v, "on", "off")}`).join(", ") + ".";
    },
  },
  {
    words: ["cipher", "rc4", "3des", "des ", "encryption", "aes", "chacha"],
    ids: ["WEAK_CIPHERS"],
    explain: "A cipher is the method used to scramble the data. Modern ciphers like AES-GCM and ChaCha20 are safe; old ones like RC4, 3DES and DES can be broken.",
    status: (s) => {
      const c = s.cipher;
      const weak = c.weak ? `It still accepts ${c.weak_list.length} weak cipher(s): ${c.weak_list.slice(0, 4).join(", ")}.`
        : c.untested?.length ? `No weak ciphers were found, but some could not be tested (${c.untested.join(", ")}).` : "No weak ciphers are accepted.";
      return `On ${s.domain}: the default cipher is ${c.negotiated}. ${weak}`;
    },
  },
  {
    words: ["forward secrecy", "pfs", "ecdhe"],
    ids: ["NO_FORWARD_SECRECY"],
    explain: "Forward secrecy means each connection uses its own temporary key. Even if the server's main key is stolen later, old recorded traffic stays unreadable.",
    status: (s) => `On ${s.domain}: forward secrecy ${state(s.cipher.forward_secrecy, "is used", "is not used")}.`,
  },
  {
    words: ["heartbleed", "robot", "ccs", "vulnerab", "cve"],
    ids: ["HEARTBLEED", "CCS_INJECTION", "ROBOT_VULNERABLE"],
    explain: "Heartbleed, CCS injection and ROBOT are famous bugs in old TLS software that let attackers read memory or decrypt traffic. SecureSphere tests for them without harming the server.",
    status: (s) => {
      const v = s.vulnerabilities || {};
      const say = (x) => (x == null ? "could not be tested" : x ? "VULNERABLE" : "not vulnerable");
      return `On ${s.domain}: Heartbleed ${say(v.heartbleed)}, CCS injection ${say(v.ccs_injection)}, ROBOT ${say(v.robot)}.`;
    },
  },
  {
    words: ["hsts", "strict-transport", "strict transport", "preload"],
    ids: ["HSTS_MISSING", "HSTS_SHORT"],
    explain: "HSTS is a header that tells browsers to always use HTTPS for your site, even if someone types http://. This stops attackers from downgrading visitors to an unprotected connection.",
    status: (s) => {
      const hd = s.header_details || {};
      const days = hd.hsts_max_age ? `, remembered for ${Math.round(hd.hsts_max_age / 86400)} days` : "";
      const preload = s.dns ? ` On the browsers' preload list: ${state(s.dns.hsts_preloaded, "yes", "no")}.` : "";
      return `On ${s.domain}: HSTS is ${state(s.headers.hsts, "present", "missing")}${s.headers.hsts ? days : ""}.${preload}`;
    },
  },
  {
    words: ["csp", "content-security", "content security", "xss", "cross-site scripting", "unsafe-inline", "script"],
    ids: ["CSP_"],
    explain: "A Content-Security-Policy (CSP) tells browsers which scripts may run on your pages. It is one of the best defences against XSS, where an attacker sneaks their own script into a page.",
    status: (s) => {
      const hd = s.header_details || {};
      if (hd.csp_report_only) return `On ${s.domain}: the CSP is only in "report-only" mode, so it blocks nothing yet.`;
      const weak = hd.csp_weaknesses?.length ? ` It allows ${hd.csp_weaknesses.join(" and ")}, which weakens it.` : "";
      return `On ${s.domain}: CSP is ${state(s.headers.csp, "present", "missing")}.${weak}`;
    },
  },
  {
    words: ["x-frame", "frame", "clickjack", "iframe"],
    ids: ["X_FRAME_OPTIONS"],
    explain: "X-Frame-Options stops other websites from showing your site inside a hidden frame. Without it, attackers can trick visitors into clicking buttons they cannot see (clickjacking).",
    status: (s) => `On ${s.domain}: X-Frame-Options is ${state(s.headers.x_frame_options, "present", "missing")}.`,
  },
  {
    words: ["x-content-type", "nosniff", "mime", "sniff"],
    ids: ["X_CONTENT_TYPE"],
    explain: "X-Content-Type-Options: nosniff stops browsers from guessing a file's type. Guessing can turn an uploaded file into a script that runs.",
    status: (s) => `On ${s.domain}: X-Content-Type-Options is ${state(s.headers.x_content_type_options, "present", "missing")}.`,
  },
  {
    words: ["referrer", "referer"],
    ids: ["REFERRER_POLICY"],
    explain: "Referrer-Policy controls how much of a page's address is shared with other sites when visitors click a link. Addresses can contain private information.",
    status: (s) => `On ${s.domain}: Referrer-Policy is ${state(s.headers.referrer_policy, "present", "missing")}.`,
  },
  {
    words: ["header"],
    ids: ["HSTS_", "CSP_", "X_FRAME", "X_CONTENT", "REFERRER"],
    explain: "Security headers are short instructions the server sends to the browser, such as \"always use HTTPS\" (HSTS) or \"only run my own scripts\" (CSP). They are free to add and block whole classes of attacks.",
    status: (s) => {
      const h = s.headers;
      const names = [["HSTS", h.hsts], ["CSP", h.csp], ["X-Frame-Options", h.x_frame_options], ["X-Content-Type-Options", h.x_content_type_options], ["Referrer-Policy", h.referrer_policy]];
      return `On ${s.domain}: ` + names.map(([n, v]) => `${n} ${state(v, "present", "missing")}`).join(", ") + ".";
    },
  },
  {
    words: ["cookie", "httponly", "samesite", "csrf", "session"],
    ids: ["COOKIE_"],
    explain: "Cookies often hold logins. Secure keeps them off unencrypted connections, HttpOnly hides them from scripts (protecting against XSS), and SameSite stops other sites from sending them along (protecting against CSRF).",
    status: (s) => {
      const list = s.cookies || [];
      if (!list.length) return `On ${s.domain}: the home page sets no cookies.`;
      return `On ${s.domain}: ${list.length} cookie(s): ` +
        list.slice(0, 5).map((c) => `${c.name} (Secure ${c.secure ? "yes" : "no"}, HttpOnly ${c.httponly ? "yes" : "no"}, SameSite ${c.samesite || "not set"})`).join("; ") + ".";
    },
  },
  {
    words: ["redirect", "http://", "plain http", "port 80"],
    ids: ["NO_HTTPS_REDIRECT"],
    explain: "When someone types your address without https://, the server should immediately send them to the https:// version. Otherwise they stay on an unprotected connection.",
    status: (s) => {
      const r = s.redirect;
      if (!r || r.http_open == null) return `On ${s.domain}: the redirect could not be checked.`;
      if (!r.http_open) return `On ${s.domain}: plain HTTP is not offered at all, which is fine.`;
      return `On ${s.domain}: http:// ${r.redirects_to_https ? `redirects to https:// (status ${r.status})` : `does NOT redirect to https:// (status ${r.status})`}.`;
    },
  },
  {
    words: ["caa", "dnssec", "dns"],
    ids: ["CAA_MISSING"],
    explain: "CAA is a DNS record listing which certificate authorities may issue certificates for your domain. DNSSEC signs your DNS answers so they cannot be forged. Both are cheap extra protection.",
    status: (s) => {
      const d = s.dns;
      if (!d) return null;
      const caa = d.caa == null ? "could not be checked" : d.caa.present ? `present (${d.caa.issuers.join(", ") || "no issuers listed"})` : "missing";
      return `On ${s.domain}: CAA ${caa}. DNSSEC ${state(d.dnssec, "enabled", "not enabled")}.`;
    },
  },
  {
    words: ["www", "bare domain", "other address", "non-www"],
    ids: ["VARIANT_"],
    explain: "Visitors type both example.com and www.example.com, so both must have a valid certificate and redirect to HTTPS.",
    status: (s) => {
      const v = s.variant;
      if (!v) return null;
      if (v.exists === false) return `${v.host} does not exist, so there is nothing to check.`;
      if (v.exists == null) return `${v.host} could not be checked.`;
      return `${v.host}: HTTPS ${state(v.https_ok, "works", "does not work")}, certificate ${state(v.cert_valid, "valid", "rejected by browsers")}.`;
    },
  },
];

const GENERAL = [
  [["https"], "HTTPS is HTTP with encryption (TLS). It hides what visitors send and receive and proves they reached the real site. The padlock in the browser means HTTPS is in use."],
  [["mitm", "man in the middle", "man-in-the-middle"], "A man-in-the-middle attack is when someone on the same network (for example public Wi-Fi) secretly reads or changes traffic. HTTPS with a valid certificate, HSTS and modern TLS prevents it."],
  [["phishing"], "Phishing is tricking people into giving away passwords on a fake site. A valid certificate proves the domain, but always check the address itself, too."],
];

function scoreAnswer(scan) {
  const findings = [...(scan.findings || [])].sort((a, b) => (b.points_lost || 0) - (a.points_lost || 0));
  let text = `${scan.domain} scored ${scan.score} out of 100. Every site starts at 100 and loses points for each problem: critical −30, high −15, medium −8, low −3. Each area (certificate, protocols, headers, cookies...) can lose only a limited number of points, so one weakness cannot wipe out the whole score.`;
  if (!findings.length) return text + " No problems were found, so no points were lost.";
  text += "\n\nPoints lost:\n" + findings
    .map((f) => (f.points_lost === 0 ? `• 0 ${f.title} (category limit reached)` : `• −${f.points_lost ?? "?"} ${f.title}`))
    .join("\n");
  if (scan.score_cap) {
    text += `\n\nThe score is also capped at ${scan.score_cap.max_score} because of: ${scan.score_cap.title}. Some problems are so serious that the site cannot get a better grade until they are fixed.`;
  }
  return text + "\n\nThis score comes from SecureSphere's own rules, not an industry standard.";
}

function fixFirstAnswer(scan) {
  const findings = [...(scan.findings || [])].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (b.points_lost || 0) - (a.points_lost || 0));
  if (!findings.length) return `Nothing needs fixing for ${scan.domain} in this scan. Keep monitoring it so you hear about changes.`;
  const top = findings.slice(0, 3);
  let text = `Fix these first on ${scan.domain} (most serious first):\n\n` + top.map(describeFinding).join("\n\n");
  if (findings.length > 3) text += `\n\n${findings.length - 3} smaller problem(s) remain after these. Ask "list all problems" to see them.`;
  return text;
}

function summaryAnswer(scan) {
  const findings = scan.findings || [];
  const count = (sev) => findings.filter((f) => f.severity === sev).length;
  const serious = count("critical") + count("high");
  let text = `${scan.domain} scored ${scan.score}/100. The scan found ${findings.length} problem(s): ` +
    `${count("critical")} critical, ${count("high")} high, ${count("medium")} medium, ${count("low")} low.`;
  text += serious ? ` Start with the ${serious} serious one(s): ask "what should I fix first?".` : " There are no serious problems.";
  return text + "\n\nA good score means the settings we checked look right. It does not guarantee the site is safe, because SecureSphere checks configuration only.";
}

export function builtInReply(message, scan) {
  const q = ` ${message.toLowerCase()} `;
  const has = (...words) => words.some((w) => q.includes(w));

  if (/^\s*(hi|hello|hey|namaste)\b/.test(q)) {
    return "Hello! Ask me about your score, what to fix first, or any term like TLS, HSTS, CSP or cookies.";
  }
  if (has("monitor", "alert", "notify", "notification")) {
    return "Turn on \"Monitor this site\" below the results. We scan it right away, then every night, and email you (once your address is confirmed) when the certificate is close to expiry, a serious new problem appears, or the score drops.";
  }
  if (has("report", "pdf", "download")) {
    return "Click \"Download report (PDF)\" next to the score to save every check, problem and fix as a PDF.";
  }
  if (has("history", "previous", "compare", "changed", "last time")) {
    return "Open the History page and click any scan. The report shows what was fixed and what is new since the scan before it.";
  }

  if (!scan) {
    const topics = TOPICS.filter((t) => has(...t.words));
    if (topics.length) return topics.slice(0, 2).map((t) => t.explain).join("\n\n") + "\n\nScan a website and I can tell you how it does on this.";
    const general = GENERAL.find(([words]) => has(...words));
    if (general) return general[1];
    if (has("score", "grade", "fix", "safe", "secure", "result")) return "Scan a website first, then I can explain its score and what to fix.";
    return "I can explain security terms like TLS, HSTS, CSP, cookies or CAA. Scan a website and I can also explain its results and how to fix them.";
  }

  if (has("score", "grade", "points", "rating", "why low", "so low")) return scoreAnswer(scan);
  if (has("list all", "all problems", "all issues", "every problem")) {
    const all = [...(scan.findings || [])].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
    return all.length ? `All problems on ${scan.domain}:\n\n` + all.map(describeFinding).join("\n\n") : `No problems were found on ${scan.domain}.`;
  }

  // A question about a specific topic ("how do I fix HSTS?", "what is CAA?") wins over generic "fix".
  const topics = TOPICS.filter((t) => has(...t.words)).slice(0, 2);
  if (topics.length) {
    return topics.map((t) => {
      const status = t.status ? t.status(scan) : null;
      const related = findingsFor(scan, t.ids);
      let text = t.explain + (status ? `\n\n${status}` : "");
      text += related.length ? "\n\nProblem(s) found:\n" + related.map(describeFinding).join("\n\n") : "\n\nNo problem was found for this on your site.";
      return text;
    }).join("\n\n———\n\n");
  }

  if (has("fix", "first", "priority", "improve", "what should i do", "how do i", "solve", "top")) return fixFirstAnswer(scan);
  if (has("safe", "secure", "hack", "summary", "overview", "explain my", "result", "how did", "how is")) return summaryAnswer(scan);
  const general = GENERAL.find(([words]) => has(...words));
  if (general) return general[1];

  return `I can answer from your scan of ${scan.domain}. Try:\n• "Why is my score ${scan.score}?"\n• "What should I fix first?"\n• "Explain HSTS" (or TLS, ciphers, CSP, cookies, CAA, redirect, www)\n• "List all problems"`;
}

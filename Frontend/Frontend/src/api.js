import { builtInReply } from "./assistantRules";
import { mockScan, mockHistory, mockAlerts } from "./mockData";

// Talks to the real backend by default. Set VITE_USE_MOCK=true in a .env file to use fake data instead.
export const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";
export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

export function getToken() {
  try {
    return localStorage.getItem("token");
  } catch {
    return null;
  }
}
export function saveToken(token) {
  try {
    localStorage.setItem("token", token);
  } catch {
    /* storage unavailable */
  }
}
export function clearToken() {
  try {
    localStorage.removeItem("token");
  } catch {
    /* storage unavailable */
  }
}

async function request(path, options = {}) {
  const token = getToken();
  let res;
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
  } catch {
    throw new Error("Could not reach the server. Check that the backend is running.");
  }
  if (!res.ok) {
    let message = "Something went wrong on the server. Try again.";
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail) && body.detail[0]?.msg) message = body.detail[0].msg;
    } catch {
      /* keep default message */
    }
    if (res.status === 401 && token) {
      // Expired or invalid session (e.g. an old mock token): log out and go to the login page.
      clearToken();
      window.location.assign("/login");
    }
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  if (res.status === 204) return null;
  return res.json();
}

// "TLS_1_0_ENABLED" -> "TLS 1.0 enabled"
function titleFromId(id) {
  const s = id.toLowerCase().replace(/_(\d)_(\d)/g, " $1.$2").replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Converts a scan document from the backend into the shape the pages use.
export function normalizeScan(raw) {
  const c = raw.certificate || {};
  const t = raw.tls || {};
  const ci = raw.ciphers || {};
  const accepted = ci.accepted || [];
  const explanations = raw.explanations || {};
  const vulns = raw.vulnerabilities || {};
  const cap = raw.score_cap;
  return {
    id: raw.id,
    domain: raw.domain,
    scanned_at: raw.scanned_at,
    score: raw.score,
    // Set when a serious problem limited the score (e.g. expired certificate -> at most 59).
    score_cap: cap ? { max_score: cap.max_score, reason: cap.reason, title: explanations[cap.finding]?.title || titleFromId(cap.finding) } : null,
    // null means "could not test/unknown" and must stay null (never shown as "not supported").
    certificate: {
      valid: Boolean(c.trusted) && !c.expired,
      issuer: c.issuer ?? "Unknown",
      expiry_date: c.expires_at ?? "Unknown",
      days_remaining: c.days_left ?? 0,
      hostname_match: c.domain_match ?? null,
      self_signed: Boolean(c.self_signed),
      key: c.key_type ? `${c.key_type}${c.key_size ? ` ${c.key_size}-bit` : ""}` : null,
      weak_key: c.weak_key ?? null,
      signature: c.signature_hash ? c.signature_hash.toUpperCase() : null,
      weak_signature: c.weak_signature ?? null,
    },
    tls: {
      ssl_2: t.ssl2 ?? null, ssl_3: t.ssl3 ?? null,
      tls_1_0: t["1.0"] ?? null, tls_1_1: t["1.1"] ?? null, tls_1_2: t["1.2"] ?? null, tls_1_3: t["1.3"] ?? null,
    },
    cipher: {
      negotiated: ci.negotiated ?? accepted[0] ?? "Unknown",
      weak: (ci.weak || []).length > 0,
      weak_list: ci.weak || [],
      untested: ci.untested || [],
      // TLS 1.3 suites and (EC)DHE key exchange give forward secrecy.
      forward_secrecy: ci.forward_secrecy !== undefined ? ci.forward_secrecy : accepted.some((n) => /^TLS_(AES|CHACHA20)|DHE/.test(n)),
    },
    headers: raw.headers || {},
    header_details: raw.header_details || {},
    cookies: raw.cookies || [],
    redirect: raw.redirect || null,
    vulnerabilities: { heartbleed: vulns.heartbleed ?? null, ccs_injection: vulns.ccs_injection ?? null, robot: vulns.robot ?? null },
    dns: raw.dns || null,
    variant: raw.variant || null,
    cached: Boolean(raw.cached),
    untested: raw.untested || [], // checks that could not run: the score is then partial
    findings: (raw.findings || []).map((f) => {
      const e = explanations[f.id] || {};
      return {
        id: f.id,
        severity: f.severity,
        title: e.title || titleFromId(f.id),
        evidence: f.evidence,
        points_lost: f.points_lost ?? null,
        problem: e.problem || f.evidence,
        impact: e.impact || e.why_it_matters || "",
        fix: e.fix || "",
      };
    }),
    ai_explanation: "",
  };
}

// Starts a background scan and asks every second how far it is. onProgress(steps) gets the list of
// finished steps ("certificate", "protocols", ...) so the page can show progress.
export async function scanDomain(domain, onProgress = () => {}) {
  if (USE_MOCK) {
    for (const step of ["certificate", "protocols", "ciphers", "headers", "redirect", "dns", "variant", "deep"]) {
      await wait(150);
      onProgress((prev) => [...prev, step]);
    }
    return { ...mockScan, domain };
  }
  const { job_id } = await request("/scan/jobs", { method: "POST", body: JSON.stringify({ domain }) });
  for (;;) {
    await wait(1000);
    const job = await request(`/scan/jobs/${job_id}`);
    onProgress(() => job.steps);
    if (job.status === "done") return normalizeScan(job.scan);
    if (job.status === "error") throw new Error(job.error || "The scan failed.");
  }
}

// Without a domain: the user's most recent scans of every site.
export async function getHistory(domain = "") {
  if (USE_MOCK) {
    await wait(600);
    return mockHistory.map((h, i) => ({ id: `mock-${i}`, domain: domain || "github.com", source: "manual", ...h }));
  }
  return request(domain ? `/history?domain=${encodeURIComponent(domain)}` : "/history?limit=100");
}

export async function getScan(id) {
  if (USE_MOCK) {
    await wait(300);
    return { ...mockScan, id };
  }
  return normalizeScan(await request(`/scan/${encodeURIComponent(id)}`));
}

// What changed since the previous scan of the same site: { previous, score_change, new_findings, fixed_findings }
export async function compareScan(id) {
  if (USE_MOCK) return { previous: null };
  return request(`/scan/${encodeURIComponent(id)}/compare`);
}

export async function login(email, password) {
  if (USE_MOCK) {
    await wait(600);
    return { access_token: "mock-token" };
  }
  return request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export async function signup(email, password, name = "") {
  if (USE_MOCK) {
    await wait(600);
    if (name) mockProfile.name = name;
    mockProfile.email = email;
    return { access_token: "mock-token" };
  }
  return request("/auth/signup", { method: "POST", body: JSON.stringify({ name, email, password }) });
}

// ---- Forgot password ----
export async function forgotPassword(email) {
  if (USE_MOCK) {
    await wait(600);
    return { message: "If an account exists for that email, a reset link has been sent." };
  }
  return request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
}

export async function resetPassword(token, newPassword) {
  if (USE_MOCK) {
    await wait(600);
    return { message: "Your password has been changed. You can now log in." };
  }
  return request("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, new_password: newPassword }) });
}

// ---- Profile ----
let mockProfile = {
  id: "mock", name: "Demo user", email: "demo@example.com", created_at: "2026-09-01T10:00:00",
  stats: { scans: mockHistory.length, monitors: 0, unread_alerts: 2 },
  recent_scans: mockHistory.map((h, i) => ({ id: String(i), domain: "github.com", source: "manual", ...h })),
};

export async function getProfile() {
  if (USE_MOCK) {
    await wait(300);
    return { ...mockProfile };
  }
  return request("/users/me");
}

export async function updateProfile(name) {
  if (USE_MOCK) {
    await wait(300);
    mockProfile = { ...mockProfile, name };
    return { ...mockProfile };
  }
  return request("/users/me", { method: "PATCH", body: JSON.stringify({ name }) });
}

export async function changePassword(currentPassword, newPassword) {
  if (USE_MOCK) {
    await wait(300);
    return { updated: true };
  }
  const res = await request("/users/me/password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  // A password change logs out every other session; this one continues with a fresh token.
  if (res.access_token) saveToken(res.access_token);
  return res;
}

// ---- Email verification ----
export async function verifyEmail(token) {
  if (USE_MOCK) {
    await wait(300);
    return { message: "Your email address is confirmed." };
  }
  return request("/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) });
}

export async function resendVerification() {
  if (USE_MOCK) {
    await wait(300);
    return { message: "We sent a new confirmation link." };
  }
  return request("/users/me/resend-verification", { method: "POST" });
}

// ---- Monitoring and alerts ----
let mockMonitored = [];
let mockAlertList = mockAlerts.map((a) => ({ ...a }));

export async function getMonitored() {
  if (USE_MOCK) {
    await wait(300);
    return [...mockMonitored];
  }
  const list = await request("/monitor");
  return list.map((m) => ({ id: m.id, domain: m.domain, score: m.last_score, last_scanned_at: m.last_scanned_at }));
}

export async function setMonitoring(domain, on) {
  if (USE_MOCK) {
    await wait(300);
    mockMonitored = on
      ? [...mockMonitored.filter((m) => m.domain !== domain), { domain, score: mockScan.score, last_scanned_at: new Date().toISOString() }]
      : mockMonitored.filter((m) => m.domain !== domain);
    return { domain, monitored: on };
  }
  if (on) {
    try {
      await request("/monitor", { method: "POST", body: JSON.stringify({ domain }) });
    } catch (e) {
      if (e.status !== 409) throw e; // 409 = already monitored, which is what we want
    }
  } else {
    // The backend deletes by monitor id, so look it up by domain first.
    const mon = (await getMonitored()).find((m) => m.domain === domain);
    if (mon) await request(`/monitor/${mon.id}`, { method: "DELETE" });
  }
  return { domain, monitored: on };
}

export async function getAlerts() {
  if (USE_MOCK) {
    await wait(300);
    return mockAlertList.map((a) => ({ ...a }));
  }
  return request("/alerts");
}

export async function getUnreadCount() {
  if (USE_MOCK) return mockAlertList.filter((a) => !a.read).length;
  return (await request("/alerts/unread-count")).count;
}

export async function markAlertRead(id) {
  if (USE_MOCK) {
    mockAlertList = mockAlertList.map((a) => (a.id === id ? { ...a, read: true } : a));
    return { id, read: true };
  }
  return request(`/alerts/${id}/read`, { method: "PATCH" });
}

// ---- AI assistant ----
// The backend asks Claude, which answers only from the user's saved scan (sent by id, never as data).
// Without an AI key on the server (or when it is unreachable) the built-in answers in assistantRules.js
// are used instead: free, offline, and based only on the real scan.
// history: earlier turns as [{ role: "user" | "assistant", content }]. Returns { reply, ai }.
export async function askAssistant(message, scan, history = []) {
  if (!USE_MOCK && getToken()) {
    try {
      const res = await request("/assistant", {
        method: "POST",
        body: JSON.stringify({ message, scan_id: scan?.id || null, history }),
      });
      return { reply: res.reply, ai: true };
    } catch (e) {
      // 503 = AI not set up, 502 = AI service unavailable (e.g. no API credit), no status = network problem:
      // use the built-in answers. Other errors (e.g. 429 "too many questions") are shown to the user.
      if (e.status && e.status !== 502 && e.status !== 503) throw e;
    }
  }
  await wait(500);
  return { reply: builtInReply(message, scan), ai: false };
}

// Accepts example.com, sub.example.com, example.com:8443. Rejects "hello", "http://", "123".
const DOMAIN_REGEX = /^(?!-)([a-z0-9-]+\.)+[a-z]{2,}(:\d{1,5})?$/i;

export function cleanDomain(input) {
  return input.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
}
export function isValidDomain(domain) {
  return DOMAIN_REGEX.test(domain);
}
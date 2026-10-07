// Catches common email typos like "gnail.com" or "gmail.con" before an account is created.
const COMMON = [
  "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com", "live.com",
  "icloud.com", "aol.com", "protonmail.com", "proton.me", "rediffmail.com", "zoho.com",
];

function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return d[a.length][b.length];
}

// Returns the corrected address ("name@gmail.com"), or null when nothing looks wrong.
export function suggestEmail(email) {
  const at = email.lastIndexOf("@");
  if (at < 1) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  if (!domain || COMMON.includes(domain)) return null;
  let best = null;
  for (const candidate of COMMON) {
    const dist = distance(domain, candidate);
    if (dist <= 2 && (!best || dist < best.dist)) best = { candidate, dist };
  }
  return best ? `${email.slice(0, at)}@${best.candidate}` : null;
}

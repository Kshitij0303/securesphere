import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// SecureSphere follows its own advice: the website sends the security headers it checks for.
// The same headers are set for production in nginx.conf (Docker) and vercel.json.
function securityHeaders(apiUrl, withCsp) {
  const headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
  // The dev server injects an inline script for hot reloading, so the strict CSP is only used for
  // the built site (npm run build && npm run preview). Inline styles are needed by the chart library.
  if (withCsp) {
    headers["Content-Security-Policy"] =
      `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; ` +
      `connect-src 'self' ${apiUrl}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`;
  }
  return headers;
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiUrl = env.VITE_API_URL || "http://localhost:8000";
  return {
    plugins: [react(), tailwindcss()],
    server: { headers: securityHeaders(apiUrl, false) },
    preview: { headers: securityHeaders(apiUrl, true) },
  };
});

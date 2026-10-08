import { Link } from "react-router-dom";
import Icon from "../components/Icon";

const STEPS = [
  { name: "Detect", icon: "search", text: "We connect to your site and read its certificate, TLS versions, ciphers and security headers." },
  { name: "Understand", icon: "chart", text: "You get a score out of 100 and a plain-English explanation of every finding." },
  { name: "Fix", icon: "wrench", text: "Each problem comes with a clear fix you can pass to whoever runs your server." },
  { name: "Monitor", icon: "bell", text: "We rescan on a schedule and alert you when a certificate is about to expire or the score drops." },
];

const CHECKS = [
  ["cert", "Certificate", "Validity, expiry, chain, key strength, hostname"],
  ["layers", "Protocols", "SSL 2/3 and TLS 1.0 to 1.3"],
  ["key", "Ciphers", "Weak ciphers and forward secrecy"],
  ["file", "Headers", "HSTS, CSP, X-Frame-Options and more"],
  ["cookie", "Cookies", "Secure, HttpOnly and SameSite flags"],
  ["bug", "Vulnerabilities", "Heartbleed, CCS injection, ROBOT"],
  ["globe", "DNS", "CAA, DNSSEC, HSTS preload list"],
  ["link", "Redirects", "HTTP to HTTPS, www and non-www"],
];

// Static preview of a result, so visitors see what they get before signing up.
function PreviewCard() {
  const rows = [["Certificate valid", true], ["TLS 1.3 supported", true], ["HSTS header", true], ["TLS 1.0 disabled", false]];
  return (
    <div aria-hidden="true" className="card relative w-full max-w-sm rotate-1 shadow-xl">
      <div className="flex items-center gap-4">
        <div className="relative flex h-20 w-20 items-center justify-center rounded-full border-[6px] border-ok/80">
          <span className="text-2xl font-extrabold text-ok">86</span>
        </div>
        <div>
          <p className="font-mono text-sm text-subtle">example.com</p>
          <p className="text-lg font-bold text-fg">Grade B</p>
          <p className="chip mt-1 bg-warn-soft text-warn">1 Medium</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {rows.map(([label, ok]) => (
          <div key={label} className="flex items-center justify-between rounded-lg bg-surface-2 px-3 py-2 text-sm">
            <span className="text-muted">{label}</span>
            <span className={`flex h-5 w-5 items-center justify-center rounded-full ${ok ? "bg-ok-soft text-ok" : "bg-warn-soft text-warn"}`}>
              {ok ? <Icon name="check" className="h-3 w-3" strokeWidth={3} /> : <span className="text-xs font-bold">!</span>}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function LandingPage({ loggedIn }) {
  return (
    <div className="-mt-8 sm:-mt-12">
      <section className="relative py-12 sm:py-20">
        <div className="hero-grid pointer-events-none absolute inset-0 -z-10 opacity-60" />
        <div className="pointer-events-none absolute left-1/2 top-0 -z-10 h-72 w-72 -translate-x-1/2 rounded-full blur-3xl" style={{ background: "var(--glow)" }} />
        <div className="grid items-center gap-12 lg:grid-cols-[1.2fr_1fr]">
          <div className="fade-up">
            <p className="chip border border-accent/30 bg-accent-soft text-accent">
              <Icon name="shieldCheck" className="h-3.5 w-3.5" /> HTTPS &amp; TLS security scanner
            </p>
            <h1 className="mt-5 max-w-2xl text-4xl font-extrabold leading-tight tracking-tight text-fg sm:text-6xl">
              Know if your website's HTTPS setup is{" "}
              <span className="bg-gradient-to-r from-teal-500 to-cyan-500 bg-clip-text text-transparent">safe</span>.
            </h1>
            <p className="mt-5 max-w-xl text-lg text-muted">
              SecureSphere checks your certificate, TLS versions, ciphers and security headers, explains what it found,
              and keeps watching after you leave.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/scan" className="btn-primary px-6 py-3">
                <Icon name="search" className="h-4 w-4" />
                Scan a website
              </Link>
              {!loggedIn && (
                <Link to="/signup" className="btn-secondary px-6 py-3">
                  Create a free account
                </Link>
              )}
            </div>
            <p className="mt-6 flex flex-wrap gap-x-5 gap-y-2 text-sm text-subtle">
              <span className="flex items-center gap-1.5"><Icon name="check" className="h-4 w-4 text-ok" /> 30+ checks per scan</span>
              <span className="flex items-center gap-1.5"><Icon name="check" className="h-4 w-4 text-ok" /> PDF reports</span>
              <span className="flex items-center gap-1.5"><Icon name="check" className="h-4 w-4 text-ok" /> Nightly monitoring</span>
            </p>
          </div>
          <div className="flex justify-center lg:justify-end">
            <PreviewCard />
          </div>
        </div>
      </section>

      <section className="mt-4">
        <h2 className="text-2xl font-bold tracking-tight text-fg">What we check</h2>
        <ul className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {CHECKS.map(([icon, name, text]) => (
            <li key={name} className="card p-4 transition-colors hover:border-accent/50 sm:p-5">
              <Icon name={icon} className="h-5 w-5 text-accent" />
              <h3 className="mt-3 font-semibold text-fg">{name}</h3>
              <p className="mt-1 text-sm text-muted">{text}</p>
            </li>
          ))}
        </ul>
      </section>

      <section className="mt-16">
        <h2 className="text-2xl font-bold tracking-tight text-fg">How it works</h2>
        <ol className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((s, i) => (
            <li key={s.name} className="card relative">
              <span className="absolute right-5 top-4 font-mono text-3xl font-bold text-line">0{i + 1}</span>
              <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-soft text-accent">
                <Icon name={s.icon} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 font-semibold text-fg">{i + 1}. {s.name}</h3>
              <p className="mt-1 text-sm text-muted">{s.text}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="card mt-16 flex flex-col items-start justify-between gap-6 bg-gradient-to-br from-teal-600 to-cyan-800 text-white sm:flex-row sm:items-center">
        <div>
          <h2 className="text-2xl font-bold">Check your site in under a minute.</h2>
          <p className="mt-1 text-white/80">
            SecureSphere analyses configuration. It is not a penetration-testing tool, it does not fix servers,
            and a high score is not a guarantee of security.
          </p>
        </div>
        <Link to={loggedIn ? "/scan" : "/signup"} className="btn shrink-0 bg-white text-teal-800 hover:bg-white/90">
          Get started <Icon name="arrowRight" className="h-4 w-4" />
        </Link>
      </section>
    </div>
  );
}

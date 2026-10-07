import { Link } from "react-router-dom";

const STEPS = [
  { name: "Detect", text: "We connect to your site and read its certificate, TLS versions, ciphers and security headers." },
  { name: "Understand", text: "You get a score out of 100 and a plain-English explanation of every finding." },
  { name: "Fix", text: "Each problem comes with a clear fix you can pass to whoever runs your server." },
  { name: "Monitor", text: "We rescan on a schedule and alert you when a certificate is about to expire or the score drops." },
];

export default function LandingPage({ loggedIn }) {
  return (
    <div>
      <section className="py-8">
        <h1 className="max-w-2xl text-4xl font-bold leading-tight sm:text-5xl">
          Know if your website's HTTPS setup is safe.
        </h1>
        <p className="mt-4 max-w-xl text-lg text-slate-600">
          SecureSphere checks your certificate, TLS versions, ciphers and security headers, explains what it found,
          and keeps watching after you leave.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link to="/scan" className="rounded-md bg-teal-700 px-6 py-3 font-semibold text-white hover:bg-teal-800">
            Scan a website
          </Link>
          {!loggedIn && (
            <Link to="/signup" className="rounded-md border border-slate-300 bg-white px-6 py-3 font-semibold hover:bg-slate-100">
              Create a free account
            </Link>
          )}
        </div>
      </section>

      <section className="mt-12">
        <h2 className="text-2xl font-semibold">How it works</h2>
        <ol className="mt-6 grid gap-4 sm:grid-cols-2">
          {STEPS.map((s, i) => (
            <li key={s.name} className="rounded-lg border border-slate-200 bg-white p-5">
              <h3 className="font-semibold">{i + 1}. {s.name}</h3>
              <p className="mt-1 text-slate-600">{s.text}</p>
            </li>
          ))}
        </ol>
      </section>

      <p className="mt-10 max-w-2xl text-sm text-slate-500">
        SecureSphere analyses configuration. It is not a penetration-testing tool, it does not fix servers,
        and a high score is not a guarantee of security.
      </p>
    </div>
  );
}
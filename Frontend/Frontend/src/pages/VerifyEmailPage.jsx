import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { verifyEmail } from "../api";
import ErrorBox from "../components/ErrorBox";

// Opened from the link in the confirmation email: /verify-email?token=...
export default function VerifyEmailPage({ onVerified }) {
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const [state, setState] = useState(token ? "checking" : "missing");
  const [error, setError] = useState("");
  const sent = useRef(false); // the link works once, so never send it twice (React StrictMode runs effects twice)

  useEffect(() => {
    if (!token || sent.current) return;
    sent.current = true;
    verifyEmail(token)
      .then(() => {
        setState("done");
        onVerified();
      })
      .catch((e) => {
        setError(e.message);
        setState("error");
      });
  }, [token, onVerified]);

  return (
    <div className="max-w-md">
      <h1 className="text-3xl font-bold">Confirm your email</h1>
      {state === "checking" && <p className="mt-4 text-slate-600">Confirming…</p>}
      {state === "missing" && <p className="mt-4 text-slate-600">Open the link from the email we sent you.</p>}
      {state === "done" && (
        <div role="status" className="mt-6 rounded-md border border-teal-200 bg-teal-50 px-4 py-3 text-slate-800">
          <p>Your email address is confirmed. You will now receive security alerts by email.</p>
          <Link to="/scan" className="mt-2 inline-block font-medium text-teal-700 underline">Go to SecureSphere</Link>
        </div>
      )}
      {state === "error" && (
        <>
          <ErrorBox message={error} />
          <p className="mt-3 text-slate-600">
            You can ask for a new link on your <Link to="/profile" className="font-medium text-teal-700 underline">profile page</Link>.
          </p>
        </>
      )}
    </div>
  );
}

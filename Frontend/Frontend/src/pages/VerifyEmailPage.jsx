import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { verifyEmail } from "../api";
import AuthCard from "../components/AuthCard";
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
    <AuthCard icon="mail" title="Confirm your email">
      {state === "checking" && <p className="mt-4 text-muted">Confirming…</p>}
      {state === "missing" && <p className="mt-4 text-muted">Open the link from the email we sent you.</p>}
      {state === "done" && (
        <div role="status" className="notice mt-6 border-ok/30 bg-ok-soft text-base text-fg">
          <p>Your email address is confirmed. You will now receive security alerts by email.</p>
          <Link to="/scan" className="link mt-2 inline-block">Go to SecureSphere</Link>
        </div>
      )}
      {state === "error" && (
        <>
          <ErrorBox message={error} />
          <p className="mt-3 text-muted">
            You can ask for a new link on your <Link to="/profile" className="link">profile page</Link>.
          </p>
        </>
      )}
    </AuthCard>
  );
}

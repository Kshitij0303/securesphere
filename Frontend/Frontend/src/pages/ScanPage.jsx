import { useState } from "react";
import { scanDomain } from "../api";
import { useScan } from "../ScanContext";
import DomainForm from "../components/DomainForm";
import ErrorBox from "../components/ErrorBox";
import ScanProgress from "../components/ScanProgress";
import ScanResults from "../components/ScanResults";

export default function ScanPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);
  const [domain, setDomain] = useState("");
  const [steps, setSteps] = useState([]);
  const { setLastScan } = useScan();

  async function handleScan(d) {
    setError("");
    setData(null);
    setDomain(d);
    setSteps([]);
    setLoading(true);
    try {
      const result = await scanDomain(d, setSteps);
      setData(result);
      setLastScan(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <h1 className="text-3xl font-bold">Check a website's HTTPS security</h1>
      <p className="mt-2 max-w-xl text-slate-600">
        Enter a domain to see its certificate, TLS versions, ciphers, security headers and more.
      </p>
      <p className="mt-1 max-w-xl text-sm text-slate-500">
        Only scan websites you own or have permission to test.
      </p>
      <DomainForm
        buttonText="Scan website"
        loadingText="Scanning…"
        loading={loading}
        onSubmit={handleScan}
        onInvalid={(msg) => { setData(null); setError(msg); }}
      />
      <ErrorBox message={error} />
      {loading && <ScanProgress domain={domain} steps={steps} />}
      {data && <ScanResults data={data} />}
    </>
  );
}

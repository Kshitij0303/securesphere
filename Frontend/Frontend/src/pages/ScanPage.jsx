import { useState } from "react";
import { scanDomain } from "../api";
import { useScan } from "../ScanContext";
import DomainForm from "../components/DomainForm";
import ErrorBox from "../components/ErrorBox";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";
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
      <PageHeader icon="search" title="Check a website's HTTPS security">
        Enter a domain to see its certificate, TLS versions, ciphers, security headers and more.
      </PageHeader>
      <DomainForm
        buttonText="Scan website"
        loadingText="Scanning…"
        loading={loading}
        onSubmit={handleScan}
        onInvalid={(msg) => { setData(null); setError(msg); }}
      />
      <p className="mt-3 flex items-center gap-1.5 text-xs text-subtle">
        <Icon name="alert" className="h-3.5 w-3.5" />
        Only scan websites you own or have permission to test.
      </p>
      <ErrorBox message={error} />
      {loading && <ScanProgress domain={domain} steps={steps} />}
      {data && <ScanResults data={data} />}
    </>
  );
}

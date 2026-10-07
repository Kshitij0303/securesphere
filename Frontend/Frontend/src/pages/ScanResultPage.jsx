import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { compareScan, getScan } from "../api";
import { useScan } from "../ScanContext";
import ErrorBox from "../components/ErrorBox";
import ScanResults from "../components/ScanResults";

// A saved scan opened from the History page: /scans/:id
export default function ScanResultPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [compare, setCompare] = useState(null);
  const [error, setError] = useState("");
  const { setLastScan } = useScan();

  useEffect(() => {
    let active = true;
    setData(null);
    setCompare(null);
    setError("");
    getScan(id)
      .then((scan) => {
        if (!active) return;
        setData(scan);
        setLastScan(scan); // the assistant can now answer questions about this scan
      })
      .catch((e) => active && setError(e.message));
    compareScan(id).then((c) => active && setCompare(c)).catch(() => {});
    return () => { active = false; };
  }, [id, setLastScan]);

  return (
    <>
      <Link to="/history" className="text-sm font-medium text-teal-700 underline">← Back to history</Link>
      <ErrorBox message={error} />
      {!data && !error && <p className="mt-6 text-slate-600">Loading…</p>}
      {data && <ScanResults data={data} compare={compare} />}
    </>
  );
}

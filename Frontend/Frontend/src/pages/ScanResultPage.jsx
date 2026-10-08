import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { compareScan, getScan } from "../api";
import { useScan } from "../ScanContext";
import Icon from "../components/Icon";
import ErrorBox from "../components/ErrorBox";
import ScanResults from "../components/ScanResults";

function ResultSkeleton() {
  return (
    <div className="mt-8 space-y-6" aria-label="Loading">
      <div className="card h-56 animate-pulse" />
      <div className="grid gap-6 md:grid-cols-2">
        {[0, 1, 2, 3].map((i) => <div key={i} className="card h-48 animate-pulse" />)}
      </div>
    </div>
  );
}

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
      <Link to="/history" className="btn-ghost -ml-3 text-sm">
        <Icon name="arrowLeft" className="h-4 w-4" /> Back to history
      </Link>
      <ErrorBox message={error} />
      {!data && !error && <ResultSkeleton />}
      {data && <ScanResults data={data} compare={compare} />}
    </>
  );
}

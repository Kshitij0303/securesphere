"""Scan every domain in a CSV with the real scanner and write one summary CSV.

    cd E:\\securesphere
    backend\\venv\\Scripts\\activate
    python validation\\run_dataset.py validation\\dataset.csv validation\\my_results.csv

The input CSV needs a "domain" column (domain or domain:port) and may have "category" and
"expected_result". Sites are scanned 3 at a time, each in its own process with a 120-second limit.
Only scan sites you own, test sites (badssl.com) or large public sites; each scan is one light check,
like SSL Labs runs."""
import csv
import json
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Runs inside a child process: one scan, result written as JSON.
CHILD = r'''
import json, os, sys
sys.path.insert(0, sys.argv[3])
from scanner import run_scan
target, out = sys.argv[1], sys.argv[2]
host, _, port = target.partition(":")
try:
    try:
        result = {"ok": True, **run_scan(host, port=int(port or 443))}
    except ValueError:  # like the website: a bare name without an address falls back to www
        if host.startswith("www."):
            raise
        result = {"ok": True, "scanned_as": "www." + host, **run_scan("www." + host, port=int(port or 443))}
except Exception as e:
    result = {"ok": False, "error_type": type(e).__name__, "error": str(e)[:300]}
open(out, "w").write(json.dumps(result, default=str))
os._exit(0)
'''


def scan(target: str, workdir: Path) -> dict:
    out = workdir / (target.replace(":", "_") + ".json")
    try:
        subprocess.run([sys.executable, "-c", CHILD, target, str(out), str(ROOT)], timeout=120, capture_output=True)
        return json.loads(out.read_text())
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return {"ok": False, "error_type": "Timeout", "error": "scan exceeded 120 seconds"}


def main(src: str, dst: str) -> None:
    rows = list(csv.DictReader(open(src, encoding="utf-8")))
    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda r: scan(r["domain"], Path(tmp)), rows))
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["domain", "category", "expected", "score", "grade", "findings", "checks_that_could_not_run", "error"])
        for row, r in zip(rows, results):
            w.writerow([row["domain"], row.get("category", ""), row.get("expected_result", ""),
                        r.get("score", ""), r.get("grade", ""),
                        " ".join(f["id"] for f in r.get("findings", [])),
                        "; ".join(r.get("untested") or []), "" if r["ok"] else f"{r['error_type']}: {r['error']}"])
    print(f"Scanned {len(rows)} sites -> {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python validation/run_dataset.py <input.csv> <output.csv>")
    main(sys.argv[1], sys.argv[2])

"""Module 6: The single doorway to Part 1.
The backend only ever calls run_scan(domain) and explain_findings(findings).
  run_scan(domain)          -> dict with certificate, tls, ciphers, headers, findings, score, grade
  explain_findings(list)    -> dict keyed by finding id, each with problem/why_it_matters/impact/fix
Each finding is {"id", "severity" (low|medium|high|critical), "evidence"}."""
import os
import sys
from pathlib import Path

if os.getenv("USE_MOCK_SCANNER", "false").lower() == "true":
    from app.mock_scanner import explain_findings, run_scan  # noqa: F401
else:
    sys.path.append(str(Path(__file__).resolve().parents[2]))  # repo root, where scanner/ lives
    from scanner import explain_findings, run_scan  # noqa: F401

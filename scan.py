"""Command-line test for the scanner:  python scan.py github.com"""
import json
import os
import sys

from scanner import explain_findings, run_scan

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan.py <domain>")
        sys.exit(1)
    result = run_scan(sys.argv[1])
    result["explanations"] = explain_findings(result["findings"])
    print(json.dumps(result, indent=2, default=str), flush=True)
    # sslyze may still be finishing a check that ran past the time limit; do not wait for it.
    os._exit(0)

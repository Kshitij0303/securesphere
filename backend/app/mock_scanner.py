"""Stand-in for the Part 1 scanner so the backend can be built in parallel.
Returns fixed, clearly fake data. Used only when USE_MOCK_SCANNER=true."""


def run_scan(domain: str, ip: str | None = None, progress=None) -> dict:
    return {
        "certificate": {"issuer": "Mock CA", "expires_at": "2027-01-01", "days_left": 90,
                        "domain_match": True, "trusted": True},
        "tls": {"1.0": True, "1.1": False, "1.2": True, "1.3": True},
        "ciphers": {"accepted": ["TLS_AES_256_GCM_SHA384"], "weak": []},
        "headers": {"hsts": False, "csp": True, "x_frame_options": True,
                    "x_content_type_options": True, "referrer_policy": True},
        "findings": [
            {"id": "TLS_1_0_ENABLED", "severity": "high", "evidence": "Server accepts TLS 1.0"},
            {"id": "HSTS_MISSING", "severity": "medium", "evidence": "Strict-Transport-Security header absent"},
        ],
        "score": 72,
        "grade": "Fair",
    }


def explain_findings(findings: list[dict]) -> dict:
    return {
        f["id"]: {
            "problem": f"Mock explanation for {f['id']}",
            "why_it_matters": "Placeholder text.",
            "impact": "Placeholder text.",
            "fix": "Placeholder text.",
        }
        for f in findings
    }

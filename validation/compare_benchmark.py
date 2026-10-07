"""Compares SecureSphere's scan results with the independent curl/openssl observations.

    python validation/compare_benchmark.py <scan results folder> validation/independent.jsonl

<scan results folder> holds one JSON per site (as written by the benchmark runner: {"ok": ..., <run_scan result>}).
For every check where BOTH sides have an answer, the answers must match. "Could not test" on either side is
counted separately: it is never an agreement or a disagreement."""
import json
import sys
from collections import Counter
from pathlib import Path

results_dir, independent_file = Path(sys.argv[1]), Path(sys.argv[2])
independent = {json.loads(line)["target"]: json.loads(line) for line in independent_file.read_text().splitlines() if line.strip()}

# OpenSSL verify codes: 0 ok, 10 expired, 18 self-signed, 19 self-signed in chain, 20/21 issuer missing, 62 hostname mismatch
SERIOUS = ("CERT_EXPIRED", "CERT_HOSTNAME_MISMATCH", "CERT_SELF_SIGNED", "CERT_UNTRUSTED", "NO_MODERN_TLS",
           "SSL_2_ENABLED", "SSL_3_ENABLED", "HEARTBLEED", "WEAK_CIPHERS")
BLOCKED = {"202", "401", "403", "429", "503", ""}


def observed(ind: dict) -> dict:
    """What curl/openssl saw, in SecureSphere's terms. None = could not observe."""
    code = (ind.get("verify") or "|").split("|")[0]
    tls = {k: ind[f"tls1_{k[-1]}"] for k in ("1.0", "1.1", "1.2", "1.3")}
    if not any(tls.values()):
        tls = dict.fromkeys(tls)  # openssl could not talk to it at all (e.g. RC4 only): unknown, not "off"
    blocked = ind.get("https_status", "") in BLOCKED
    status, _, location = (ind.get("http") or "000 ").partition(" ")
    if status == "000":
        redirect = None  # plain HTTP not offered
    elif status in BLOCKED:
        redirect = None
    else:
        redirect = status.startswith("3") and location.startswith("https://")
    return {
        "trusted": None if code == "" else code == "0",
        "expired": None if code == "" else code == "10",
        "hostname_mismatch": None if code == "" else code == "62",
        "tls": tls,
        "headers": None if blocked else {k: ind[k] for k in ("hsts", "csp", "xfo", "xcto", "referrer")},
        "redirect": redirect,
    }


def secure_sphere(r: dict) -> dict:
    c, h = r["certificate"], r["headers"]
    return {
        "trusted": c["trusted"] and c.get("error") != "chain_incomplete",  # openssl has no AIA: same rule as Firefox
        "expired": c["expired"],
        "hostname_mismatch": c["domain_match"] is False,
        "tls": {k: r["tls"].get(k) for k in ("1.0", "1.1", "1.2", "1.3")},
        "headers": {"hsts": h.get("hsts"), "csp": h.get("csp"),  # an enforced CSP; report-only does not count
                    "xfo": h.get("x_frame_options"), "xcto": h.get("x_content_type_options"), "referrer": h.get("referrer_policy")},
        "redirect": r["redirect"].get("redirects_to_https") if r["redirect"].get("http_open") else None,
    }


tally, disagreements, rows = Counter(), [], []
for path in sorted(results_dir.glob("*.json")):
    target = path.stem.replace("_", ":")
    r, ind = json.loads(path.read_text()), independent.get(target)
    if not ind:
        continue
    if not r["ok"]:
        rows.append((target, f"scan error: {r['error'][:60]}", ind.get("verify", "")))
        tally["scan errors"] += 1
        continue
    o, s = observed(ind), secure_sphere(r)
    pairs = [("certificate trusted", o["trusted"], s["trusted"]), ("certificate expired", o["expired"], s["expired"]),
             ("hostname mismatch", o["hostname_mismatch"], s["hostname_mismatch"]), ("HTTP->HTTPS redirect", o["redirect"], s["redirect"])]
    pairs += [(f"TLS {v}", o["tls"][v], s["tls"][v]) for v in ("1.0", "1.1", "1.2", "1.3")]
    if o["headers"] is not None:
        pairs += [(f"header {k}", o["headers"][k], s["headers"][k]) for k in o["headers"]]
    for name, theirs, ours in pairs:
        if theirs is None or ours is None:
            tally["could not compare"] += 1
        elif bool(theirs) == bool(ours):
            tally["agree"] += 1
        else:
            tally["disagree"] += 1
            disagreements.append(f"{target}: {name}: curl/openssl={theirs} SecureSphere={ours}")
    serious = [f["id"] for f in r["findings"] if f["id"] in SERIOUS]
    rows.append((target, f"{r['score']} {r['grade']}", ", ".join(serious) or "-"))

compared = tally["agree"] + tally["disagree"]
print(f"Checks compared: {compared}, agree {tally['agree']}, disagree {tally['disagree']} "
      f"({100 * tally['agree'] / max(compared, 1):.1f}% agreement); could not compare: {tally['could not compare']}; "
      f"scan errors: {tally['scan errors']}")
print("\nDisagreements:")
print("\n".join(disagreements) or "none")
print("\nPer site (score, serious findings):")
for row in rows:
    print(" | ".join(row))

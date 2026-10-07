"""Accuracy tests against sites whose problems are known in advance.

badssl.com is run by Chrome's security engineers; each subdomain is broken in exactly one way, so the
correct answer is known before scanning. These tests use the internet and take a few minutes, so they
only run when asked:

    PowerShell:  $env:RUN_NETWORK_TESTS="1"; pytest tests/test_scanner_accuracy.py -v
    Bash:        RUN_NETWORK_TESTS=1 pytest tests/test_scanner_accuracy.py -v
"""
import os

import pytest

from scanner import run_scan
from scanner.cert import check_certificate
from scanner.deep_tls import deep_scan
from scanner.redirect import check_https_redirect
from scanner.tls_check import check_tls_versions

pytestmark = pytest.mark.skipif(os.getenv("RUN_NETWORK_TESTS") != "1", reason="set RUN_NETWORK_TESTS=1 to run")


@pytest.mark.parametrize("host, field, expected", [
    ("expired.badssl.com", "expired", True),
    ("wrong.host.badssl.com", "domain_match", False),
    ("self-signed.badssl.com", "error", "self_signed"),
    ("untrusted-root.badssl.com", "error", "untrusted_root"),
    ("sha256.badssl.com", "trusted", True),
])
def test_certificate_problems(host, field, expected):
    assert check_certificate(host)[field] == expected


def test_expired_certificate_still_checks_domain_by_hand():
    assert check_certificate("expired.badssl.com")["domain_match"] is True


@pytest.mark.parametrize("host, port, version", [
    ("tls-v1-0.badssl.com", 1010, "tls1_0"),
    ("tls-v1-1.badssl.com", 1011, "tls1_1"),
    ("tls-v1-2.badssl.com", 1012, "tls1_2"),
])
def test_tls_versions(host, port, version):
    result = check_tls_versions(host, port)
    if result[version] is None:
        pytest.skip(f"this computer's OpenSSL cannot test {version}")  # never count "could not test" as a pass
    assert result[version] is True


def test_rc4_is_reported_as_weak():
    result = deep_scan("rc4.badssl.com")
    if result is None:
        pytest.skip("sslyze is not installed or could not run")
    assert any("RC4" in name for name in result["weak"])


def test_http_site_without_redirect():
    result = check_https_redirect("http.badssl.com")
    assert result["http_open"] is True and result["redirects_to_https"] is False


def test_well_configured_site_scores_well():
    result = run_scan("github.com")
    assert result["certificate"]["trusted"] is True
    assert result["tls"]["1.0"] is False and result["tls"]["1.3"] is True
    assert result["redirect"]["redirects_to_https"] is True
    assert result["score"] >= 90



def test_tls_1_0_only_server_can_be_scanned():
    """Found by the dataset run: servers that speak only TLS 1.0 used to crash the scan."""
    result = run_scan("tls-v1-0.badssl.com", port=1010)
    assert result["certificate"]["legacy_only"] is True
    assert result["tls"]["1.0"] is True


def test_sha1_intermediate_is_detected():
    """Found by the dataset run: SHA-1 in an intermediate certificate was missed."""
    assert "intermediate certificate" in check_certificate("sha1-intermediate.badssl.com")["weak_signature_in"]

"""Deep TLS scan with sslyze.

sslyze ships its own OpenSSL build (nassl) that still contains SSL 2/3, RC4, 3DES, EXPORT and NULL ciphers,
so it can test what this computer's Python OpenSSL no longer can. It also runs non-intrusive checks for
Heartbleed, OpenSSL CCS injection and ROBOT.

deep_scan() returns None if sslyze is not installed or the scan could not run; the caller then falls back
to tls_check.py and ciphers.py."""
import logging

log = logging.getLogger("securesphere.scanner")

try:
    from sslyze import (ScanCommand, ScanCommandAttemptStatusEnum, Scanner,
                        ServerNetworkConfiguration, ServerNetworkLocation, ServerScanRequest, ServerScanStatusEnum)
except ImportError:  # sslyze is optional
    Scanner = None

# result key -> (scan command, attribute on the scan result)
VERSIONS = {
    "ssl2": ("SSL_2_0_CIPHER_SUITES", "ssl_2_0_cipher_suites"),
    "ssl3": ("SSL_3_0_CIPHER_SUITES", "ssl_3_0_cipher_suites"),
    "1.0": ("TLS_1_0_CIPHER_SUITES", "tls_1_0_cipher_suites"),
    "1.1": ("TLS_1_1_CIPHER_SUITES", "tls_1_1_cipher_suites"),
    "1.2": ("TLS_1_2_CIPHER_SUITES", "tls_1_2_cipher_suites"),
    "1.3": ("TLS_1_3_CIPHER_SUITES", "tls_1_3_cipher_suites"),
}
WEAK_MARKERS = ("RC4", "3DES", "_DES_", "DES40", "DES_CBC_", "NULL", "EXPORT", "_anon_", "IDEA", "MD5")


def _is_weak(suite) -> bool:
    name = suite.name
    return suite.is_anonymous or suite.key_size < 128 or any(m in name for m in WEAK_MARKERS)


def _attempt_result(attempt):
    if attempt is None or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
        return None
    return attempt.result


def deep_scan(host: str, port: int = 443, ip: str | None = None) -> dict | None:
    if Scanner is None:
        return None
    commands = {getattr(ScanCommand, cmd) for cmd, _ in VERSIONS.values()}
    commands |= {ScanCommand.HEARTBLEED, ScanCommand.OPENSSL_CCS_INJECTION, ScanCommand.ROBOT}
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=host, port=port, ip_address=ip),
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication=host,
                                                         network_timeout=5, network_max_retries=1),
        scan_commands=commands,
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    result = next(iter(scanner.get_results()), None)
    if result is None or result.scan_status != ServerScanStatusEnum.COMPLETED:
        log.warning("sslyze could not scan %s: %s", host, result and result.connectivity_error_trace)
        return None
    sr = result.scan_result

    versions, accepted, weak = {}, [], []
    for key, (_, attr) in VERSIONS.items():
        res = _attempt_result(getattr(sr, attr))
        versions[key] = res.is_tls_version_supported if res else None
        for c in (res.accepted_cipher_suites if res else []):
            name = c.cipher_suite.name
            if name not in accepted:
                accepted.append(name)
            if _is_weak(c.cipher_suite) and name not in weak:
                weak.append(name)

    heartbleed = _attempt_result(sr.heartbleed)
    ccs = _attempt_result(sr.openssl_ccs_injection)
    robot = _attempt_result(sr.robot)
    robot_state = robot.robot_result.name if robot else ""
    return {
        "versions": versions,
        "accepted": accepted,
        "weak": weak,
        "vulnerabilities": {
            "heartbleed": heartbleed.is_vulnerable_to_heartbleed if heartbleed else None,
            "ccs_injection": ccs.is_vulnerable_to_ccs_injection if ccs else None,
            # UNKNOWN_INCONSISTENT_RESULTS stays None (could not tell)
            "robot": True if robot_state.startswith("VULNERABLE") else False if robot_state.startswith("NOT_VULNERABLE") else None,
        },
    }

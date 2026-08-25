"""Tests for the SaferPickle CLI helpers."""

import io
import zipfile

import cli


def test_benign_pickle_is_benign(benign_bytes):
    result = cli.security_scan_with_justifications(benign_bytes)
    assert result["classification"] == "benign"


def test_malicious_pickle_is_unsafe(malicious_system_bytes):
    result = cli.security_scan_with_justifications(malicious_system_bytes)
    assert result["classification"] == "unsafe"


def test_zip_scans_all_members_not_just_first(benign_bytes, malicious_system_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.pkl", benign_bytes)
        zf.writestr("b.pkl", malicious_system_bytes)
    result = cli.security_scan_with_justifications(buf.getvalue())
    assert result["classification"] == "unsafe"

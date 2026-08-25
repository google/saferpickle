"""Tests for classification and archive scanning in saferpickle."""

import bz2
import gzip
import io
import lzma
import zipfile

import saferpickle


def test_benign_is_clean(benign_bytes):
    result = saferpickle.security_scan(benign_bytes)
    assert result["unsafe"] == 0


def test_malicious_system_is_unsafe(malicious_system_bytes):
    assert saferpickle.security_scan(malicious_system_bytes)["unsafe"] > 0


def test_malicious_eval_is_unsafe(malicious_eval_bytes):
    assert saferpickle.security_scan(malicious_eval_bytes)["unsafe"] > 0


def test_strict_security_scan(benign_bytes, malicious_system_bytes):
    assert saferpickle.strict_security_scan(benign_bytes) is False
    assert saferpickle.strict_security_scan(malicious_system_bytes) is True


def test_zip_slip_detection():
    assert saferpickle._is_unsafe_archive_member("../evil")
    assert saferpickle._is_unsafe_archive_member("..\\evil")
    assert saferpickle._is_unsafe_archive_member("/absolute/path")
    assert saferpickle._is_unsafe_archive_member("C:\\evil")
    assert saferpickle._is_unsafe_archive_member("\\\\unc\\path")
    assert not saferpickle._is_unsafe_archive_member("normal.txt")
    assert not saferpickle._is_unsafe_archive_member("foo..bar")


def test_compressed_archives_scan_inside(malicious_system_bytes):
    for compress in (gzip.compress, bz2.compress, lzma.compress):
        result = saferpickle.security_scan(compress(malicious_system_bytes))
        assert result["unsafe"] > 0


def test_zip_archive_detects_malicious_member(benign_bytes, malicious_system_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("safe.pkl", benign_bytes)
        zf.writestr("evil.pkl", malicious_system_bytes)
    assert saferpickle.security_scan(buf.getvalue())["unsafe"] > 0


def test_zip_slip_member_detected(benign_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.pkl", benign_bytes)
    assert saferpickle.security_scan(buf.getvalue())["unsafe"] > 0

"""Tests for load(), loads(), Unpickler, and pickle hooking."""

import io
import pickle

import pytest

import saferpickle


def test_loads_roundtrip(benign_bytes, benign_obj):
    assert saferpickle.loads(benign_bytes) == benign_obj


def test_load_roundtrip(benign_bytes, benign_obj):
    assert saferpickle.load(io.BytesIO(benign_bytes)) == benign_obj


def test_loads_raises_on_malicious(malicious_system_bytes):
    with pytest.raises(saferpickle.UnsafePickleDetectedError):
        saferpickle.loads(malicious_system_bytes)


def test_load_raises_on_malicious(malicious_system_bytes):
    with pytest.raises(saferpickle.UnsafePickleDetectedError):
        saferpickle.load(io.BytesIO(malicious_system_bytes))


def test_loads_allow_unsafe(malicious_eval_bytes):
    assert saferpickle.loads(malicious_eval_bytes, allow_unsafe=True) == 42


def test_loads_strict_check(malicious_system_bytes):
    with pytest.raises(saferpickle.StrictCheckError):
        saferpickle.loads(malicious_system_bytes, strict_check=True)


def test_loads_illegal_combo(benign_bytes):
    with pytest.raises(saferpickle.IllegalArgumentCombinationError):
        saferpickle.loads(benign_bytes, allow_unsafe=True, strict_check=True)


def test_loads_report_only_returns_object(benign_bytes, benign_obj):
    assert saferpickle.loads(benign_bytes, report_only=True) == benign_obj


def test_unpickler(benign_bytes, benign_obj, malicious_system_bytes):
    assert saferpickle.Unpickler(io.BytesIO(benign_bytes)).load() == benign_obj
    with pytest.raises(saferpickle.UnsafePickleDetectedError):
        saferpickle.Unpickler(io.BytesIO(malicious_system_bytes)).load()


def test_hook_and_unhook(benign_bytes, benign_obj, malicious_system_bytes):
    saferpickle.hook_pickle()
    try:
        assert pickle.loads(benign_bytes) == benign_obj
        with pytest.raises(saferpickle.UnsafePickleDetectedError):
            pickle.loads(malicious_system_bytes)
    finally:
        saferpickle.unhook_pickle()


def test_unhook_restores_pickle(benign_bytes, benign_obj, malicious_system_bytes):
    saferpickle.hook_pickle()
    saferpickle.unhook_pickle()
    # After unhooking, plain pickle no longer raises.
    assert pickle.loads(benign_bytes) == benign_obj

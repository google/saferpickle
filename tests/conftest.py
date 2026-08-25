"""Shared fixtures for the SaferPickle test suite."""

import os
import pickle

import pytest


class _SystemExploit:
    def __reduce__(self):
        return (os.system, ("echo saferpickle_test",))


class _EvalExploit:
    def __reduce__(self):
        return (eval, ("40 + 2",))


@pytest.fixture(scope="session")
def benign_bytes():
    return pickle.dumps({"a": [1, 2, 3], "b": "hello"})


@pytest.fixture(scope="session")
def benign_obj():
    return {"a": [1, 2, 3], "b": "hello"}


@pytest.fixture(scope="session")
def malicious_system_bytes():
    return pickle.dumps(_SystemExploit())


@pytest.fixture(scope="session")
def malicious_eval_bytes():
    return pickle.dumps(_EvalExploit())

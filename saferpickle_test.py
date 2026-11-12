# Must be imported after safer_pickle. Violates g-bad-import-order
# pylint: disable=g-bad-import-order
import saferpickle as safer_pickle
import cli as safer_pickle_cli
from lib import config
from absl.testing import absltest as googletest
from absl.testing import parameterized

# Some of these imports are used for mocking and are not used directly.
# pylint: disable=unused-import
import io
import json
import pathlib
import pickle
import unittest
import cloudpickle
import torch
import dill
import joblib
import threading
import time

# Imports used in COMMAND_EXECUTION_TARGETS for mocking
import bdb
import encodings.raw_unicode_escape
import posix
import pty
import runpy
import subprocess
import timeit

# pylint: enable=unused-import
import collections
import concurrent.futures
import contextlib
import copyreg
import fractions
import functools
import gzip
from unittest import mock
import sys
import os
import tarfile
import zipfile
from absl import logging
from absl import flags

import _pickle
# pylint: enable=g-bad-import-order
# pylint: disable=g-unsafe-pickle-load


COMMAND_EXECUTION_TARGETS = (
    'posix.system',
    'os.system',
    'builtins.exec',
    'builtins.eval',
    'subprocess.run',
    'subprocess.Popen',
    'subprocess.call',
    'subprocess.check_call',
    'subprocess.check_output',
    'pty.spawn',
    'runpy._run_code',
    'timeit.timeit',
    'bdb.Bdb.run',
)

# To avoid creating __pycache__ files
sys.dont_write_bytecode: bool = True


def make_security_scan_wrapper(fail_fast_val):
  original_security_scan = safer_pickle.security_scan

  def wrapped_security_scan(
      pickle_bytes,
      force_scan=False,
      recursion_depth=0,
      fail_fast=None,
      **kwargs,
  ):
    if fail_fast is None:
      fail_fast = fail_fast_val
    return original_security_scan(
        pickle_bytes, force_scan, recursion_depth, fail_fast, **kwargs
    )

  return wrapped_security_scan


def make_genops_scan_wrapper(fail_fast_val):
  original_genops_scan = safer_pickle.genops_scan

  def wrapped_genops_scan(
      pickle_bytes,
      pickle_file_path=None,
      fail_fast=None,
      **kwargs,
  ):
    if fail_fast is None:
      fail_fast = fail_fast_val
    return original_genops_scan(
        pickle_bytes, pickle_file_path, fail_fast, **kwargs
    )

  return wrapped_genops_scan


_DEBUG_MODE = flags.DEFINE_bool('debug_mode', False, 'Enable debug mode')


# Helper class for testing the seek logic
class SeekSpyIO(io.BytesIO):
  """A file-like object that tracks if seek has been called."""

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.was_seeked = False

  def seek(self, *args, **kwargs):
    self.was_seeked = True
    return super().seek(*args, **kwargs)


class TestCustomState:

  def __init__(self, payload):
    self.payload = payload

  def __getstate__(self):
    return self.__dict__

  def __setstate__(self, state):
    self.__dict__.update(state)


class TestTargetClass:

  def __init__(self, state=None):
    self.state = state

  def __getstate__(self):
    return self.state

  def __setstate__(self, state):
    self.state = state


class _CommandGuardTestCase(parameterized.TestCase):

  @contextlib.contextmanager
  def _assert_no_command_execution(self, expect_calls=False, extra_targets=()):
    mocks = {}
    with contextlib.ExitStack() as stack:
      for target in COMMAND_EXECUTION_TARGETS + tuple(extra_targets):
        try:
          mock_obj = stack.enter_context(mock.patch(target))
          mocks[target] = mock_obj
        except (ImportError, ModuleNotFoundError):
          pass  # Some modules might not be available.
      yield
      # Primarily for report_only mode tests
      if not expect_calls:
        for target, mock_obj in mocks.items():
          if mock_obj.called:
            self.fail(
                f'{target} was called unexpectedly with args:'
                f' {mock_obj.call_args_list}'
            )


class BaseTestLoad(_CommandGuardTestCase):

  def setUp(self):
    """Hooks pickle and resets configuration before each test."""
    super().setUp()
    if _DEBUG_MODE.value:
      safer_pickle.DEBUG_MODE = True

    config.set_config_path(None)

    # Ensure hooks are active before each test
    safer_pickle.hook_pickle()

  def tearDown(self):
    """Unhooks pickle after each test to ensure isolation."""
    super().tearDown()
    safer_pickle.unhook_pickle()
    config.set_config_path(None)

  def test_strict_check_error(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaises(safer_pickle.StrictCheckError):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes, strict_check=True)

  # The file used here is 200 bytes of unpickleable data and the rest is random
  # bytes. This bypasses our file detection algorithm since we check for 128
  # bytes of valid unpickleable data.
  def test_forced_scan_of_non_pickle_file(self):
    with open(
        'testdata/pickle_or_not.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      scores_no_force = safer_pickle.security_scan(data_bytes, force_scan=False)
      self.assertGreaterEqual(scores_no_force['unsafe'], 1)
      self.assertEqual(scores_no_force['suspicious'], 0)

      # Scan with force_scan=True (should find the unsafe string)
      scores_force = safer_pickle.security_scan(data_bytes, force_scan=True)
      self.assertGreaterEqual(scores_force['unsafe'], 1)
      self.assertEqual(scores_force['suspicious'], 0)

  def test_load_forced_scan_of_non_pickle_file(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      try:
        data_bytes = f.read()
        pickle.loads(data_bytes, force_scan=True)
      except Exception as e:  # pylint: disable=broad-except
        self.fail(f'Error loading benign pickle file : {e}')

  # Tests a benign file
  def test_benign_file(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      try:
        data_bytes = f.read()
        pickle.loads(data_bytes)
      except Exception as e:  # pylint: disable=broad-except
        self.fail(f'Error loading benign pickle file : {e}')

  # Tests a file that is suspicious and would need further investigation
  # This particular file doesn't actually contain malicious code
  # It calls "tmp" as a method (which doesn't exist) and implements a
  # "print" function that does not execute.

  def test_suspicious_file(self):
    with open(
        'testdata/suspicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  # This tests a file that runs ls using posix.system
  def test_malicious_file(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  # This tests a file that executes code despite unpickling errors
  def test_file_with_error_on_unpickling(self):
    with open(
        'testdata/error_on_unpickling.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  def test_reproducer_file(self):
    reproducer_path = 'testdata/reproducer.pkl'
    if not os.path.exists(reproducer_path):
      self.skipTest(f'{reproducer_path} not present')
    with open(reproducer_path, 'rb') as f:
      try:
        data_bytes = f.read()
        pickle.loads(data_bytes)
      except ModuleNotFoundError as e:
        if 'custom_pkg.' not in str(e):
          self.fail(f'Unexpected ModuleNotFoundError: {e}')
      except Exception as e:  # pylint: disable=broad-except
        self.fail(f'Error loading benign pickle file : {e}')

  def test_approved_root_missing_class_propagates_import_error(self):
    """Tests missing approved-root public classes pass scan and raise ImportError.

    Returns:
      None.
    """
    class_payload = b'ccustom_pkg.nonexistent_subpkg\nMissingLayer\n.'
    with self._assert_no_command_execution():
      scores = safer_pickle.security_scan(class_payload)
      self.assertEqual(scores['unsafe'], 0)
      self.assertEqual(scores['suspicious'], 0)
      self.assertEqual(scores['unknown'], 0)

      with self.assertRaisesRegex(ModuleNotFoundError, 'custom_pkg'):
        pickle.loads(class_payload)

  def test_approved_root_missing_func_raises_unknown_or_propagates_report_only(
      self,
  ):
    """Tests missing approved-root functions raise UNKNOWN or ImportError.

    Returns:
      None.
    """
    func_payload = b'ccustom_pkg.nonexistent_subpkg\nmissing_func\n.'
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(func_payload)

      with self.assertLogs(level='ERROR') as log_output:
        with self.assertRaisesRegex(ModuleNotFoundError, 'custom_pkg'):
          pickle.loads(func_payload, report_only=True)

    self.assertIn('Classification: UNKNOWN', log_output.output[0])

  def test_file_with_unknown_import(self):
    with open(
        'testdata/unknown_import.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self._assert_no_command_execution():
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
        ):
          pickle.loads(data_bytes)
        with mock.patch(
            'platform._syscmd_ver', new=lambda *args, **kwargs: ('', '', '')
        ):
          with self.assertLogs(level='ERROR') as log_output:
            pickle.loads(data_bytes, report_only=True)
      self.assertIn('Classification: UNKNOWN', log_output.output[0])

  def test_picklemagic_parsing_results(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self._assert_no_command_execution():
        results = safer_pickle.picklemagic_scan(data_bytes)
        self.assertNotEmpty(results.unsafe_results)

  def test_pydoc_ordereddict_bypass_blocked(self):
    malicious_bytecode = (
        b'ccollections\nOrderedDict\n)R}(Vfoo\nVbar\nub'
        b'cpydoc\nlocate\n'
        b'('
        b'cpydoc\nreplace\n(VpoXix.XyXtem\nVX\nVs\ntR'
        b'tR'
        b'('
        b'V/bin/sh\n'
        b'tR.'
    )
    with self._assert_no_command_execution():
      with self.assertRaises((
          safer_pickle.StrictCheckError,
          safer_pickle.UnsafePickleDetectedError,
          pickle.UnpicklingError,
      )):
        safer_pickle.load(io.BytesIO(malicious_bytecode), strict_check=True)

  def test_picklemagic_new_opcodes(self):
    with open(
        'testdata/fickling_tests/simple_command_execution.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self._assert_no_command_execution():
        results = safer_pickle.picklemagic_scan(data_bytes)
        self.assertIn('posix.system', results.unsafe_results)

  # Malformed pickle byte stream (ends prematurely) to trigger
  # EOFError in sandbox
  def test_sandbox_unpickling_error_is_flagged(self):
    malformed_pickle = b'cbuiltins\nid\n('
    results = safer_pickle.picklemagic_scan(malformed_pickle)
    self.assertIn('sandbox_unpickling_error', results.suspicious_results)

  def test_custom_container_state_escape_blocked(self):
    orig_safe_strings = safer_pickle.constants.SAFE_STRINGS
    mod_name = 'custom_test_module'
    safer_pickle.constants.SAFE_STRINGS = orig_safe_strings.union({mod_name})
    sys.modules[mod_name] = sys.modules[__name__]
    orig_custom_module = TestCustomState.__module__
    orig_target_module = TestTargetClass.__module__

    try:
      TestCustomState.__module__ = mod_name
      TestTargetClass.__module__ = mod_name
      state = TestCustomState(os.system)
      target = TestTargetClass(state)
      payload_bytes = pickle.dumps(target)

      results = safer_pickle.picklemagic_scan(payload_bytes)
      self.assertIn('unsafe_state_assignment', results.suspicious_results)
    finally:
      TestCustomState.__module__ = orig_custom_module
      TestTargetClass.__module__ = orig_target_module
      safer_pickle.constants.SAFE_STRINGS = orig_safe_strings

  def test_rce_untrusted_module_import_blocked(self):
    with open(
        'testdata/robustness_tests/rce_untrusted_import.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      results = safer_pickle.picklemagic_scan(data_bytes)
      self.assertIn('posix.system', results.unsafe_results)

  def test_stack_global_type_confusion_handled(self):
    with open(
        'testdata/robustness_tests/stack_global_type_confusion.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      results = safer_pickle.picklemagic_scan(data_bytes)
      self.assertIsNotNone(results)

  # This file bypasses Fickling, Picklescan, and Modelscan, but is detected by
  # SaferPickle.
  def test_bypasses_all_pickle_loads(self):
    with open(
        'testdata/extra_bypasses/bypasses_all.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  def test_printbypass_pickle_loads(self):
    with open(
        'testdata/printbypass.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  def test_allow_unsafe(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      try:
        pickle.loads(data_bytes, allow_unsafe=True)
      except Exception as e:  # pylint: disable=broad-except
        self.fail(f'Error loading malicious pickle file : {e}')

  def test_allow_unsafe_report_only(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='INFO') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.INFO)
        try:
          data_bytes = f.read()
          pickle.loads(data_bytes, allow_unsafe=True, report_only=True)
        except Exception as e:  # pylint: disable=broad-except
          self.fail(f'Error loading safe pickle file : {e}')
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('allow_unsafe set to True', output)

  # This tests if a malicious file is detected as
  # malicious by all the scan approaches
  def test_all_scan_approaches(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()

      scores = safer_pickle.apply_approach(
          safer_pickle.picklemagic_scan, data_bytes
      )
      self.assertGreater(
          scores['unsafe'] + scores['suspicious'],
          0,
          'Picklemagic scan did not find any unsafe/suspicious results',
      )

      scores = safer_pickle.apply_approach(safer_pickle.genops_scan, data_bytes)
      self.assertGreater(
          scores['unsafe'] + scores['suspicious'],
          0,
          'Genops scan did not find any unsafe/suspicious results',
      )

  @parameterized.named_parameters(
      dict(
          testcase_name='cloudpickle_lambda.pkl',
          filename='cloudpickle_lambda.pkl',
      ),
      dict(
          testcase_name='cloudpickle_ossystem.pkl',
          filename='cloudpickle_ossystem.pkl',
      ),
      dict(
          testcase_name='cloudpickle_register_module.pkl',
          filename='cloudpickle_register_module.pkl',
      ),
  )
  def testing_cloudpickle(self, filename):
    file = os.path.join(
        'testdata/cloudpickle_tests',
        filename,
    )
    with open(file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          cloudpickle.loads(data_bytes)

  # Tests if the hook doesn't empty out pickle.dump
  def testing_pickle_dump(self):
    with self.assertRaisesRegex(TypeError, 'missing required argument'):
      pickle.dump()

  # Tests if the hook doesn't empty out pickle.dumps
  def testing_pickle_dumps(self):
    with self.assertRaisesRegex(TypeError, 'missing required argument'):
      pickle.dumps()

  def test_hooking_all_libraries(self):
    malicious_pickle_path = 'testdata/malicious.pkl'
    with open(malicious_pickle_path, 'rb') as f:
      data_bytes = f.read()

    # check pickle
    with self.subTest('pickle'):
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            pickle.load(f)

    # check _pickle
    with self.subTest('_pickle'):
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          _pickle.loads(data_bytes)
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            _pickle.load(f)

    # check dill
    with self.subTest('dill'):
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          dill.loads(data_bytes)
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            dill.load(f)

    # check cloudpickle
    with self.subTest('cloudpickle'):
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          cloudpickle.loads(data_bytes)
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            cloudpickle.load(f)

    # check torch
    with self.subTest('torch'):
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            torch.load(f)

    # check joblib
    with self.subTest('joblib'):
      with open(malicious_pickle_path, 'rb') as f:
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          with self._assert_no_command_execution():
            joblib.load(f)

  @parameterized.named_parameters(
      dict(
          testcase_name='loads_pickle',
          lib=pickle,
          file_name='pickle_safe.pkl',
      ),
      dict(
          testcase_name='loads__pickle',
          lib=_pickle,
          file_name='pickle_safe.pkl',
      ),
      dict(
          testcase_name='loads_dill',
          lib=dill,
          file_name='dill_safe.pkl',
      ),
      dict(
          testcase_name='loads_cloudpickle',
          lib=cloudpickle,
          file_name='cloudpickle_safe.pkl',
      ),
  )
  def test_hooking_benign_file_loads(self, lib, file_name):
    test_file_dir = (
        'testdata/library_specific_safe_pickles'
    )
    pickle_path = os.path.join(test_file_dir, file_name)
    with open(pickle_path, 'rb') as f:
      data_bytes = f.read()
    try:
      lib.loads(data_bytes)
    except Exception as e:  # pylint: disable=broad-except
      self.fail(f'{lib.__name__}.loads failed on safe file {file_name}: {e}')

  @parameterized.named_parameters(
      dict(
          testcase_name='load_pickle',
          lib=pickle,
          file_name='pickle_safe.pkl',
      ),
      dict(
          testcase_name='load__pickle',
          lib=_pickle,
          file_name='pickle_safe.pkl',
      ),
      dict(
          testcase_name='load_dill',
          lib=dill,
          file_name='dill_safe.pkl',
      ),
      dict(
          testcase_name='load_cloudpickle',
          lib=cloudpickle,
          file_name='cloudpickle_safe.pkl',
      ),
      dict(
          testcase_name='load_joblib',
          lib=joblib,
          file_name='joblib_safe.pkl',
      ),
      dict(
          testcase_name='load_torch_pkl',
          lib=torch,
          file_name='torch_safe.pkl',
      ),
      dict(
          testcase_name='load_torch_pt',
          lib=torch,
          file_name='torch_safe.pt',
      ),
      dict(
          testcase_name='load_torch_zip_pt',
          lib=torch,
          file_name='torch_safe_zip.pt',
      ),
  )
  def test_hooking_benign_file_load(self, lib, file_name):
    test_file_dir = (
        'testdata/library_specific_safe_pickles'
    )
    pickle_path = os.path.join(test_file_dir, file_name)
    with open(pickle_path, 'rb') as f:
      try:
        lib.load(f)
      except (ModuleNotFoundError, AttributeError):
        pass
      except Exception as e:  # pylint: disable=broad-except
        self.fail(f'{lib.__name__}.load failed on safe file {file_name}: {e}')

  def test_unhook_pickle(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()

    # Verify hook is active
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
    ):
      with self._assert_no_command_execution():
        pickle.loads(data_bytes)

    safer_pickle.unhook_pickle()

    # Mock posix.system to prevent actual execution
    with mock.patch('posix.system') as mocked_system:
      try:
        pickle.loads(data_bytes)
      except safer_pickle.UnsafePickleDetectedError:
        self.fail('Unhooking failed')
      mocked_system.assert_called_once()

    # Re-enable hook for the other tests
    safer_pickle.hook_pickle()

    # Verify if hook is active again
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
    ):
      with self._assert_no_command_execution():
        pickle.loads(data_bytes)

  def test_hook_pickle_libs_context_manager_report_only_off(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()

    # Unhook first to test context manager behavior in isolation
    safer_pickle.unhook_pickle()

    # Check that hook is inactive
    with mock.patch('posix.system') as mocked_system:
      try:
        pickle.loads(data_bytes)
      except safer_pickle.UnsafePickleDetectedError:
        self.fail('Hook should be inactive.')
      mocked_system.assert_called_once()

    # Test context manager with report_only=False
    with safer_pickle.hook_pickle_libs(report_only=False):
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

    # Check that hook is inactive after exiting context manager
    with mock.patch('posix.system') as mocked_system:
      try:
        pickle.loads(data_bytes)
      except safer_pickle.UnsafePickleDetectedError:
        self.fail('Hook should be inactive after context manager.')
      mocked_system.assert_called_once()

    # Re-enable hook for the other tests
    safer_pickle.hook_pickle()

  def test_hook_pickle_libs_context_manager_report_only_on(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()

    # Unhook first to test context manager behavior in isolation
    safer_pickle.unhook_pickle()

    # Check that hook is inactive
    with mock.patch('posix.system') as mocked_system:
      try:
        pickle.loads(data_bytes)
      except safer_pickle.UnsafePickleDetectedError:
        self.fail('Hook should be inactive.')
      mocked_system.assert_called_once()

    # Test context manager with report_only=True (default)
    with safer_pickle.hook_pickle_libs():
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          with self._assert_no_command_execution(expect_calls=True):
            pickle.loads(data_bytes)
        except safer_pickle.UnsafePickleDetectedError:
          self.fail(
              'hook_pickle_libs() should be in report-only mode by default and'
              ' not raise UnsafePickleDetectedError.'
          )
        finally:
          logging.set_verbosity(log_level)
      self.assertIn('UNSAFE', log_output.output[0])

    # Check that hook is inactive after exiting context manager
    with mock.patch('posix.system') as mocked_system:
      try:
        pickle.loads(data_bytes)
      except safer_pickle.UnsafePickleDetectedError:
        self.fail('Hook should be inactive after context manager.')
      mocked_system.assert_called_once()

    # Re-enable hook for the other tests
    safer_pickle.hook_pickle()

  def test_custom_load_calls_seek(self):
    """Confirms custom_load calls seek() on a seekable file-like object."""
    with open('testdata/safe.pkl', 'rb') as f:
      pickle_data = f.read()

    # Wrap the pickle data in our spy object
    spy_file = SeekSpyIO(pickle_data)

    # Load from the spy object. The hook will trigger custom_load.
    pickle.load(spy_file)

    # Assert that the seek method on our spy object was called.
    self.assertTrue(
        spy_file.was_seeked,
        'The seek() method was not called on the file object.',
    )

  def testing_pickle_shorthand_load(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle._load(f)

  def testing_pickle_shorthand_loads(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle._loads(data_bytes)

  @parameterized.named_parameters(
      dict(
          testcase_name='benign',
          filename='safe.pkl',
          expected=False,
      ),
      dict(
          testcase_name='suspicious',
          filename='suspicious.pkl',
          expected=True,
      ),
      dict(
          testcase_name='malicious',
          filename='malicious.pkl',
          expected=True,
      ),
      dict(
          testcase_name='file_with_error_on_unpickling',
          filename='error_on_unpickling.pkl',
          expected=True,
      ),
  )
  def test_strict_checking(self, filename, expected):
    """Tests if strict checking is working for various files."""
    with open(
        'testdata/' + filename,
        'rb',
    ) as f:
      data_bytes = f.read()
      self.assertEqual(safer_pickle.strict_security_scan(data_bytes), expected)

  def test_malicious_zipped_torch_model(self):
    with open(
        'testdata/modelscan_tests/unsafe_zip_pytorch.pt',
        'rb',
    ) as f:
      data_bytes = f.read()
      scan_scores = safer_pickle.security_scan(data_bytes)
      self.assertGreater(scan_scores['unsafe'] + scan_scores['suspicious'], 0)

  def test_bad_zip_archive_fails_scan(self):
    # Zip signature PK\x03\x04 followed by invalid/corrupted bytes
    bad_zip_data = b'PK\x03\x04' + b'\x00' * 20
    scan_scores = safer_pickle.security_scan(bad_zip_data)
    self.assertEqual(
        scan_scores['unsafe'],
        safer_pickle.constants.HIGH_SEVERITY_ZIPSLIP,
    )

  @parameterized.named_parameters(
      dict(
          testcase_name='pickle',
          lib=pickle,
      ),
      dict(
          testcase_name='pickle_',
          lib=_pickle,
      ),
  )
  def test_strict_checking_with_hook(self, lib):
    """Tests if the strict checking is working while hooking pickle libraries."""
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaises(safer_pickle.StrictCheckError):
        with self._assert_no_command_execution():
          lib.loads(data_bytes, strict_check=True)

  @parameterized.named_parameters(
      dict(
          testcase_name='blocking',
          report_only=False,
      ),
      dict(
          testcase_name='report_only',
          report_only=True,
      ),
  )
  def test_conflicting_arguments(self, report_only):
    """Tests if IllegalArgumentCombinationError is raised when strict_check and allow_unsafe are both set to True."""
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      if report_only:
        with self.assertLogs(level='ERROR') as log_output:
          log_level = logging.get_verbosity()
          logging.set_verbosity(logging.ERROR)
          try:
            with self._assert_no_command_execution(expect_calls=True):
              pickle.loads(
                  data_bytes,
                  strict_check=True,
                  allow_unsafe=True,
                  report_only=True,
              )
          except Exception as e:  # pylint: disable=broad-except
            self.fail(f'Error loading malicious pickle file : {e}')
          finally:
            logging.set_verbosity(log_level)
        output = log_output[0][0].message
        self.assertIn('cannot be used together', output)
      else:
        with self.assertRaises(safer_pickle.IllegalArgumentCombinationError):
          with self._assert_no_command_execution(expect_calls=True):
            pickle.loads(data_bytes, strict_check=True, allow_unsafe=True)

  # TESTING using report-only mode
  # Tests a benign file
  @mock.patch('absl.logging.info')
  def test_benign_file_report_only(self, mock_logging_info):
    with open('testdata/safe.pkl', 'rb') as f:
      data_bytes = f.read()
    pickle.loads(data_bytes, report_only=True)
    mock_logging_info.assert_called_with('Loading safe pickle file')

  def test_suspicious_file_report_only(self):
    with open(
        'testdata/suspicious.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          data_bytes = f.read()
          with self._assert_no_command_execution(expect_calls=True):
            pickle.loads(data_bytes, report_only=True)
        except (ModuleNotFoundError, AttributeError) as e:
          if isinstance(e, ModuleNotFoundError) and 'tmp' not in str(e):
            self.fail(f'Unexpected ModuleNotFoundError: {e}')
        except Exception as e:  # pylint: disable=broad-except
          self.fail(f'Error loading suspicious pickle file : {e}')
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('SUSPICIOUS', output)

  def test_malicious_file_report_only(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          data_bytes = f.read()
          with self._assert_no_command_execution(expect_calls=True):
            pickle.loads(data_bytes, report_only=True)
        except Exception as e:  # pylint: disable=broad-except
          self.fail(f'Error loading malicious pickle file : {e}')
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('UNSAFE', output)

  def test_file_with_error_on_unpickling_report_only(self):
    with open(
        'testdata/error_on_unpickling.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          data_bytes = f.read()
          with self._assert_no_command_execution(
              expect_calls=True, extra_targets=('builtins.print',)
          ):
            with self.assertRaises(pickle.UnpicklingError):
              pickle.loads(data_bytes, report_only=True)
        except Exception as e:  # pylint: disable=broad-except
          self.fail(f'Error loading file with unpickling error : {e}')
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('code execution', output)

  def testing_pickle_with_strict_checking_report_only(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          data_bytes = f.read()
          with self._assert_no_command_execution(expect_calls=True):
            pickle.loads(data_bytes, strict_check=True, report_only=True)
        except Exception as e:  # pylint: disable=broad-except
          self.fail(f'Error loading malicious pickle file : {e}')
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('failed strict', output)

  def test_strict_check_report_only_returns_deserialized_object(self):
    """Verifies strict_check=True with report_only=True returns the object.

    Ensures a pickle failing `strict_security_scan` under `report_only=True`
    logs an error and still returns the deserialized instance rather than None.

    Returns:
      None.
    """
    payload = b'\x80\x04cfractions\nFraction\n(I3\nI4\ntR.'

    with self.assertLogs(level='ERROR') as log_output:
      log_level = logging.get_verbosity()
      logging.set_verbosity(logging.ERROR)
      try:
        with self._assert_no_command_execution():
          loaded = pickle.loads(payload, strict_check=True, report_only=True)
          unpickled = pickle.Unpickler(
              io.BytesIO(payload), strict_check=True, report_only=True
          ).load()
      finally:
        logging.set_verbosity(log_level)

    self.assertEqual(loaded, fractions.Fraction(3, 4))
    self.assertEqual(unpickled, fractions.Fraction(3, 4))
    self.assertIn('failed strict', log_output[0][0].message)

  def test_custom_unpickler(self):
    with open(
        'testdata/numpy_allowlist.pkl',
        'rb',
    ) as f:
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          safer_pickle.Unpickler(f).load()

  def test_custom_unpickler_safe_file(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      try:
        safer_pickle.Unpickler(f).load()
      except Exception as e:  # pylint: disable=broad-except
        self.fail(
            f'Error loading benign pickle file with custom unpickler: {e}'
        )

  def test_custom_unpickler_malicious_file_report_only(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          with self._assert_no_command_execution(expect_calls=True):
            safer_pickle.Unpickler(f, report_only=True).load()
        except Exception as e:  # pylint: disable=broad-except
          self.fail(
              'Error loading malicious pickle file with custom unpickler in'
              f' report-only mode: {e}'
          )
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('UNSAFE', output)

  def test_custom_load_safe_file(self):
    with open(
        'testdata/safe.pkl',
        'rb',
    ) as f:
      try:
        safer_pickle.load(f)
      except (ModuleNotFoundError, AttributeError):
        pass
      except Exception as e:  # pylint: disable=broad-except
        if 'weights_only' in str(e) or 'Weights only load failed' in str(e):
          pass
        else:
          self.fail(f'Error loading benign pickle file with custom load: {e}')

  def test_custom_load_malicious_file(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          safer_pickle.load(f)

  def test_custom_load_malicious_file_report_only(self):
    with open(
        'testdata/malicious.pkl',
        'rb',
    ) as f:
      with self.assertLogs(level='ERROR') as log_output:
        log_level = logging.get_verbosity()
        logging.set_verbosity(logging.ERROR)
        try:
          safer_pickle.load(f, report_only=True)
        except (ModuleNotFoundError, AttributeError):
          pass
        except Exception as e:  # pylint: disable=broad-except
          if 'weights_only' in str(e) or 'Weights only load failed' in str(e):
            pass
          else:
            self.fail(
                'Error loading malicious pickle file with custom load in'
                f' report-only mode: {e}'
            )
        finally:
          logging.set_verbosity(log_level)
      output = log_output[0][0].message
      self.assertIn('UNSAFE', output)

  def test_obfuscated_malicious_file(self):
    with open(
        'testdata/malicious_obfuscated.pkl',
        'rb',
    ) as f:
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        data_bytes = f.read()
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @parameterized.named_parameters(
      dict(testcase_name='jax_test_1.pkl', filename='jax_test_1.pkl'),
      dict(testcase_name='jax_test_10.pkl', filename='jax_test_10.pkl'),
      dict(testcase_name='jax_test_11.pkl', filename='jax_test_11.pkl'),
      dict(testcase_name='jax_test_12.pkl', filename='jax_test_12.pkl'),
      dict(testcase_name='jax_test_13.pkl', filename='jax_test_13.pkl'),
      dict(testcase_name='jax_test_2.pkl', filename='jax_test_2.pkl'),
      dict(testcase_name='jax_test_3.pkl', filename='jax_test_3.pkl'),
      dict(testcase_name='jax_test_4.pkl', filename='jax_test_4.pkl'),
      dict(testcase_name='jax_test_5.pkl', filename='jax_test_5.pkl'),
      dict(testcase_name='jax_test_6.pkl', filename='jax_test_6.pkl'),
      dict(testcase_name='jax_test_7.pkl', filename='jax_test_7.pkl'),
      dict(testcase_name='jax_test_8.pkl', filename='jax_test_8.pkl'),
      dict(testcase_name='jax_test_9.pkl', filename='jax_test_9.pkl'),
  )
  def test_jax_files(self, filename):
    benign_file = os.path.join(
        'testdata/jax_tests', filename
    )
    if not os.path.exists(benign_file):
      self.skipTest(f'{benign_file} not present')
    with open(benign_file, 'rb') as f:
      data_bytes = f.read()
      scan_scores = safer_pickle.security_scan(data_bytes)
      self.assertLessEqual(scan_scores['unsafe'], 0)
      if filename in (
          'jax_test_5.pkl',
          'jax_test_6.pkl',
          'jax_test_7.pkl',
          'jax_test_8.pkl',
          'jax_test_9.pkl',
      ):
        # Files 5-9 contain __globals__ and getattr from serialized functions.
        self.assertGreater(scan_scores['suspicious'], 0)
      else:
        self.assertLessEqual(scan_scores['suspicious'], 0)

  @parameterized.named_parameters(
      dict(
          testcase_name='crash_obj_opcode',
          filename='crash_obj_opcode.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='crash_pop_mark_obfuscation',
          filename='crash_pop_mark_obfuscation.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='nested_pytorch_bypass',
          filename='nested_pytorch_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='programmatic_inst_opcode',
          filename='programmatic_inst_opcode.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='programmatic_lambda_call',
          filename='programmatic_lambda_call.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='simple_command_execution',
          filename='simple_command_execution.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
  )
  def test_fickling_files(self, filename, expected_exception, expected_message):
    malicious_file = os.path.join(
        'testdata/fickling_tests',
        filename,
    )
    with open(malicious_file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          expected_exception,
          expected_message,
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  # These test files were generated by referring to
  # https://hitcon.org/2022/slides/Pain%20Pickle%EF%BC%9A%E7%B3%BB%E7%B5%B1%E5%8C%96%E5%9C%B0%E7%B9%9E%E9%81%8E%20Restricted%20Unpickler.pdf
  @parameterized.named_parameters(
      dict(
          testcase_name='type1_id.pkl',
          filename='type1_id.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type1_req.pkl',
          filename='type1_req.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type2_id.pkl',
          filename='type2_id.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type2_req.pkl',
          filename='type2_req.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type3_id.pkl',
          filename='type3_id.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type3_id_2.pkl',
          filename='type3_id_2.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='type3_req.pkl',
          filename='type3_req.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='unrestricted_id.pkl',
          filename='unrestricted_id.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='unrestricted_req.pkl',
          filename='unrestricted_req.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
  )
  def test_painpickle_malicious_test_files(
      self, filename, expected_exception, expected_message
  ):
    malicious_file = os.path.join(
        'testdata/pain_pickle_tests',
        filename,
    )
    with open(malicious_file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          expected_exception,
          expected_message,
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @parameterized.named_parameters(
      dict(
          testcase_name='numpy_setstate_bypass',
          filename='numpy_setstate_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='timeit_bypass',
          filename='timeit_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='subclass_bypass',
          filename='subclass_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='metamorphic_bypass',
          filename='metamorphic_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='chainmap_bypass',
          filename='chainmap_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='unused_variable_bypass',
          filename='unused_variable_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='string_concat_bypass',
          filename='string_concat_bypass.pkl',
          expected_exception=safer_pickle.UnsafePickleDetectedError,
          expected_message='UNSAFE|SUSPICIOUS',
      ),
  )
  def test_extra_bypasses(self, filename, expected_exception, expected_message):
    malicious_file = os.path.join(
        'testdata/extra_bypasses',
        filename,
    )
    with open(malicious_file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          expected_exception,
          expected_message,
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @parameterized.named_parameters(
      dict(
          testcase_name='malicious-invalid-bytes.pkl',
          filename='malicious-invalid-bytes.pkl',
      ),
      dict(testcase_name='malicious0.pkl', filename='malicious0.pkl'),
      dict(testcase_name='malicious10.pkl', filename='malicious10.pkl'),
      dict(testcase_name='malicious11.pkl', filename='malicious11.pkl'),
      dict(testcase_name='malicious12.pkl', filename='malicious12.pkl'),
      dict(testcase_name='malicious13a.pkl', filename='malicious13a.pkl'),
      dict(testcase_name='malicious13b.pkl', filename='malicious13b.pkl'),
      dict(testcase_name='malicious14.pkl', filename='malicious14.pkl'),
      dict(testcase_name='malicious15a.pkl', filename='malicious15a.pkl'),
      dict(testcase_name='malicious15b.pkl', filename='malicious15b.pkl'),
      dict(testcase_name='malicious1_v0.pkl', filename='malicious1_v0.pkl'),
      dict(testcase_name='malicious1_v3.pkl', filename='malicious1_v3.pkl'),
      dict(testcase_name='malicious1_v4.pkl', filename='malicious1_v4.pkl'),
      dict(testcase_name='malicious2_v0.pkl', filename='malicious2_v0.pkl'),
      dict(testcase_name='malicious2_v3.pkl', filename='malicious2_v3.pkl'),
      dict(testcase_name='malicious2_v4.pkl', filename='malicious2_v4.pkl'),
      dict(testcase_name='malicious3.pkl', filename='malicious3.pkl'),
      dict(testcase_name='malicious4.pickle', filename='malicious4.pickle'),
      dict(testcase_name='malicious5.pkl', filename='malicious5.pkl'),
      dict(testcase_name='malicious7.pkl', filename='malicious7.pkl'),
      dict(testcase_name='malicious8.pkl', filename='malicious8.pkl'),
      dict(testcase_name='malicious9.pkl', filename='malicious9.pkl'),
  )
  def test_picklescan_malicious_test_files(self, filename):
    malicious_file = os.path.join(
        'testdata/picklescan_tests',
        filename,
    )
    with open(malicious_file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @parameterized.named_parameters(
      dict(
          testcase_name='Pickle file with find_class bypass',
          input_file='testdata/numpy_allowlist.pkl',
          expected_classification='unsafe',
          expected_justification_substr='__import__',
      ),
      dict(
          testcase_name='Cloudpickled file with os.system',
          input_file=(
              'testdata/cloudpickle_tests/cloudpickle_ossystem.pkl'
          ),
          expected_classification='suspicious',
          expected_justification_substr='__globals__',
      ),
      dict(
          testcase_name='Cloudpickled file with malicious lambda layer',
          input_file=(
              'testdata/cloudpickle_tests/cloudpickle_lambda.pkl'
          ),
          expected_classification='suspicious',
          expected_justification_substr='__globals__',
      ),
      dict(
          testcase_name='Pickle file that errors out on unpickling',
          input_file=(
              'testdata/error_on_unpickling.pkl'
          ),
          expected_classification='suspicious',
          expected_justification_substr='print',
      ),
      dict(
          testcase_name='Pickle file with unknown import',
          input_file='testdata/unknown_import.pkl',
          expected_classification='unknown',
          expected_justification_substr='platform._syscmd_ver',
      ),
      dict(
          testcase_name='Safe pickle file',
          input_file='testdata/safe.pkl',
          expected_classification='benign',
          expected_justification_substr='',
      ),
      dict(
          testcase_name='A file that is not a pickle file',
          input_file=(
              'testdata/not_a_pickle_file.pkl'
          ),
          expected_classification='Not supported',
          expected_justification_substr='Not a pickle file',
      ),
  )
  def test_security_scan_with_justifications_and_file_detection(
      self, input_file, expected_classification, expected_justification_substr
  ):
    with open(input_file, 'rb') as f:
      data_bytes = f.read()
      results = safer_pickle_cli.security_scan_with_justifications(data_bytes)
      self.assertEqual(results['classification'], expected_classification)
      self.assertIn(expected_justification_substr, results['justification'])

  @parameterized.named_parameters(
      dict(
          testcase_name='Cloudpickled file with os.system',
          input_file=(
              'testdata/cloudpickle_tests/cloudpickle_ossystem.pkl'
          ),
          expected='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='Cloudpickled file with register_module',
          input_file=(
              'testdata/cloudpickle_tests/cloudpickle_register_module.pkl'
          ),
          expected='UNSAFE|SUSPICIOUS',
      ),
      dict(
          testcase_name='Cloudpickled file with a malicious lambda layer',
          input_file=(
              'testdata/cloudpickle_tests/cloudpickle_lambda.pkl'
          ),
          expected='UNSAFE|SUSPICIOUS',
      ),
  )
  def test_scanning_cloudpickle_files(self, input_file, expected):
    with open(input_file, 'rb') as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, expected
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  def test_thread_safety_context_manager(self):
    malicious_pickle_path = 'testdata/malicious.pkl'
    with open(malicious_pickle_path, 'rb') as f:
      malicious_pickle_bytes = f.read()

    exception_in_thread = []

    def thread_target(report_only_flag):
      try:
        with self._assert_no_command_execution(expect_calls=report_only_flag):
          with safer_pickle.hook_pickle_libs(report_only=report_only_flag):
            if report_only_flag:
              # Should not raise in report-only mode
              pickle.loads(malicious_pickle_bytes)
            else:
              # Should raise in non-report-only mode
              try:
                pickle.loads(malicious_pickle_bytes)
                exception_in_thread.append(
                    'Exception not raised in thread with report_only=False'
                )
              except safer_pickle.UnsafePickleDetectedError:
                pass  # Expected
      except safer_pickle.UnsafePickleDetectedError:
        if report_only_flag:
          exception_in_thread.append(
              'Exception raised in thread with report_only=True'
          )
      except Exception as e:  # pylint: disable=broad-except
        exception_in_thread.append(f'Unexpected exception in thread: {e}')

    safer_pickle.unhook_pickle()

    threads = []
    for i in range(4):
      thread = threading.Thread(target=thread_target, args=(i % 2 != 0,))
      threads.append(thread)
      thread.start()
      time.sleep(0.05)  # stagger threads slightly to increase chance of race

    for thread in threads:
      thread.join()

    self.assertEmpty(exception_in_thread)

    safer_pickle.hook_pickle()

  def test_streaming_scan(self):
    """Tests that the streaming scan produces the same result as the in-memory scan."""
    content = pickle.dumps(fractions.Fraction(3, 4), protocol=4)
    temp_file = self.create_tempfile('streaming_fraction.pkl', content=content)

    expected_ops = safer_pickle.generate_ops(content)
    streaming_ops = safer_pickle.generate_ops_from_file(
        temp_file.full_path, pickle_length=len(content)
    )

    self.assertNotEmpty(expected_ops)
    self.assertEqual(expected_ops, streaming_ops)

  def test_module_not_found_raises(self):
    pickle_bytes = b'cnon_existent_module\nNonExistentClass\n.'
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(pickle_bytes)
      with self.assertRaises(ModuleNotFoundError):
        pickle.loads(pickle_bytes, allow_unsafe=True)

  def test_attribute_error_raises(self):
    pickle_bytes = b'ccollections\nnon_existent_attribute\n.'
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(pickle_bytes)
      with self.assertRaises(AttributeError):
        pickle.loads(pickle_bytes, allow_unsafe=True)

  def test_genops_truncated_stringnl_raises_unsafe_error(self):
    malformed_pickle = b'S"unterminated string'
    with self.assertRaises(safer_pickle.UnsafePickleDetectedError):
      list(safer_pickle._custom_genops(malformed_pickle))

  def test_custom_genops_custom_stream_unexpected_error_not_swallowed(self):
    class BrokenStream:

      def read(self, size):
        raise TypeError('Unexpected stream type error')

    with self.assertRaises(TypeError):
      list(safer_pickle._custom_genops(BrokenStream()))

  def test_cloudpickle_make_function_without_globals_blocked(self):
    # Constructs a pickle invoking _builtin_type('CodeType') and
    # _make_function(code_obj, {}) with empty {} globals and no '__globals__'
    # string token anywhere in the stream.
    payload = (
        b'\x80\x04'
        b'\x8c\x17cloudpickle.cloudpickle\x8c\r_make_function\x93'
        b'\x8c\x17cloudpickle.cloudpickle\x8c\r_builtin_type\x93'
        b'\x8c\x08CodeType\x85R'
        b'(\x8a\x00'
        b'}\x86R'
        b')R.'
    )
    scan_res = safer_pickle.genops_scan(payload)
    self.assertNotEmpty(scan_res.suspicious_results)
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
    ):
      pickle.loads(payload)  # pylint: disable=g-unsafe-pickle-load


class TestCLI(parameterized.TestCase):

  def test_scan_directory_with_invalid_path(self):
    results = safer_pickle_cli.scan_directory('invalid_path')
    with self.subTest(name='CheckStatus'):
      self.assertEqual(results[0]['status'], 'error')
    with self.subTest(name='CheckFilename'):
      self.assertEqual(results[0]['filename'], 'invalid_path')
    with self.subTest(name='CheckErrorMessage'):
      self.assertEqual(
          results[0]['error_msg'], 'Input path is not a valid directory.'
      )

  def test_scan_directory_returns_json_serializable_results(self):
    test_dir = self.create_tempdir()
    test_dir.create_file('test.pkl', content=b'test')
    results = safer_pickle_cli.scan_directory(test_dir.full_path)
    try:
      json.dumps(results)
    except TypeError as e:
      self.fail(f'scan_directory result is not json serializable: {e}')

  def test_indirect_import(self):
    data = pickle.dumps('torch.serialization.os.system')
    scores = safer_pickle.security_scan(data)
    self.assertGreater(scores['unsafe'], 0)

  def test_pathlib_use(self):
    data = pickle.dumps(pathlib.Path('/tmp/test'))
    scores = safer_pickle.security_scan(data)
    self.assertGreater(scores['suspicious'], 0)

  def test_byte_streaming_and_seek_back(self):
    # Verifies that load() natively streams seekable file-like objects without
    # loading them into memory and safely seeks back to 0 in the finally block.
    class SeekTrackingBytesIO(io.BytesIO):

      def __init__(self, initial_bytes):
        super().__init__(initial_bytes)
        self.seek_calls = []
        self.read_calls = []

      def seek(self, *args, **kwargs):
        self.seek_calls.append((args, kwargs))
        return super().seek(*args, **kwargs)

      def read(self, *args, **kwargs):
        self.read_calls.append((args, kwargs))
        return super().read(*args, **kwargs)

    data_bytes = pickle.dumps([1, 2, 3])
    stream = SeekTrackingBytesIO(data_bytes)

    safer_pickle.hook_pickle()
    try:
      result = pickle.load(stream)
      self.assertEqual(result, [1, 2, 3])

      seek_to_zero_calls = [
          call for call in stream.seek_calls if call[0] == (0,)
      ]
      self.assertGreaterEqual(len(seek_to_zero_calls), 2)

      full_read_calls = [call for call in stream.read_calls if not call[0]]
      self.assertEmpty(full_read_calls)
    finally:
      safer_pickle.unhook_pickle()

  def test_strict_scan_fail_fast(self):
    # strict_security_scan should fail fast on the first unsafe match.
    original_genops = safer_pickle._custom_genops
    yield_count = 0

    def mock_genops(*args, **kwargs):
      nonlocal yield_count
      for item in original_genops(*args, **kwargs):
        yield_count += 1
        yield item

    with mock.patch.object(
        safer_pickle, '_custom_genops', side_effect=mock_genops
    ):
      data_bytes = pickle.dumps([os.system, os.system, os.system])
      is_dangerous = safer_pickle.strict_security_scan(data_bytes)
      self.assertTrue(is_dangerous)
      self.assertEqual(yield_count, 3)

  def test_picklemagic_scan_archive(self):
    with open(
        'testdata/modelscan_tests/unsafe_zip_pytorch.pt',
        'rb',
    ) as f:
      data_bytes = f.read()
      results = safer_pickle.picklemagic_scan(data_bytes)
      self.assertNotEmpty(results.unsafe_results)

  def test_genops_scan_archive(self):
    with open(
        'testdata/modelscan_tests/unsafe_zip_pytorch.pt',
        'rb',
    ) as f:
      data_bytes = f.read()
      results = safer_pickle.genops_scan(data_bytes)
      self.assertNotEmpty(results.unsafe_results)

  def test_cli_archive_multi_pickle_zip_flags_unsafe(self):
    benign_pkl = pickle.dumps({'safe': [1, 2, 3]}, protocol=4)
    malicious_pkl = b'\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'

    multi_zip_buf = io.BytesIO()
    with zipfile.ZipFile(multi_zip_buf, 'w') as zf:
      zf.writestr('01_benign.pkl', benign_pkl)
      zf.writestr('02_malicious.pkl', malicious_pkl)

    multi_res = safer_pickle_cli.security_scan_with_justifications(
        multi_zip_buf.getvalue()
    )
    self.assertEqual(multi_res['classification'], 'unsafe')

  def test_cli_archive_benign_zip_classified_benign(self):
    benign_pkl = pickle.dumps({'safe': [1, 2, 3]}, protocol=4)
    benign_zip_buf = io.BytesIO()
    with zipfile.ZipFile(benign_zip_buf, 'w') as zf:
      zf.writestr('01_benign.pkl', benign_pkl)

    benign_res = safer_pickle_cli.security_scan_with_justifications(
        benign_zip_buf.getvalue()
    )
    self.assertEqual(benign_res['classification'], 'benign')

  def test_cli_archive_corrupted_zip_fails_closed(self):
    corrupt_res = safer_pickle_cli.security_scan_with_justifications(
        b'PK\x03\x04corrupted_zip_payload'
    )
    self.assertEqual(corrupt_res['classification'], 'unsafe')

  def test_cli_non_pickle_archives_return_not_supported(self):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
      zf.writestr('README.txt', b'plain text archive member')
      zf.writestr('config.json', b'{"hello": "world"}')

    zip_res = safer_pickle_cli.security_scan_with_justifications(
        zip_buf.getvalue()
    )
    self.assertEqual(zip_res['classification'], 'Not supported')

    gz_res = safer_pickle_cli.security_scan_with_justifications(
        gzip.compress(b'plain text compressed payload')
    )
    self.assertEqual(gz_res['classification'], 'Not supported')


class TestLoadFailFastTrue(BaseTestLoad):

  def setUp(self):
    super().setUp()
    self.patcher1 = mock.patch.object(
        safer_pickle, 'security_scan', make_security_scan_wrapper(True)
    )
    self.patcher2 = mock.patch.object(
        safer_pickle, 'genops_scan', make_genops_scan_wrapper(True)
    )
    self.patcher1.start()
    self.patcher2.start()

  def tearDown(self):
    self.patcher1.stop()
    self.patcher2.stop()
    super().tearDown()

  def test_tensor_checkpoint_400mb(self):
    checkpoint_path = (
        'testdata/tensor_checkpoint_400mb.pkl'
    )
    if not os.path.exists(checkpoint_path):
      self.skipTest(f'{checkpoint_path} not present')
    with open(checkpoint_path, 'rb') as f:
      data_bytes = f.read()

    t0 = time.perf_counter()
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
    ):
      with self._assert_no_command_execution():
        pickle.loads(data_bytes)
    t1 = time.perf_counter()

    print(
        '\n[Benchmark] 400MB Malicious Tensor Checkpoint blocked in'
        f' {t1 - t0:.4f}s'
    )


class TestLoadFailFastFalse(BaseTestLoad):

  def setUp(self):
    super().setUp()
    self.patcher1 = mock.patch.object(
        safer_pickle, 'security_scan', make_security_scan_wrapper(False)
    )
    self.patcher2 = mock.patch.object(
        safer_pickle, 'genops_scan', make_genops_scan_wrapper(False)
    )
    self.patcher1.start()
    self.patcher2.start()

  def tearDown(self):
    self.patcher1.stop()
    self.patcher2.stop()
    super().tearDown()

  def test_tensor_checkpoint_400mb(self):
    TestLoadFailFastTrue.test_tensor_checkpoint_400mb(self)


class TestFailFast(parameterized.TestCase):

  @mock.patch.object(safer_pickle.utils, 'get_optimal_workers', return_value=3)
  def test_parallel_short_circuiting(self, unused_mock_workers):
    class MockFuture:

      def __init__(self, result, name=''):
        self._result = result
        self.name = name
        self.cancelled = False

      def result(self):
        return self._result

      def cancel(self):
        self.cancelled = True

    futures = []

    class MockExecutor:

      def __init__(self, *args, **kwargs):
        pass

      def __enter__(self):
        return self

      def __exit__(self, *args, **kwargs):
        pass

      def submit(self, unused_func, *args, **unused_kwargs):
        target = args[0] if args else b''
        start = args[1] if len(args) > 1 else 0
        end = args[2] if len(args) > 2 else len(target)
        slice_bytes = target[start:end] if isinstance(target, bytes) else target

        if isinstance(slice_bytes, bytes):
          has_os = b'system' in slice_bytes
          has_never = b'never_reached' in slice_bytes
        else:
          has_os = 'system' in slice_bytes
          has_never = 'never_reached' in slice_bytes

        if has_os:
          name = 'unsafe'
          res = {'os.system', 'posix.system'}
        elif has_never:
          name = 'never_reached'
          res = {'never_reached'}
        else:
          name = 'safe'
          res = {'safe'}

        f = MockFuture(res, name)
        futures.append(f)
        return f

    def mock_as_completed(fs):
      # Ensure the unsafe future is completed first to trigger abort
      sorted_fs = sorted(fs, key=lambda f: 0 if f.name == 'unsafe' else 1)
      return sorted_fs

    with (
        mock.patch.object(safer_pickle.constants, 'MIN_SIZE_FOR_CHUNKING', 10),
        mock.patch('concurrent.futures.ThreadPoolExecutor', MockExecutor),
        mock.patch(
            'concurrent.futures.as_completed', side_effect=mock_as_completed
        ),
    ):
      temp_dir = self.create_tempdir()
      chunk0 = b'cbuiltins\nprint\n' + b'A' * 400
      chunk1 = b'cposix\nsystem\n' + b'B' * 400
      chunk2 = b'cbuiltins\nnever_reached\n' + b'C' * 400
      content = chunk0 + chunk1 + chunk2
      temp_file = temp_dir.create_file('temp.pkl', content=content)

      results = safer_pickle.generate_ops_from_file(
          temp_file.full_path, pickle_length=len(content), fail_fast=True
      )

      # Assert that 'os.system' is in the results
      self.assertIn('os.system', results)

      # The never_reached future should have been cancelled
      never_reached_futures = [f for f in futures if f.name == 'never_reached']
      self.assertTrue(never_reached_futures)
      self.assertTrue(never_reached_futures[0].cancelled)


class RegressionTests(_CommandGuardTestCase):

  def setUp(self):
    super().setUp()
    self.patcher1 = mock.patch.object(
        safer_pickle, 'security_scan', make_security_scan_wrapper(True)
    )
    self.patcher2 = mock.patch.object(
        safer_pickle, 'genops_scan', make_genops_scan_wrapper(True)
    )
    self.patcher1.start()
    self.patcher2.start()
    safer_pickle.hook_pickle()

  def tearDown(self):
    safer_pickle.unhook_pickle()
    self.patcher1.stop()
    self.patcher2.stop()
    super().tearDown()

  @mock.patch.object(safer_pickle, 'DEBUG_MODE', False)
  def test_magic_byte_bypass(self):
    with open(
        'testdata/regression_tests/magic_byte_bypass.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @mock.patch.object(safer_pickle, 'DEBUG_MODE', False)
  def test_large_binbytes_malicious(self):
    with open(
        'testdata/extra_bypasses/large_binbytes_malicious.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        with self._assert_no_command_execution():
          pickle.loads(data_bytes)

  @mock.patch.object(
      safer_pickle.config,
      'get_allow_list',
      return_value={'zlib', 'builtins', 'exec', 'builtins.exec'},
  )
  @mock.patch.object(safer_pickle, 'DEBUG_MODE', False)
  def test_large_binbytes_scanning_speed(self, unused_mock_get_allow_list):
    with open(
        'testdata/extra_bypasses/large_binbytes_exec.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
      start_time = time.time()

      f_stdout = io.StringIO()
      with contextlib.redirect_stdout(f_stdout):
        pickle.loads(data_bytes, report_only=True)

      duration = time.time() - start_time

      self.assertIn('EXPLOIT RUNNING', f_stdout.getvalue())

      # Scanning this should take < 1s (typically < 0.1s with seeking)
      self.assertLess(duration, 1.0)

  def test_benign_pickle_with_leading_garbage_unpickles_successfully(self):
    # JPEG magic bytes followed by a benign pickle of a dict
    benign_data = pickle.dumps({'status': 'OK'})
    payload = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00' + benign_data

    res = pickle.loads(payload)
    self.assertEqual(res, {'status': 'OK'})

    stream = io.BytesIO(payload)
    res_stream = pickle.load(stream)
    self.assertEqual(res_stream, {'status': 'OK'})

  def test_truncated_pickle_with_offset_is_flagged_unsafe(self):
    payload = b'\x89PNG\r\n\x1a\n\x80\x04}(J\x01'

    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError,
        'Parser error during security scan',
    ):
      pickle.loads(payload, strict_check=True)

  @parameterized.named_parameters(
      dict(
          testcase_name='ordered_dict',
          bytecode=b'ccollections\nOrderedDict\n)R}(Vkey\nVval\nub.',
      ),
      dict(
          testcase_name='default_dict',
          bytecode=b'ccollections\ndefaultdict\n)R}(Vkey\nVval\nub.',
      ),
      dict(
          testcase_name='plain_dict',
          bytecode=b'}}Vkey\nVval\nsb.',
      ),
  )
  def test_build_opcode_on_dictionaryless_types_simulates_cleanly(
      self, bytecode
  ):
    scan_results = safer_pickle.picklemagic_scan(bytecode)
    self.assertNotIn(
        'sandbox_unpickling_error', scan_results.suspicious_results
    )
    self.assertNotIn('unsafe_state_assignment', scan_results.suspicious_results)
    self.assertEmpty(scan_results.unsafe_results)

  def test_build_opcode_on_plain_dict_blocks_fake_class_state(self):
    stream = io.BytesIO(b'}}Vkey\nVval\nsb.')
    unpickler = safer_pickle.SaferUnpickler(stream)
    result = unpickler.load()
    self.assertEqual(result, {'key': 'val'})
    self.assertFalse(unpickler.has_blocked_unsafe_build_instr)

    malicious_bytecode = b'}}\x8c\x03key\x8c\x02os\x8c\x06system\x93sb.'
    with self._assert_no_command_execution():
      scan_results = safer_pickle.picklemagic_scan(malicious_bytecode)

    self.assertIn('os.system', scan_results.unsafe_results)
    self.assertIn('unsafe_state_assignment', scan_results.suspicious_results)

  def test_vocab_disconnected_words_not_flagged(self):
    payload = {
        'metadata': {
            'status': 'open',
            'read_mode': 'streaming',
            'apply_transform': True,
            'decode_strategy': 'greedy',
        },
        'vocab': ['system', 'os', 'open', 'read'],
    }
    data_bytes = pickle.dumps(payload)

    res = pickle.loads(data_bytes)  # pylint: disable=g-unsafe-pickle-load
    self.assertEqual(res['metadata']['status'], 'open')
    self.assertEqual(res['metadata']['read_mode'], 'streaming')
    self.assertTrue(res['metadata']['apply_transform'])
    self.assertEqual(res['metadata']['decode_strategy'], 'greedy')
    self.assertIn('system', res['vocab'])
    self.assertIn('os', res['vocab'])
    self.assertIn('open', res['vocab'])
    self.assertIn('read', res['vocab'])

    res_stream = pickle.load(io.BytesIO(data_bytes))  # pylint: disable=g-unsafe-pickle-load
    self.assertEqual(res_stream['metadata']['status'], 'open')

    scan_res = safer_pickle.genops_scan(data_bytes)
    self.assertEmpty(scan_res.unsafe_results)
    self.assertEmpty(scan_res.suspicious_results)

  def test_stack_global_memoized_reconstruction(self):
    # Bytecode for timeit.timeit using MEMOIZE and BINGET
    # \x80\x04\x8c\x06timeit\x94h\x00\x93(S'pass'\ntR.
    payload = b"\x80\x04\x8c\x06timeit\x94h\x00\x93(S'pass'\ntR."
    with self._assert_no_command_execution():
      with self.assertRaises(safer_pickle.UnsafePickleDetectedError):
        pickle.loads(payload)  # pylint: disable=g-unsafe-pickle-load

  def test_legacy_global_space_reconstruction(self):
    # Protocol 0 space-separated GLOBAL opcode
    payload = b"cposix\nsystem\n(S'id'\ntR."
    with self._assert_no_command_execution():
      with self.assertRaises(safer_pickle.UnsafePickleDetectedError):
        pickle.loads(payload)  # pylint: disable=g-unsafe-pickle-load

  def test_reflection_gadget_operator_attrgetter_blocked(self):
    with open(
        'testdata/picklescan_tests/malicious12.pkl',
        'rb',
    ) as f:
      data_bytes = f.read()
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE|SUSPICIOUS'
      ):
        pickle.loads(data_bytes)  # pylint: disable=g-unsafe-pickle-load

  def test_safer_unpickler_fast_binary_skipping(self):
    binbytes8_payload = (
        b'\x80\x04\x8e' + (5000).to_bytes(8, 'little') + (b'x' * 5000) + b'.'
    )
    unpickler = safer_pickle.SaferUnpickler(io.BytesIO(binbytes8_payload))
    self.assertEqual(unpickler.load(), b'')

    bytearray8_payload = (
        b'\x80\x04\x96' + (5000).to_bytes(8, 'little') + (b'y' * 5000) + b'.'
    )
    unpickler_ba = safer_pickle.SaferUnpickler(io.BytesIO(bytearray8_payload))
    self.assertEqual(unpickler_ba.load(), bytearray())

  def test_safer_unpickler_negative_length_raises_error(self):
    unpickler = safer_pickle.SaferUnpickler(io.BytesIO(b'\x80\x04}.'))
    with self.assertRaises(pickle.UnpicklingError):
      unpickler._skip_or_read_bytes(-1)

  @parameterized.named_parameters(
      ('truncated_large_seek', 8192, 100),
      ('truncated_small_read', 100, 10),
  )
  def test_safer_unpickler_truncated_binbytes_raises_eof(
      self, declared_len, actual_len
  ):
    payload = (
        b'\x80\x04B' + declared_len.to_bytes(4, 'little') + (b'a' * actual_len)
    )
    with self.assertRaises(EOFError):
      safer_pickle.SaferUnpickler(io.BytesIO(payload)).load()

  def test_safer_unpickler_single_string_slots_inspection(self):
    class SingleSlotHolder:  # pylint: disable=single-string-used-for-slots
      __slots__ = 'single_slot'

      def __init__(self, val):
        self.single_slot = val

    unpickler = safer_pickle.SaferUnpickler(io.BytesIO(b'\x80\x04}.'))
    fake_cls = unpickler.find_class('custom_untrusted_mod', 'FakeNested')
    fake_instance = object.__new__(fake_cls)
    holder = SingleSlotHolder(fake_instance)

    self.assertTrue(unpickler._state_contains_fake_class(holder))

  def test_safer_unpickler_blocks_non_class_and_suspicious_fake_classes(self):
    factory = safer_pickle.picklemagic.FakeClassFactory(
        [], safer_pickle.picklemagic.FakeWarning
    )
    unpickler = safer_pickle.SaferUnpickler(
        io.BytesIO(b'\x80\x04}.'),
        class_factory=factory,
    )
    fake_numpy_size = factory('size', 'numpy')
    fake_numpy_builtins = factory('__builtins__', 'numpy')
    fake_failed_reduce = factory('failed_reduce', 'picklemagic')()
    fake_numpy_ndarray = factory('ndarray', 'numpy')

    self.assertTrue(unpickler._state_contains_fake_class(fake_numpy_size))
    self.assertTrue(unpickler._state_contains_fake_class(fake_numpy_builtins))
    self.assertTrue(unpickler._state_contains_fake_class(fake_failed_reduce))
    self.assertFalse(unpickler._state_contains_fake_class(fake_numpy_ndarray))

    # Bytecode for:
    #   from numpy import size, __builtins__
    #   size.shape = __builtins__
    #   size(size, 'eval')('__import__("os").system("id")')
    exploit_bytecode = (
        b'\x80\x04'
        b'\x8c\x05numpy\x8c\x04size\x93\x94'
        b'}\x8c\x05shape'
        b'\x8c\x05numpy\x8c\x0c__builtins__\x93'
        b'sb'
        b'h\x00\x8c\x04eval\x86R'
        b"\x8c\x1c__import__('os').system('id')\x85R."
    )
    pm_results = safer_pickle.picklemagic_scan(exploit_bytecode)
    self.assertIn('unsafe_state_assignment', pm_results.suspicious_results)
    genops_results = safer_pickle.genops_scan(exploit_bytecode)
    self.assertNotEmpty(genops_results.unsafe_results)
    self.assertIn('numpy.__builtins__', genops_results.suspicious_results)
    with self._assert_no_command_execution():
      with self.assertRaises(safer_pickle.UnsafePickleDetectedError):
        pickle.loads(exploit_bytecode)  # pylint: disable=g-unsafe-pickle-load

  def test_stream_in_memory_chunking_and_prefixed_offset_scan(self):
    temp_dir = self.create_tempdir()
    safe_file = os.path.join(temp_dir.full_path, 'stream_safe.pkl')
    safe_bytes = pickle.dumps({'key': 'value', 'numbers': list(range(50))})
    with open(safe_file, 'wb') as f:
      f.write(safe_bytes)

    with mock.patch.object(safer_pickle.constants, 'MIN_SIZE_FOR_CHUNKING', 16):
      with open(safe_file, 'rb') as stream:
        scores = safer_pickle._security_scan_internal(
            stream,
            force_scan=False,
            fail_fast=False,
            check_magic_bytes=True,
        )
        self.assertEqual(stream.tell(), 0)
      self.assertEqual(scores['unsafe'], 0)

    prefixed_file = os.path.join(temp_dir.full_path, 'prefixed.pkl')
    with open(prefixed_file, 'wb') as f:
      f.write(b'\x00\x00\x00\x00' + safe_bytes)
    with open(prefixed_file, 'rb') as stream:
      scores_prefixed = safer_pickle._security_scan_internal(
          stream,
          force_scan=True,
          fail_fast=False,
          check_magic_bytes=True,
      )
    self.assertEqual(scores_prefixed['unsafe'], 0)

  def test_genops_scan_accepts_stream_without_explicit_length(self):
    safe_bytes = pickle.dumps({'alpha': [1, 2, 3], 'beta': 'ok'})
    prefixed_stream = io.BytesIO(b'HEAD' + safe_bytes)
    prefixed_stream.seek(4)

    with mock.patch.object(safer_pickle.constants, 'MIN_SIZE_FOR_CHUNKING', 8):
      chunked_res = safer_pickle.genops_scan(prefixed_stream)
      self.assertEqual(prefixed_stream.tell(), 4)
      self.assertEmpty(chunked_res.unsafe_results)
      self.assertEmpty(chunked_res.suspicious_results)

    class _UnseekableBytesReader(io.RawIOBase):

      def __init__(self, data: bytes):
        super().__init__()
        self._buf = io.BytesIO(data)

      def readable(self) -> bool:
        return True

      def seekable(self) -> bool:
        return False

      def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    unseekable_res = safer_pickle.genops_scan(
        _UnseekableBytesReader(safe_bytes)
    )
    self.assertEmpty(unseekable_res.unsafe_results)
    self.assertEmpty(unseekable_res.suspicious_results)

  @parameterized.named_parameters(
      dict(
          testcase_name='shutil_chown',
          module='shutil',
          attr='chown',
          arg='/tmp/nonexistent_saferpickle_test',
      ),
      dict(
          testcase_name='ftplib_ftp',
          module='ftplib',
          attr='FTP',
          arg='127.0.0.1',
      ),
      dict(
          testcase_name='sqlite3_connect',
          module='sqlite3',
          attr='connect',
          arg=':memory:',
      ),
      dict(
          testcase_name='zipfile_pyzipfile',
          module='zipfile',
          attr='PyZipFile',
          arg='/tmp/nonexistent.zip',
      ),
  )
  def test_undenylisted_malicious_gadgets_blocked_as_unknown(
      self, module, attr, arg
  ):
    """Verifies un-denylisted callables are blocked as UNKNOWN."""
    standalone_payload = f'c{module}\n{attr}\n(V{arg}\ntR.'.encode('utf-8')
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(standalone_payload)
      with self.assertRaises(safer_pickle.StrictCheckError):
        pickle.loads(standalone_payload, strict_check=True)

    cli_res = safer_pickle_cli.security_scan_with_justifications(
        standalone_payload
    )
    self.assertEqual(cli_res['classification'], 'unknown')
    self.assertIn(f'{module}.{attr}', cli_res['justification'])

    # Import-stuffed payload: 10 SAFE imports + 1 unapproved unknown gadget
    safe_imports_prefix = (
        b'\x80\x04('
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b'\x8c\x0bcollections\x8c\x05deque\x93'
        b'\x8c\x0bcollections\x8c\x0bdefaultdict\x93'
        b'\x8c\x0bcollections\x8c\x07Counter\x93'
        b'\x8c\x08datetime\x8c\x08datetime\x93'
        b'\x8c\x08datetime\x8c\x04date\x93'
        b'\x8c\x08datetime\x8c\x04time\x93'
        b'\x8c\x08datetime\x8c\x09timedelta\x93'
        b'\x8c\x05numpy\x8c\x07ndarray\x93'
        b'\x8c\x05numpy\x8c\x05dtype\x93'
    )
    stuffed_payload = (
        safe_imports_prefix
        + f'c{module}\n{attr}\n(V{arg}\ntR'.encode('utf-8')
        + b't.'
    )
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(stuffed_payload)

    cli_stuffed = safer_pickle_cli.security_scan_with_justifications(
        stuffed_payload
    )
    self.assertEqual(cli_stuffed['classification'], 'unknown')

  def test_approved_root_unknown_function_threshold_and_strict_mode(self):
    """Tests that unknown functions in approved roots are blocked."""
    # 1 unknown function in numpy ('numpy.polyval') with 0 safe imports
    unapproved_fn_payload = b'cnumpy\npolyval\n((I1\ntI2\ntR.'
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
    ):
      pickle.loads(unapproved_fn_payload)

    cli_res = safer_pickle_cli.security_scan_with_justifications(
        unapproved_fn_payload
    )
    self.assertEqual(cli_res['classification'], 'unknown')

    # Unknown helper in approved root (numpy.polyval) stuffed with 3 safe
    # imports is blocked in both default mode and strict_check=True, whereas
    # explicitly approved numpy.mean (numpy_mean.pkl) loads cleanly.
    stuffed_unapproved_fn_payload = (
        b'\x80\x04('
        b'\x8c\x05numpy\x8c\x07ndarray\x93'
        b'\x8c\x05numpy\x8c\x05dtype\x93'
        b'\x8c\x15numpy.core.multiarray\x8c\x0c_reconstruct\x93'
        b'cnumpy\npolyval\n((I1\ntI2\ntR'
        b't.'
    )
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
    ):
      pickle.loads(stuffed_unapproved_fn_payload)
    with self.assertRaises(safer_pickle.StrictCheckError):
      pickle.loads(stuffed_unapproved_fn_payload, strict_check=True)

    with open(
        'testdata/numpy_mean.pkl', 'rb'
    ) as f:
      numpy_mean_bytes = f.read()
    self.assertEqual(pickle.loads(numpy_mean_bytes), 2.0)

    # Inert string literals do not populate unknown_results in strict mode.
    inert_dict_bytes = pickle.dumps({
        'custom_layer_alpha': 'relu_activation',
        'vocabulary_token_xyz': 'embedding_matrix',
        'hyperparameter_beta': [1, 2, 3],
    })
    self.assertEmpty(safer_pickle.genops_scan(inert_dict_bytes).unknown_results)
    self.assertIsNotNone(pickle.loads(inert_dict_bytes, strict_check=True))

  def test_ext1_opcode_unsafe_blocked(self):
    """Tests that EXT1 resolving to an UNSAFE symbol is blocked."""
    copyreg.add_extension('posix', 'system', 181)
    self.addCleanup(copyreg.remove_extension, 'posix', 'system', 181)

    ext1_unsafe = (
        b'\x80\x04\x82' + (181).to_bytes(1, 'little') + b'\x8c\x02id\x85R.'
    )
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(ext1_unsafe)
      with self.assertRaises(safer_pickle.StrictCheckError):
        pickle.loads(ext1_unsafe, strict_check=True)

  def test_ext2_and_unregistered_ext4_opcodes_unknown_blocked(self):
    """Tests that EXT2 resolving to UNKNOWN and unregistered EXT4 are blocked."""
    copyreg.add_extension('shutil', 'chown', 1181)
    self.addCleanup(copyreg.remove_extension, 'shutil', 'chown', 1181)

    ext2_unknown = b'\x80\x04\x83' + (1181).to_bytes(2, 'little') + b'\x94.'
    unregistered_ext4 = (
        b'\x80\x04\x84' + (777777).to_bytes(4, 'little', signed=True) + b'\x94.'
    )

    for payload in (ext2_unknown, unregistered_ext4):
      with self._assert_no_command_execution():
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
        ):
          pickle.loads(payload)
        with self.assertRaises(safer_pickle.StrictCheckError):
          pickle.loads(payload, strict_check=True)

  def test_protocol0_put_get_stack_global_evasion_blocked(self):
    """Tests Protocol 0 PUT and GET reassembling STACK_GLOBAL targets."""
    proto0_evasion_unsafe = (
        b"S'posix'\np0\n0S'system'\np1\n0g0\ng1\n\x93(S'id'\ntR."
    )
    proto0_evasion_unknown = b"S'shutil'\np0\n0S'chown'\np1\n0g0\ng1\n\x93."

    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(proto0_evasion_unsafe)
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(proto0_evasion_unknown)

  def test_persid_and_binpersid_opcodes_blocked(self):
    """Tests that PERSID and BINPERSID opcodes are classified and blocked."""
    persid_unknown = b'\x80\x04Pexternal_db_record_42\n\x94.'
    binpersid_unknown = b'\x80\x04\x8c\x15external_db_record_42Q\x94.'
    persid_unsafe = b'\x80\x04Pos.system\n\x94.'

    for payload in (persid_unknown, binpersid_unknown):
      with self._assert_no_command_execution():
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
        ):
          pickle.loads(payload)
        with self.assertRaises(safer_pickle.StrictCheckError):
          pickle.loads(payload, strict_check=True)

    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(persid_unsafe)

  def test_build_opcode_dangerous_state_keys_without_reduce(self):
    """Tests that BUILD (0x62) setting __setstate__ hooks is blocked."""
    build_hook_payload = (
        b'\x80\x04'
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b')\x81'
        b'}\x8c\x0c__setstate__\x8c\x07payloadsb.'
    )
    pm_res = safer_pickle.picklemagic_scan(build_hook_payload)
    self.assertEmpty(pm_res.unsafe_results)
    self.assertIn('unsafe_state_assignment', pm_res.suspicious_results)

    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        pickle.loads(build_hook_payload)
      with self.assertRaises(safer_pickle.StrictCheckError):
        pickle.loads(build_hook_payload, strict_check=True)

  def test_safe_constructor_colliding_string_args_not_flagged(self):
    """Tests safe constructors receiving module-colliding string arguments."""
    safe_container = {
        'requests',
        'commands',
        'ssl',
        'eval',
        'operator',
        'code.org',
    }
    payload = pickle.dumps(safe_container, protocol=2)
    scores = safer_pickle.security_scan(payload)

    self.assertEqual(scores['unsafe'], 0)
    self.assertEqual(scores['suspicious'], 0)

  def test_unknown_custom_class_pydantic_dict_state_not_flagged(self):
    """Tests Pydantic v2 style __dict__ state on unknown FakeClass instances."""
    custom_state_bytecode = (
        b'\x80\x04'
        b'\x8c\x12custom_user_module\x8c\x0bCustomModel\x93'
        b')\x81'
        b'}\x8c\x08__dict__}\x8c\x08requests\x8c\x02okssb'
        b'\x8c\x03key\x8c\x03vals'
        b'\x8c\x04itema.'
    )
    pm_res = safer_pickle.picklemagic_scan(custom_state_bytecode)

    self.assertEmpty(pm_res.unsafe_results)
    self.assertEmpty(pm_res.suspicious_results)
    self.assertIn('custom_user_module.CustomModel', pm_res.unknown_results)

  def test_nested_dict_state_dangerous_dunder_key_blocked(self):
    """Tests dangerous dunder keys nested inside __dict__ state are blocked."""
    nested_evil_state_bytecode = (
        b'\x80\x04'
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b')\x81'
        b'}\x8c\x08__dict__}\x8c\n__reduce__\x8c\x04evilssb.'
    )
    pm_evil = safer_pickle.picklemagic_scan(nested_evil_state_bytecode)

    self.assertEmpty(pm_evil.unsafe_results)
    self.assertIn('unsafe_state_assignment', pm_evil.suspicious_results)

  def test_self_protected_symbols_blocked_even_when_allowlisted(self):
    """Tests self-protected SaferPickle symbols ignore user allow_list."""
    temp_dir = self.create_tempdir()
    cfg_file = temp_dir.create_file(
        'config.json',
        content=(
            '{"safer_pickle": {"allow_list": ["safer_pickle", "saferpickle",'
            ' "corrupy", "picklemagic", "config", "saferpickle.lib.config"]}}'
        ),
    )
    safer_pickle.config.set_config_path(cfg_file.full_path)
    self.addCleanup(safer_pickle.config.set_config_path, None)

    protected_payloads = (
        b'csaferpickle.safer_pickle\nunhook_pickle\n)R.',
        b'csaferpickle.lib.config\nset_config_path\n(\x8c\x09/tmp/x.jsontR.',
    )

    for payload in protected_payloads:
      with self._assert_no_command_execution():
        scores = safer_pickle.security_scan(payload)
        self.assertGreater(scores['unsafe'], 0)
        self.assertNotEmpty(
            safer_pickle.picklemagic_scan(payload).unsafe_results
        )
        self.assertNotEmpty(safer_pickle.genops_scan(payload).unsafe_results)
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)

  def test_concurrent_get_class_instantiations_isolates_threads(self):
    """Tests concurrent scans do not cross-contaminate picklemagic logs."""
    safe_bytes = pickle.dumps({'items': [1, 2, 3]}, protocol=4)
    unsafe_bytes = b"cposix\nsystem\n(S'id'\ntR."

    def scan_worker(index: int) -> dict[str, int]:
      target = safe_bytes if index % 2 == 0 else unsafe_bytes
      return safer_pickle.security_scan(target)

    with self._assert_no_command_execution():
      with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(scan_worker, range(40)))

    for index, scores in enumerate(results):
      if index % 2 == 0:
        self.assertEqual(scores['unsafe'], 0)
        self.assertEqual(scores['suspicious'], 0)
      else:
        self.assertGreater(scores['unsafe'], 0)

  @parameterized.named_parameters(
      dict(testcase_name='read_tail', length=5000),
      dict(testcase_name='seek_tail', length=10000),
  )
  def test_binstring_exceeding_4096_bytes_scans_cleanly(self, length: int):
    """Tests BINSTRING payloads larger than 4096 bytes skip tails cleanly."""
    payload = b'T' + length.to_bytes(4, 'little') + (b'a' * length) + b'.'

    pm_res = safer_pickle.picklemagic_scan(payload)
    self.assertEmpty(pm_res.unsafe_results)
    self.assertEmpty(pm_res.suspicious_results)
    self.assertEmpty(pm_res.unknown_results)

    scores = safer_pickle.security_scan(payload)
    self.assertEqual(scores['unsafe'], 0)
    self.assertEqual(scores['suspicious'], 0)

  def test_cyclic_build_state_dict_terminates_cleanly(self):
    """Tests self-referential __dict__ state mappings do not loop infinitely."""
    cyclic_benign_bytecode = (
        b'\x80\x04ccollections\nOrderedDict\n)R}q\x01\x8c\x08__dict__h\x01sb.'
    )
    pm_benign = safer_pickle.picklemagic_scan(cyclic_benign_bytecode)
    self.assertEmpty(pm_benign.unsafe_results)
    self.assertEmpty(pm_benign.suspicious_results)
    self.assertEmpty(pm_benign.unknown_results)

    cyclic_dangerous_bytecode = (
        b'\x80\x04'
        b'ccollections\nOrderedDict\n)R'
        b'}q\x01'
        b'(\x8c\x08__dict__h\x01\x8c\n__reduce__\x8c\x01xu'
        b'b.'
    )
    pm_evil = safer_pickle.picklemagic_scan(cyclic_dangerous_bytecode)
    self.assertEmpty(pm_evil.unsafe_results)
    self.assertIn('unsafe_state_assignment', pm_evil.suspicious_results)

  def test_metadata_attr_on_unsafe_or_unknown_module_blocked(self):
    """Tests metadata attributes on unsafe or unknown modules are blocked.

    Returns:
      None.
    """
    unsafe_doc_payload = b'cos\n__doc__\n.'
    unknown_doc_payload = b'cunrecognized_custom_pkg\n__doc__\n.'

    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(unsafe_doc_payload)
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        pickle.loads(unknown_doc_payload)

      cli_unsafe = safer_pickle_cli.security_scan_with_justifications(
          unsafe_doc_payload
      )
      self.assertEqual(cli_unsafe['classification'], 'unsafe')

      cli_unknown = safer_pickle_cli.security_scan_with_justifications(
          unknown_doc_payload
      )
      self.assertEqual(cli_unknown['classification'], 'suspicious')
      self.assertIn(
          'unrecognized_custom_pkg.__doc__', cli_unknown['justification']
      )

  def test_load_reduce_does_not_cache_safe_class_with_non_cacheable_args(self):
    """Tests `load_reduce` skips `_cached_safe_instance` on non-cacheable args.

    Returns:
      None.
    """
    payload = (
        b'\x80\x04'
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b'\x8c\x17unrecognized_custom_pkg\x8c\x09CustomVal\x93)\x81'
        b'\x85R.'
    )
    factory = safer_pickle.picklemagic.FakeClassFactory(
        [], safer_pickle._SaferFakeWarning
    )
    unpickler = safer_pickle.SaferUnpickler(
        io.BytesIO(payload),
        class_factory=factory,
        safe_modules=safer_pickle.constants.SAFE_STRINGS,
        unsafe_modules=safer_pickle.constants.UNSAFE_STRINGS,
    )
    factory.default.unpickler = unpickler
    unpickler.load()

    ordered_dict_cls = unpickler.find_class('collections', 'OrderedDict')
    self.assertNotIn('_cached_safe_instance', ordered_dict_cls.__dict__)


class ReportedVulnerabilityBypassesTest(BaseTestLoad):
  """Regression tests for vulnerability reports and variants."""

  @parameterized.named_parameters(
      dict(
          testcase_name='hooked_loads_positional_fix_imports',
          call_fn=lambda payload: pickle.loads(
              payload, True, 'ASCII', 'strict'
          ),
      ),
      dict(
          testcase_name='hooked_load_positional_fix_imports',
          call_fn=lambda payload: pickle.load(io.BytesIO(payload), True),
      ),
      dict(
          testcase_name='safer_pickle_load_positional_map_location',
          call_fn=lambda payload: safer_pickle.load(io.BytesIO(payload), 'cpu'),
      ),
      dict(
          testcase_name='safer_pickle_unpickler_keyword_fix_imports',
          call_fn=lambda payload: safer_pickle.Unpickler(
              io.BytesIO(payload), fix_imports=True
          ).load(),
      ),
  )
  def test_positional_and_unpickler_args_do_not_bypass_scan(self, call_fn):
    """Verifies positional and keyword loader args never bypass scanning.

    Args:
      call_fn: Loader callable invoked on the malicious pickle payload.

    Returns:
      None.
    """
    malicious_payload = b"cos\nsystem\n(S'echo PWNED'\ntR."

    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        call_fn(malicious_payload)

  def test_safer_pickle_unpickler_extra_positional_arg_raises_type_error(self):
    """Verifies extra positional args to `Unpickler` raise `TypeError`.

    Returns:
      None.
    """
    malicious_payload = b"cos\nsystem\n(S'echo PWNED'\ntR."

    with self._assert_no_command_execution():
      with self.assertRaises(TypeError):
        safer_pickle.Unpickler(io.BytesIO(malicious_payload), True)

  def test_benign_positional_args_forwarded_to_loaders(self):
    """Verifies benign positional arguments forward to `dill` and `joblib`.

    Ensures hooked `dill.loads` and `joblib.load` forward legitimate positional
    options (including path-streamed `joblib.load`) cleanly.

    Returns:
      None.
    """
    benign_payload = pickle.dumps({'ok': 123}, protocol=3)
    temp_file = self.create_tempfile(content=benign_payload)

    self.assertEqual(dill.loads(benign_payload, False), {'ok': 123})
    self.assertEqual(
        joblib.load(io.BytesIO(benign_payload), None),
        {'ok': 123},
    )
    self.assertEqual(joblib.load(temp_file.full_path, None), {'ok': 123})

  def test_fail_fast_and_safe_padding_do_not_dilute_unsafe(self):
    """Tests that fail_fast=True and safe padding never dilute os.system.

    Verifies both direct and safe-padded `os.system` payloads classify as
    `UNSAFE` under both `fail_fast=True` and `fail_fast=False`.

    Returns:
      None.
    """
    raw_os_system = (
        b'\x80\x04\x95%\x00\x00\x00\x00\x00\x00\x00'
        b'\x8c\x02os\x94\x8c\x06system\x94\x93\x94'
        b'\x8c\x0fecho PWNED_5860\x94\x85\x94R\x94.'
    )
    safe_padding = (
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b'\x8c\x0bcollections\x8c\x05deque\x93'
        b'\x8c\x05numpy\x8c\x07ndarray\x93'
    ) * 15
    padded_os_system = (
        b'\x80\x04('
        + safe_padding
        + b'\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85Rt.'
    )

    for payload in (raw_os_system, padded_os_system):
      with self._assert_no_command_execution():
        scores_fast = safer_pickle.security_scan(payload, fail_fast=True)
        scores_full = safer_pickle.security_scan(payload, fail_fast=False)
        self.assertGreater(scores_fast['unsafe'], 0)
        self.assertGreater(scores_full['unsafe'], 0)
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)

    with mock.patch.object(
        safer_pickle.config,
        'get_allow_list',
        return_value={'posix.system.sub'},
    ):
      self.assertTrue(
          safer_pickle.utils.is_unsafe_for_fail_fast('posix.system')
      )
      self.assertFalse(
          safer_pickle.utils.is_unsafe_for_fail_fast('posix.system.sub')
      )

  def test_classify_precedence_and_pydoc_pipe_pager_blocked(self):
    """Tests classify_symbol precedence and pydoc/_osx_support/test gadgets.

    Verifies dangerous inner modules under safe roots and pager/runner gadgets
    classify as `UNSAFE` and raise `UnsafePickleDetectedError`.

    Returns:
      None.
    """
    self.assertEqual(
        safer_pickle.utils.classify_symbol('torch.serialization.os.system'),
        safer_pickle.utils.Classification.UNSAFE,
    )
    self.assertEqual(
        safer_pickle.utils.classify_symbol('os.__doc__'),
        safer_pickle.utils.Classification.UNSAFE,
    )

    gadget_payloads = (
        b'cpydoc\npipe_pager\n(Vdata\nVecho PWNED\ntR.',
        b'cpydoc\ntempfile_pager\n(Vdata\nVecho PWNED\ntR.',
        b'cpydoc\nttypager\n(Vdata\ntR.',
        b'c_osx_support\n_read_output\n(Vecho PWNED\ntR.',
        b'ctest.support\nrun_code\n(Vprint(1)\nV<string>\ntR.',
    )

    for payload in gadget_payloads:
      with self._assert_no_command_execution():
        self.assertGreater(safer_pickle.security_scan(payload)['unsafe'], 0)
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)
        with self.assertRaises(safer_pickle.StrictCheckError):
          pickle.loads(payload, strict_check=True)

  def test_no_pre_verdict_code_execution_during_scan(self):
    """Tests that security_scan/strict_security_scan never invoke live funcs.

    Verifies `functools.partial` and `copyreg._reconstructor` chains targeting
    `os.system` are blocked statically without invoking `os.system`.

    Returns:
      None.
    """
    partial_chain = b'cfunctools\npartial\n(cos\nsystem\nVecho PWNED\ntR(tR.'
    reconstructor_chain = (
        b'ccopyreg\n_reconstructor\n(cos\nsystem\ncbuiltins\nstr\n'
        b'Vecho PWNED\ntR.'
    )

    for payload in (partial_chain, reconstructor_chain):
      with self._assert_no_command_execution():
        scores = safer_pickle.security_scan(payload)
        self.assertGreater(scores['unsafe'], 0)
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)

  def test_short_binstring_binstring_and_escaped_string_blocked(self):
    """Tests 0x55 SHORT_BINSTRING, 0x54 BINSTRING, and 0x53 hex/octal STRING.

    Verifies binary string opcodes and hex/octal-escaped protocol 0 strings
    feeding `STACK_GLOBAL` are decoded and classified as `UNSAFE`.

    Returns:
      None.
    """
    pocs = (
        b'\x80\x04U\x0c_osx_supportU\x0c_read_output\x93U\necho PWNED\x85R.',
        (
            b'\x80\x04T\x02\x00\x00\x00osT\x06\x00\x00\x00system\x93U\n'
            b'echo PWNED\x85R.'
        ),
        (
            b"S'\\x6f\\x73'\nS'\\x73\\x79\\x73\\x74\\x65\\x6d'\n\x93"
            b"(S'echo PWNED'\ntR."
        ),
        (
            b"S'\\157\\163'\nS'\\163\\171\\163\\164\\145\\155'\n\x93"
            b"(S'echo PWNED'\ntR."
        ),
        b'\x80\x04U\x05a.b.c\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.',
    )

    for payload in pocs:
      with self._assert_no_command_execution():
        genops_res = safer_pickle.genops_scan(payload)
        self.assertNotEmpty(genops_res.unsafe_results)
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)
        with self.assertRaises(safer_pickle.StrictCheckError):
          pickle.loads(payload, strict_check=True)

  def test_encoding_differential_and_method_hijack_blocked(self):
    """Tests encoding differential and APPEND/ADDITEMS method hijacks.

    Verifies `latin1` vs `UNICODE` key collisions and `append`/`add` method
    overrides via `BUILD` state dictionaries are flagged as `UNSAFE`.

    Returns:
      None.
    """
    pocs = (
        # Encoding differential and APPEND method hijack PoC
        (
            b'\x80\x04cemail.message\nMessage\n)R(d'
            b'Vappend\nccollections\ndeque\ns'
            b"S'append'\nclogging.config\ndictConfig\nsb"
            b'(dVversion\nI1\nsba.'
        ),
        # Reverse key order: S'append' malicious followed by Vappend primitive
        (
            b'\x80\x04ccollections\nOrderedDict\n)R(d'
            b"S'append'\nc_osx_support\n_read_output\ns"
            b'Vappend\nVbenign_primitive\nsb'
            b'Vecho PWNED\na.'
        ),
        # Safe FakeClass container (OrderedDict) used as BUILD state via SETITEM
        (
            b'\x80\x04ccollections\nOrderedDict\n)R'
            b'ccollections\nOrderedDict\n)R'
            b'Vappend\nc_osx_support\n_read_output\nsb'
            b'Vecho PWNED\na.'
        ),
        # ADDITEMS (0x90) method hijack via 'add' attribute in BUILD state
        (
            b'\x80\x04ccollections\nOrderedDict\n)R'
            b'}\x8c\x03add\x8c\x02os\x8c\x06system\x93sb'
            b'(\x8c\x02id\x90.'
        ),
    )

    for payload in pocs:
      with self._assert_no_command_execution():
        pm_res = safer_pickle.picklemagic_scan(payload)
        self.assertNotEmpty(pm_res.unsafe_results)
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)
        with self.assertRaises(safer_pickle.StrictCheckError):
          pickle.loads(payload, strict_check=True)


class SecurityBypassVariantsTest(_CommandGuardTestCase):
  """Regression tests for security bypass variants and PoCs."""

  def setUp(self):
    super().setUp()
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle()

  def tearDown(self):
    safer_pickle.unhook_pickle()
    super().tearDown()

  def test_protocol0_cr_and_hex_escape_blocked(self):
    r"""Verifies protocol 0 CRLF line-endings and hex-escaped strings are blocked.

    Ensures `\r\n`-terminated `GLOBAL`, `INST`, and hex-escaped `STRING`
    opcodes classify as `UNSAFE` without executing commands.

    Returns:
      None.
    """
    cr_global_payload = b'cos\r\nsystem\r\n(Vecho PWNED\r\ntR.'
    cr_inst_payload = b'(Vecho PWNED\r\nios\r\nsystem\r\n.'
    hex_string_payload = (
        b"S'\\x6f\\x73'\r\nS'\\x73\\x79\\x73\\x74\\x65\\x6d'\r\n\x93"
        b"(S'echo PWNED'\r\ntR."
    )

    for payload in (cr_global_payload, cr_inst_payload, hex_string_payload):
      with self._assert_no_command_execution():
        genops_results = safer_pickle.genops_scan(payload)
        self.assertNotEmpty(genops_results.unsafe_results)
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaisesRegex(
            safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
        ):
          pickle.loads(payload)

  def test_chunk_boundary_and_embedded_stop_blocked(self):
    """Verifies chunk-boundary splits and embedded 0x2E bytes do not hide ops.

    Ensures `partition_pickle_chunks` and `SHORT_BINBYTES` stride skipping do
    not truncate scanning before trailing `os.system` opcodes.

    Returns:
      None.
    """
    chunk_boundary_payload = (
        b'\x80\x04\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R'
        b'\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R\x86.'
    )
    partitions = safer_pickle.utils.partition_pickle_chunks(
        chunk_boundary_payload, 20
    )

    combined_operands = set()
    for start_offset, end_offset, seed_stack in partitions:
      for _, operand in safer_pickle.utils.custom_genops_from_bytes(
          chunk_boundary_payload, start_offset, end_offset, seed_stack
      ):
        if operand is not None:
          combined_operands.add(str(operand))
    self.assertIn('os.system', combined_operands)

    embedded_stop_payload = (
        b'\x80\x04C\x08\x2e\x2e\x2e\x2e\x2e\x2e\x2e\x2e0'
        b'\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.'
    )
    with self._assert_no_command_execution():
      self.assertGreater(
          safer_pickle.security_scan(embedded_stop_payload)['unsafe'], 0
      )

  def test_persid_and_short_string_stack_global_blocked(self):
    """Verifies PERSID, BINPERSID, and 1-char STACK_GLOBAL symbols are flagged.

    Ensures persistent IDs and single-character `STACK_GLOBAL` operands are not
    discarded during scanning.

    Returns:
      None.
    """
    persid_payload = b'Ppersistent_id_payload\r\n.'
    binpersid_payload = b'\x80\x04\x8c\x0bcustom_persQ.'
    one_char_global_payload = b'\x80\x04\x8c\x01a\x8c\x01b\x93)R.'

    for payload in (
        persid_payload,
        binpersid_payload,
        one_char_global_payload,
    ):
      with self._assert_no_command_execution():
        scan_scores = safer_pickle.security_scan(payload)
        self.assertGreater(
            scan_scores['unsafe']
            + scan_scores['suspicious']
            + scan_scores['unknown'],
            0,
        )
        self.assertTrue(safer_pickle.strict_security_scan(payload))

  def test_sandbox_state_and_instantiation_hardening(self):
    """Tests sandbox state inspection, slots, and non-callable instantiation.

    Verifies non-callable `REDUCE`/`NEWOBJ` targets, nested 2-tuple `BUILD`
    state dicts, and mutated cached safe instances are blocked.

    Returns:
      None.
    """
    non_callable_reduce = b'\x80\x04K\x01)R.'
    non_callable_newobj = b'\x80\x04K\x01)\x81.'
    tuple_state_build = (
        b'\x80\x04\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R'
        b'}N\x8c\x0c__setstate__\x8c\x02os\x8c\x06system\x93s\x86b.'
    )
    mutated_cached_instance = (
        b'\x80\x04\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R'
        b'}\x8c\x04attr\x8c\x07unknown\x8c\x06Gadget\x93sb'
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R\x86.'
    )

    for payload in (
        non_callable_reduce,
        non_callable_newobj,
        tuple_state_build,
        mutated_cached_instance,
    ):
      with self._assert_no_command_execution():
        self.assertTrue(safer_pickle.strict_security_scan(payload))
        with self.assertRaises((
            safer_pickle.UnsafePickleDetectedError,
            safer_pickle.StrictCheckError,
        )):
          pickle.loads(payload)

  def test_classification_and_mro_hardening(self):
    """Tests classification rules, MRO/AST checks, and inline call patterns.

    Verifies dangerous codegen/eval helpers classify as `UNSAFE`, generic type
    callables as `UNKNOWN`, and filesystem path types as `SUSPICIOUS`.

    Returns:
      None.
    """
    unsafe_symbols = (
        'dataclasses._create_fn',
        'dataclasses.make_dataclass',
        'typing._eval_type',
        'typing.get_type_hints',
        'torch._dynamo.utils',
        'torch._inductor.codecache',
        'torch.distributed.launcher',
        'keras.saving.pickle_utils',
        'scipy.weave',
        'pandas.io.clipboard',
        'sympy.core.sympify',
        'builtins.eval(1)',
        'builtins.__import__ ("os")',
    )
    for symbol in unsafe_symbols:
      self.assertEqual(
          safer_pickle.utils.classify_symbol(symbol),
          safer_pickle.utils.Classification.UNSAFE,
          msg=f'Expected {symbol} to be classified as UNSAFE',
      )

    unknown_symbols = (
        'collections.abc.Callable',
        'typing.Callable',
        'numpy.polyval',
    )
    for symbol in unknown_symbols:
      self.assertEqual(
          safer_pickle.utils.classify_symbol(symbol),
          safer_pickle.utils.Classification.UNKNOWN,
          msg=f'Expected {symbol} to be classified as UNKNOWN',
      )

    suspicious_symbols = (
        'pathlib.PosixPath',
        'pathlib.Path',
    )
    for symbol in suspicious_symbols:
      self.assertEqual(
          safer_pickle.utils.classify_symbol(symbol),
          safer_pickle.utils.Classification.SUSPICIOUS,
          msg=f'Expected {symbol} to be classified as SUSPICIOUS',
      )

  def test_polyglot_pocs(self):
    """Verifies hooked `pickle.Unpickler`, tar-pickle polyglots, and stuffing.

    Ensures direct `pickle.Unpickler.load()`, tar-header pickle polyglots, and
    safe-padded unknown gadgets are all caught under RCE command guards.

    Returns:
      None.
    """
    malicious_payload = b'cos\nsystem\n(Vecho PWNED\ntR.'
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.Unpickler(io.BytesIO(malicious_payload)).load()

    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer, mode='w', format=tarfile.USTAR_FORMAT
    ) as tar_archive:
      safe_data = pickle.dumps({'safe_key': 123})
      tar_info = tarfile.TarInfo(name='cos\nsystem\n(Vid\ntR.')
      tar_info.size = len(safe_data)
      tar_archive.addfile(tar_info, io.BytesIO(safe_data))
    polyglot_bytes = tar_buffer.getvalue()

    self.assertTrue(safer_pickle.utils.is_tar_bytes(polyglot_bytes))
    self.assertTrue(safer_pickle.utils.is_pickle_file(polyglot_bytes))
    with self._assert_no_command_execution():
      pm_res = safer_pickle.picklemagic_scan(polyglot_bytes)
      genops_res = safer_pickle.genops_scan(polyglot_bytes)
      self.assertNotIn('archive_extraction_error', pm_res.unsafe_results)
      self.assertNotEmpty(pm_res.unsafe_results)
      self.assertNotEmpty(genops_res.unsafe_results)
      self.assertGreater(
          safer_pickle.security_scan(polyglot_bytes)['unsafe'], 0
      )
      self.assertTrue(safer_pickle.strict_security_scan(polyglot_bytes))
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(polyglot_bytes)

    stuffed_unknown = (
        b'\x80\x04('
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93'
        b'\x8c\x0bcollections\x8c\x05deque\x93'
        b'\x8c\x05numpy\x8c\x07ndarray\x93'
        b'\x8c\x05numpy\x8c\x05dtype\x93'
        b'cftplib\nFTP\n(V127.0.0.1\ntR'
        b't.'
    )
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
      ):
        pickle.loads(stuffed_unknown)

  def test_dunder_chain_compat_and_build_state_bypasses_blocked(self):
    """Verifies dunder chains, `cPickle.loads`, and `__globals__` state blocks.

    Ensures dotted dunder attribute chains, Python 2 `cPickle.loads`, and
    unlisted dunder keys in `BUILD` state raise `UnsafePickleDetectedError`.

    Returns:
      None.
    """
    dunder_chain_payload = (
        b'\x80\x04'
        b'\x8c\x0bcollections'
        b'\x8c&OrderedDict.__init__.__closure__.dict'
        b'\x93).'
    )
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        pickle.loads(dunder_chain_payload)

    cpickle_compat_payload = b'ccPickle\nloads\n(S"cos\\nsystem\\n."\ntR.'
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(cpickle_compat_payload)

    unlisted_dunder_build_state = (
        b'\x80\x04'
        b'\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R'
        b'}\x8c\x0b__globals__}sb.'
    )
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        pickle.loads(unlisted_dunder_build_state)

  def test_hook_pickle_libs_restores_blocking_hooks_and_config(self):
    """Tests `hook_pickle_libs` restores prior blocking hooks and `config_path`."""
    deny_cfg = self.create_tempfile(
        'outer_deny.json',
        content=json.dumps({'safer_pickle': {'deny_list': ['numpy.sum']}}),
    )
    temp_allow_cfg = self.create_tempfile(
        'inner_allow.json',
        content=json.dumps(
            {'safer_pickle': {'allow_list': ['platform._syscmd_ver']}}
        ),
    )
    malicious_payload = b"cos\nsystem\n(S'echo PWNED'\ntR."
    numpy_sum_payload = b'\x80\x04\x8c\x05numpy\x8c\x03sum\x93\x5d\x85R.'

    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(
        force_report_only=False, config_path=deny_cfg.full_path
    )

    with self._assert_no_command_execution(expect_calls=True):
      with safer_pickle.hook_pickle_libs(
          report_only=True, config_path=temp_allow_cfg.full_path
      ):
        with self.assertLogs(level='ERROR'):
          pickle.loads(malicious_payload)

    self.assertEqual(config.get_config_path(), deny_cfg.full_path)
    with self._assert_no_command_execution():
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(malicious_payload)
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.Unpickler(io.BytesIO(malicious_payload)).load()
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(numpy_sum_payload)

    safer_pickle.unhook_pickle()
    config.set_config_path(None)
    with safer_pickle.hook_pickle_libs(
        report_only=True, config_path=temp_allow_cfg.full_path
    ):
      self.assertEqual(config.get_config_path(), temp_allow_cfg.full_path)
    self.assertIsNone(config.get_config_path())

  def test_unseekable_buffered_stream_scan_and_load(self):
    """Tests unseekable `io.BufferedReader` streams scan and load without byte loss."""

    class _UnseekableRawStream(io.RawIOBase):

      def __init__(self, payload: bytes) -> None:
        self._buffer = io.BytesIO(payload)

      def readable(self) -> bool:
        return True

      def readinto(self, target_buf) -> int:
        return self._buffer.readinto(target_buf)

    def make_unseekable(payload: bytes) -> io.BufferedReader:
      return io.BufferedReader(_UnseekableRawStream(payload))

    benign_obj = {'header': 'ok', 'blob': b'X' * 5000}
    benign_bytes = pickle.dumps(benign_obj, protocol=4)
    malicious_bytes = b"cos\nsystem\n(S'echo PWNED'\ntR."

    peek_stream = make_unseekable(benign_bytes)
    self.assertFalse(peek_stream.seekable())
    self.assertTrue(safer_pickle.utils.is_pickle_file(peek_stream))
    self.assertEqual(peek_stream.read(), benign_bytes)

    self.assertFalse(
        safer_pickle.strict_security_scan(make_unseekable(benign_bytes))
    )
    self.assertTrue(
        safer_pickle.strict_security_scan(make_unseekable(malicious_bytes))
    )
    self.assertEqual(
        safer_pickle.security_scan(make_unseekable(benign_bytes)),
        {'unsafe': 0, 'suspicious': 0, 'unknown': 0},
    )
    scan_res = safer_pickle.security_scan_results(make_unseekable(benign_bytes))
    self.assertIsNotNone(scan_res)

    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle()
    with self._assert_no_command_execution():
      self.assertEqual(pickle.load(make_unseekable(benign_bytes)), benign_obj)
      self.assertEqual(
          pickle.Unpickler(
              make_unseekable(benign_bytes), strict_check=True
          ).load(),
          benign_obj,
      )
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.load(make_unseekable(malicious_bytes))

  def test_benign_functools_partial_nested_and_top_level_allowed(self):
    """Tests benign `functools.partial` payloads pass top-level and nested scans.

    Returns:
      None.
    """
    top_level_partial = pickle.dumps(functools.partial(int, base=2), protocol=4)
    defaultdict_partial = pickle.dumps(
        collections.defaultdict(functools.partial(int, '101', base=2)),
        protocol=4,
    )
    state_holder = collections.OrderedDict()
    state_holder['factory'] = functools.partial(
        collections.OrderedDict, update=True
    )
    state_holder_bytes = pickle.dumps(state_holder, protocol=4)

    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle()
    with self._assert_no_command_execution():
      for payload in (
          top_level_partial,
          defaultdict_partial,
          state_holder_bytes,
      ):
        self.assertEqual(
            safer_pickle.security_scan(payload),
            {'unsafe': 0, 'suspicious': 0, 'unknown': 0},
        )
        self.assertFalse(safer_pickle.strict_security_scan(payload))

      loaded_fn = pickle.loads(top_level_partial, strict_check=True)
      self.assertEqual(loaded_fn('110'), 6)

      loaded_dd = pickle.loads(defaultdict_partial, strict_check=True)
      self.assertEqual(loaded_dd['missing'], 5)

      loaded_holder = pickle.loads(state_holder_bytes, strict_check=True)
      self.assertEqual(loaded_holder['factory'](), {'update': True})

  @parameterized.named_parameters(
      dict(
          testcase_name='unknown_target_top_level',
          payload=(
              b'cfunctools\npartial\n(ccustom_untrusted_pkg\nhelper\n'
              b"S'arg'\ntR."
          ),
      ),
      dict(
          testcase_name='unknown_target_in_defaultdict',
          payload=(
              b'ccollections\ndefaultdict\n(cfunctools\npartial\n'
              b'(ccustom_untrusted_pkg\nhelper\ntRtR.'
          ),
      ),
      dict(
          testcase_name='setstate_swaps_safe_target_for_unknown',
          payload=(
              b'cfunctools\npartial\n(cbuiltins\nint\ntR'
              b"(ccustom_untrusted_pkg\nhelper\n(S'arg'\ntNNtb."
          ),
      ),
      dict(
          testcase_name='setstate_injects_dunder_namespace',
          payload=(
              b'cfunctools\npartial\n(cbuiltins\nint\ntR'
              b"(cbuiltins\nint\n(tN(dS'__reduce__'\nS'x'\nstb."
          ),
      ),
      dict(
          testcase_name='outer_reduce_invoking_safe_partial_instance',
          payload=b"cfunctools\npartial\n(cbuiltins\nint\nS'101'\ntR(tR.",
      ),
      dict(
          testcase_name='outer_obj_invoking_safe_partial_instance',
          payload=b"(cfunctools\npartial\n(cbuiltins\nint\nS'101'\ntRo.",
      ),
      dict(
          testcase_name='reconstructor_with_functools_partial_base',
          payload=(
              b'ccopyreg\n_reconstructor\n(ccustom_untrusted_pkg\nSubPartial\n'
              b'cfunctools\npartial\nccustom_untrusted_pkg\nhelper\ntR.'
          ),
      ),
  )
  def test_malicious_functools_partial_variants_blocked(self, payload: bytes):
    """Tests malicious and unapproved `functools.partial` gadgets are blocked.

    Args:
      payload: Crafted pickle byte sequence exercising a `partial` bypass shape.

    Returns:
      None.
    """
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle()
    with self._assert_no_command_execution():
      scan_res = safer_pickle.security_scan_results(payload)
      self.assertNotEmpty(scan_res.suspicious_results)
      self.assertIn('unsafe_state_assignment', scan_res.suspicious_results)
      self.assertTrue(safer_pickle.strict_security_scan(payload))
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'SUSPICIOUS'
      ):
        pickle.loads(payload)

  def test_functools_partial_respects_allow_and_deny_config(self):
    """Tests `functools.partial` honors `allow_list` targets and `deny_list`.

    Returns:
      None.
    """
    allow_payload = (
        b'ccollections\ndefaultdict\n(cfunctools\npartial\n'
        b"(ccustom_trusted_pkg\nsafe_factory\nS'x'\ntRtR."
    )
    benign_partial = pickle.dumps(functools.partial(int, base=2), protocol=4)

    allow_cfg = self.create_tempfile(
        content=json.dumps({
            'safer_pickle': {
                'allow_list': ['custom_trusted_pkg.safe_factory'],
                'deny_list': [],
            }
        })
    )
    deny_cfg = self.create_tempfile(
        content=json.dumps({
            'safer_pickle': {
                'allow_list': [],
                'deny_list': ['functools.partial'],
            }
        })
    )

    try:
      with self._assert_no_command_execution():
        config.set_config_path(allow_cfg.full_path)
        allow_res = safer_pickle.security_scan_results(allow_payload)
        self.assertEmpty(allow_res.unsafe_results)
        self.assertEmpty(allow_res.suspicious_results)
        self.assertFalse(safer_pickle.strict_security_scan(allow_payload))

        config.set_config_path(deny_cfg.full_path)
        deny_res = safer_pickle.security_scan_results(benign_partial)
        self.assertNotEmpty(deny_res.unsafe_results)
        self.assertTrue(safer_pickle.strict_security_scan(benign_partial))
    finally:
      config.set_config_path(None)

  def test_cyclic_fake_class_and_sequence_build_state_terminates_cleanly(self):
    """Tests cyclic FakeClass and list BUILD states terminate cleanly.

    Returns:
      None.
    """
    unpickler = safer_pickle.SaferUnpickler(io.BytesIO(b'.'))
    fake_state = unpickler.class_factory('OrderedDict', 'collections')()
    fake_state.__dict__['__dict__'] = fake_state
    cyclic_list = []
    cyclic_list.append(cyclic_list)
    fake_state.__dict__['_list_items'] = cyclic_list

    self.assertFalse(unpickler._state_has_dangerous_keys(fake_state))

    fake_evil_state = unpickler.class_factory('OrderedDict', 'collections')()
    fake_evil_state.__dict__['__dict__'] = fake_evil_state
    cyclic_evil_list = []
    cyclic_evil_list.append(cyclic_evil_list)
    cyclic_evil_list.append(('__reduce__', 'x'))
    fake_evil_state.__dict__['_list_items'] = cyclic_evil_list

    self.assertTrue(unpickler._state_has_dangerous_keys(fake_evil_state))

  def test_tar_with_proto4_pickle_member_name_scans_inner_entries(self):
    """Tests tar archives starting with a Protocol 4 pickle member name.

    Returns:
      None.
    """
    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer,
        mode='w',
        format=tarfile.USTAR_FORMAT,
        encoding='latin1',
    ) as tar_archive:
      benign_member = b'\x80\x04}.'
      first_info = tarfile.TarInfo(name='\x80\x04}.a')
      first_info.size = len(benign_member)
      tar_archive.addfile(first_info, io.BytesIO(benign_member))

      evil_member = b'cos\nsystem\n(Vecho PWNED\ntR.'
      second_info = tarfile.TarInfo(name='inner_evil.pkl')
      second_info.size = len(evil_member)
      tar_archive.addfile(second_info, io.BytesIO(evil_member))

    polyglot_tar = tar_buffer.getvalue()
    self.assertEqual(polyglot_tar[:5], b'\x80\x04}.a')
    self.assertTrue(safer_pickle.utils.is_tar_bytes(polyglot_tar))

    with self._assert_no_command_execution():
      self.assertGreater(safer_pickle.security_scan(polyglot_tar)['unsafe'], 0)
      self.assertTrue(safer_pickle.strict_security_scan(polyglot_tar))
      self.assertNotEmpty(
          safer_pickle.picklemagic_scan(polyglot_tar).unsafe_results
      )
      self.assertNotEmpty(safer_pickle.genops_scan(polyglot_tar).unsafe_results)
      with self.assertRaisesRegex(
          safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
      ):
        pickle.loads(polyglot_tar)

  def test_benign_proto4_pickle_with_ustar_at_tar_offset_loads_cleanly(self):
    """Tests benign Protocol 4 pickles containing `ustar` at offset 257.

    Returns:
      None.
    """
    expected_obj = {
        'pad': 'a' * 222,
        'flavor': 'mustard',
        'tail': 'b' * 300,
    }
    benign_ustar_pickle = pickle.dumps(expected_obj, protocol=4)

    self.assertGreaterEqual(len(benign_ustar_pickle), 512)
    self.assertEqual(benign_ustar_pickle[257:262], b'ustar')
    self.assertFalse(safer_pickle.utils.is_tar_bytes(benign_ustar_pickle))

    with self._assert_no_command_execution():
      scores = safer_pickle.security_scan(benign_ustar_pickle)
      self.assertEqual(scores['unsafe'], 0)
      self.assertEqual(scores['suspicious'], 0)
      self.assertEqual(scores['unknown'], 0)
      loaded_obj = pickle.loads(benign_ustar_pickle)

    self.assertDictEqual(loaded_obj, expected_obj)


if __name__ == '__main__':
  googletest.main()

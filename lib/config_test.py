import contextlib
import json
import pickle
from unittest import mock

# Must be imported after safer_pickle. Violates g-bad-import-order
# pylint: disable=g-bad-import-order
# Imports used in COMMAND_EXECUTION_TARGETS for mocking
# pylint: disable=unused-import
import bdb
import os
import posix
import pty
import runpy
import subprocess
import timeit
import numpy

# pylint: enable=unused-import
import saferpickle as safer_pickle
from lib import config
from absl.testing import absltest as googletest
from absl.testing import parameterized

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


@contextlib.contextmanager
def _assert_no_command_execution():
  mocks = {}
  with contextlib.ExitStack() as stack:
    # Targets that work with autospec=True
    autospec_targets = [
        'posix.system',
        'os.system',
        'subprocess.run',
        'subprocess.call',
        'subprocess.check_call',
        'subprocess.check_output',
        'pty.spawn',
        'timeit.timeit',
    ]
    for target in autospec_targets:
      try:
        mock_obj = stack.enter_context(mock.patch(target, autospec=True))
        mocks[target] = mock_obj
      except (ImportError, ModuleNotFoundError):
        pass

    # Targets that don't work with autospec=True
    no_autospec_targets = [
        'builtins.exec',
        'builtins.eval',
        'subprocess.Popen',
        'runpy._run_code',
        'bdb.Bdb.run',
    ]
    for target in no_autospec_targets:
      try:
        # This is a special case where we were running into KeyError's on 'run'
        if target == 'bdb.Bdb.run':
          mock_bdb_class = stack.enter_context(mock.patch('bdb.Bdb'))
          mocks['bdb.Bdb.run'] = mock_bdb_class.return_value.run
        else:
          mock_obj = stack.enter_context(mock.patch(target))
          mocks[target] = mock_obj
      except (ImportError, ModuleNotFoundError):
        pass

    yield
    for target, mock_obj in mocks.items():
      try:
        mock_obj.assert_not_called()
      except AssertionError as e:
        raise AssertionError(f'{target} was called unexpectedly') from e


class ConfigTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    config.set_config_path(None)
    # Ensure hooks are active before each test
    safer_pickle.hook_pickle()

  def tearDown(self):
    """Unhooks pickle after each test to ensure isolation."""
    super().tearDown()
    safer_pickle.unhook_pickle()
    config.set_config_path(None)

  @parameterized.named_parameters(
      dict(
          testcase_name='json_decode_error',
          file_content='invalid json',
          allow_list_exception=json.JSONDecodeError,
          deny_list_exception=json.JSONDecodeError,
          exception_message='Could not parse SaferPickle config at',
      ),
      dict(
          testcase_name='type_error',
          file_content='{"safer_pickle": {"allow_list": 1, "deny_list": 2}}',
          allow_list_exception=TypeError,
          deny_list_exception=TypeError,
          exception_message='in the config must be an array.',
      ),
  )
  def test_config_errors(
      self,
      file_content,
      allow_list_exception,
      deny_list_exception,
      exception_message,
  ):
    config_file = self.create_tempfile(content=file_content)
    config.set_config_path(config_file.full_path)
    with self.subTest('get_allow_list'):
      with self.assertRaisesRegex(allow_list_exception, exception_message):
        config.get_allow_list()
    with self.subTest('get_deny_list'):
      with self.assertRaisesRegex(deny_list_exception, exception_message):
        config.get_deny_list()

  @parameterized.named_parameters(
      (
          'deny_module_sum',
          ['numpy'],
          'numpy_sum.pkl',
          safer_pickle.UnsafePickleDetectedError,
          'UNSAFE',
      ),
      (
          'deny_module_mean',
          ['numpy'],
          'numpy_mean.pkl',
          safer_pickle.UnsafePickleDetectedError,
          'UNSAFE',
      ),
      (
          'deny_function_sum',
          ['numpy.sum'],
          'numpy_sum.pkl',
          safer_pickle.UnsafePickleDetectedError,
          'UNSAFE',
      ),
      (
          'allow_function_mean',
          ['numpy.sum'],
          'numpy_mean.pkl',
          None,  # No exception expected
          None,
      ),
  )
  def test_deny_list_numpy(
      self, deny_list, pickle_name, expected_exception, expected_message
  ):
    """Tests that a configured deny-list blocks numpy at various levels."""
    # 1. Create a config file with the specified deny-list
    config_content = {'safer_pickle': {'deny_list': deny_list}}
    config_path = self.create_tempfile(
        'deny_config.json', content=json.dumps(config_content)
    )

    # 2. Re-hook the pickle module with our new config file
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(config_path=config_path.full_path)

    pickle_path = f'testdata/{pickle_name}'
    with open(pickle_path, 'rb') as f:
      data_bytes = f.read()

    # 3. Assert the expected outcome
    if expected_exception:
      with self.assertRaisesRegex(expected_exception, expected_message):
        pickle.loads(data_bytes)
      return

    try:
      pickle.loads(data_bytes)
    except safer_pickle.UnsafePickleDetectedError:
      self.fail(f'The deny-list blocked an unlisted function in {pickle_name}.')

  def test_allow_list_bypasses_unsafe_check_module(self):
    """Tests that a configured allow-list bypasses an UNSAFE classification for a whole module."""
    # This pickle file normally raises an
    # UNSAFE error because it calls posix.system
    malicious_pickle_path = 'testdata/malicious.pkl'

    # 1. Create a config file that allows the entire 'posix' module
    config_content = {'safer_pickle': {'allow_list': ['posix']}}
    config_path = self.create_tempfile(
        'allow_config.json', content=json.dumps(config_content)
    )

    # 2. Re-hook the pickle module with our new config file
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(config_path=config_path.full_path)

    with open(malicious_pickle_path, 'rb') as f:
      data_bytes = f.read()

    # 3. Assert that the file now loads WITHOUT raising an error
    try:
      # We mock the underlying system call to prevent
      # the test from actually executing it
      with mock.patch('posix.system', autospec=True):
        pickle.loads(data_bytes)
    except safer_pickle.UnsafePickleDetectedError:
      self.fail(
          'The allow-list failed to bypass the security check for the module.'
      )

  def test_allow_list_bypasses_unsafe_check_module_function(self):
    """Tests that a configured allow-list bypasses an UNSAFE classification."""
    # This pickle file normally raises an
    # UNSAFE error because it calls posix.system
    malicious_pickle_path = 'testdata/malicious.pkl'

    # 1. Create a config file that allows 'posix.system'
    config_content = {'safer_pickle': {'allow_list': ['posix.system']}}
    config_path = self.create_tempfile(
        'allow_config.json', content=json.dumps(config_content)
    )

    # 2. Re-hook the pickle module with our new config file
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(config_path=config_path.full_path)

    with open(malicious_pickle_path, 'rb') as f:
      data_bytes = f.read()

    # 3. Assert that the file now loads WITHOUT raising an error
    try:
      # We mock the underlying system call to prevent
      # the test from actually executing it
      with mock.patch('posix.system', autospec=True):
        pickle.loads(data_bytes)
    except safer_pickle.UnsafePickleDetectedError:
      self.fail('The allow-list failed to bypass the security check.')

  def test_allow_list_does_not_affect_unlisted_items(self):
    """Tests that a config file does not allow items that are not on its list."""
    malicious_pickle_path = 'testdata/malicious.pkl'

    # 1. Create a config file that allows something irrelevant
    config_content = {'safer_pickle': {'allow_list': ['a.safe.module']}}
    config_path = self.create_tempfile(
        'irrelevant_config.json', content=json.dumps(config_content)
    )

    # 2. Re-hook the pickle module with this config
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(config_path=config_path.full_path)

    with open(malicious_pickle_path, 'rb') as f:
      data_bytes = f.read()

    # 3. Assert that the UnsafePickleDetectedError IS STILL RAISED
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNSAFE'
    ):
      with _assert_no_command_execution():
        pickle.loads(data_bytes)

  def test_allow_list_bypasses_unknown_check(self):
    """Tests that a configured allow-list overrides UNKNOWN classification."""
    unknown_pickle_path = (
        'testdata/unknown_import.pkl'
    )
    with open(unknown_pickle_path, 'rb') as f:
      data_bytes = f.read()

    # Without allow_list, unknown_import.pkl raises UNKNOWN.
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle()
    with self.assertRaisesRegex(
        safer_pickle.UnsafePickleDetectedError, 'UNKNOWN'
    ):
      pickle.loads(data_bytes)  # pylint: disable=g-unsafe-pickle-load

    # With allow_list containing 'platform._syscmd_ver', it loads cleanly.
    config_content = {'safer_pickle': {'allow_list': ['platform._syscmd_ver']}}
    config_path = self.create_tempfile(
        'allow_unknown_config.json', content=json.dumps(config_content)
    )
    safer_pickle.unhook_pickle()
    safer_pickle.hook_pickle(config_path=config_path.full_path)
    pickle.loads(data_bytes)  # pylint: disable=g-unsafe-pickle-load


if __name__ == '__main__':
  googletest.main()

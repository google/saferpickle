# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copyreg
import io
import os
import pickle
import subprocess
import sys
import tarfile
import types
import unittest.mock
import zipfile
# Import these four modules so that BuildCleaner doesn't complain.
import cloudpickle
import dill
import joblib
from lib import utils
import torch
from absl.testing import absltest as googletest
from absl.testing import parameterized

_TESTDATA_DIR = os.path.join(
    os.environ.get('TEST_SRCDIR', ''),
    'testdata',
)


class UtilsTest(parameterized.TestCase):

  def test_is_zip_file(self):
    with self.subTest('A zip file'):
      with open(
          os.path.join(_TESTDATA_DIR, 'modelscan_tests/unsafe_zip_pytorch.pt'),
          'rb',
      ) as f:
        data_bytes = f.read()
        self.assertTrue(utils.is_zip_bytes(data_bytes))

    with self.subTest('Not a zip file'):
      with open(
          os.path.join(_TESTDATA_DIR, 'malicious.pkl'),
          'rb',
      ) as f:
        data_bytes = f.read()
        self.assertFalse(utils.is_zip_bytes(data_bytes))

  @parameterized.named_parameters(
      dict(
          testcase_name='Empty set',
          input_set=set(),
          expected=set(),
      ),
      dict(
          testcase_name='No modules',
          input_set={'a', 'b'},
          expected={'a', 'b'},
      ),
      dict(
          testcase_name='Module and member',
          input_set={'os', 'system'},
          expected={'os.system'},
      ),
      dict(
          testcase_name='Module and member with other strings',
          input_set={'os', 'system', 'json'},
          expected={'os.system', 'json'},
      ),
      dict(
          testcase_name='Fully qualified names',
          input_set={'os.path', 'json.loads'},
          expected={'os.path', 'json.loads'},
      ),
      dict(
          testcase_name='Module, member, and fully qualified',
          input_set={'os', 'system', 'json.loads'},
          expected={'os.system', 'json.loads'},
      ),
      dict(
          testcase_name='Module without members in set',
          input_set={'os', 'json'},
          expected={'os', 'json'},
      ),
      dict(
          testcase_name='Member without module in set',
          input_set={'system', 'loads'},
          expected={'system', 'loads'},
      ),
      dict(
          testcase_name='Multiple members for one module',
          input_set={'os', 'system', 'path'},
          expected={'os.system', 'os.path'},
      ),
      dict(
          testcase_name='Remove base library if member is present',
          input_set={'os', 'os.system'},
          expected={'os.system'},
      ),
      dict(
          testcase_name='Remove member if more specific member is present',
          input_set={'os.path', 'os.path.join'},
          expected={'os.path.join'},
      ),
      dict(
          testcase_name='Complex case',
          input_set={
              'os',
              'system',
              'path',
              'json',
              'loads',
              'os.path.join',
              'requests.get',
              'requests',
              'urllib',
              'urllib.request',
              'request',
          },
          expected={
              'os.system',
              'os.path.join',
              'json.loads',
              'requests.get',
              'urllib.request',
          },
      ),
      dict(
          testcase_name='Complex Ambiguous Edge Case',
          input_set={
              'concurrent',
              'futures',
              'ProcessPoolExecutor',
              'concurrent.futures',
              'http',
              'client',
              'server',
              'http.server',
              'get',
              'requests.get',
              'pathlib',
              'Path',
              'standalone',
          },
          expected={
              # Example of a.b from a.b.c. It's okay to ignore
              'concurrent.futures',
              # Example of c from a.b.c. It's okay to ignore
              'ProcessPoolExecutor',
              'http.server',
              'http.client',
              'standalone',
              'requests.get',
              'pathlib.Path',
          },
      ),
  )
  def test_resolve_library_modules_from_results(self, input_set, expected):
    self.assertEqual(
        utils.resolve_library_modules_from_results(input_set), expected
    )

  @parameterized.named_parameters(
      dict(
          testcase_name='_pickle',
          original_name='_pickle',
          new_name='pickle_copy',
          should_succeed=True,
      ),
      dict(
          testcase_name='dill',
          original_name='dill',
          new_name='dill_copy',
          should_succeed=True,
      ),
      dict(
          testcase_name='joblib',
          original_name='joblib',
          new_name='joblib_copy',
          should_succeed=True,
      ),
      dict(
          testcase_name='cloudpickle',
          original_name='cloudpickle',
          new_name='cloudpickle_copy',
          should_succeed=True,
      ),
      dict(
          testcase_name='torch',
          original_name='torch',
          new_name='torch_copy',
          should_succeed=True,
      ),
      dict(
          testcase_name='nonexistent_module',
          original_name='nonexistent_module',
          new_name='nonexistent_copy',
          should_succeed=False,
      ),
  )
  def test_copy_module(self, original_name, new_name, should_succeed):
    # Use the modules so that the linter doesn't complain.
    _ = dill.__name__
    _ = joblib.__name__
    _ = cloudpickle.__name__
    _ = torch.__name__

    copied_module = utils.copy_module(original_name, new_name)
    if should_succeed:
      self.assertIsNotNone(copied_module)
      self.assertIsInstance(copied_module, types.ModuleType)
      self.assertEqual(copied_module.__name__, new_name)
      original_module = utils.importlib.import_module(original_name)
      if hasattr(original_module, 'loads'):
        self.assertTrue(hasattr(copied_module, 'loads'))
      if hasattr(original_module, 'load'):
        self.assertTrue(hasattr(copied_module, 'load'))
    else:
      self.assertIsNone(copied_module)

  def test_get_module_members_spec_origin_none(self):
    with unittest.mock.patch.object(
        utils.importlib.util, 'find_spec'
    ) as mock_find_spec:
      mock_spec = unittest.mock.MagicMock()
      mock_spec.origin = None
      mock_find_spec.return_value = mock_spec

      self.assertIsNone(utils.get_module_members('some_module'))

  def test_classify_symbol(self):
    for symbol, expected in (
        ('collections.OrderedDict', utils.Classification.SAFE),
        ('eval', utils.Classification.UNSAFE),
        ('os.system', utils.Classification.UNSAFE),
        ('torch.nn.Linear', utils.Classification.SAFE),
        ('unlisted_mod.some_class', utils.Classification.UNKNOWN),
        ('numpy.size', utils.Classification.UNKNOWN),
        ('base64.urlsafe_b64decode', utils.Classification.UNSAFE),
        ('ssl.SSLSocket', utils.Classification.UNSAFE),
        ('shutil.disk_usage', utils.Classification.SAFE),
        ('shutil.rmtree', utils.Classification.UNSAFE),
        ('shutil.which', utils.Classification.UNKNOWN),
        ('posix system', utils.Classification.UNSAFE),
        ('custom_mod.system', utils.Classification.UNSAFE),
        ('Anatomical system', utils.Classification.UNKNOWN),
    ):
      self.assertEqual(utils.classify_symbol(symbol), expected)

    self.assertEmpty(
        utils.constants.SAFE_STRINGS & utils.constants.SUSPICIOUS_STRINGS
    )
    self.assertEmpty(
        utils.constants.SAFE_STRINGS & utils.constants.UNSAFE_STRINGS
    )
    self.assertEmpty(
        utils.constants.SUSPICIOUS_STRINGS & utils.constants.UNSAFE_STRINGS
    )
    self.assertEmpty(
        utils.constants.APPROVED_ROOT_PACKAGES
        & utils.constants.UNSAFE_ROOT_PACKAGES
    )

  def test_compression_matchers_streaming(self):
    zip_data = b'PK\x05\x06' + b'\x00' * 18
    self.assertTrue(utils.is_zip_bytes(zip_data))
    self.assertFalse(utils.is_zip_bytes(b'not a zip'))

    bz2_data = b'\x42\x5a\x68' + b'\x00' * 10
    self.assertTrue(utils.is_bz2_bytes(io.BytesIO(bz2_data)))

    lzma_data = b'\xfd\x37\x7a\x58\x5a\x00' + b'\x00' * 10
    self.assertTrue(utils.is_lzma_bytes(io.BytesIO(lzma_data)))

    gzip_data = b'\x1f\x8b' + b'\x00' * 10
    self.assertTrue(utils.is_gzip_bytes(io.BytesIO(gzip_data)))

    tar_data = b'\x00' * 257 + b'ustar' + b'\x00' * 10
    self.assertTrue(utils.is_tar_bytes(io.BytesIO(tar_data)))

  # Test is_pickle_file with a seekable stream and assert seek-back
  def test_is_pickle_file_streaming_and_position_restoration(self):
    with open(
        os.path.join(_TESTDATA_DIR, 'safe.pkl'),
        'rb',
    ) as f:
      start_pos = f.tell()

      is_pickle = utils.is_pickle_file(f)
      self.assertTrue(is_pickle)

      self.assertEqual(f.tell(), start_pos)

  def test_extract_zip_contents_streaming(self):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
      zf.writestr('test.txt', b'hello world')

    zip_buffer.seek(0)

    generator = utils.extract_zip_contents(zip_buffer)

    count = 0
    for name, f in generator:
      self.assertEqual(name, 'test.txt')
      self.assertEqual(f.read(), b'hello world')
      count += 1
    self.assertEqual(count, 1)

  def test_extract_zip_contents_duplicate_filenames_and_skips_dirs(self):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
      zf.writestr('subdir/', b'')
      zf.writestr('dup.pkl', b'first_payload')
      zf.writestr('dup.pkl', b'second_payload')

    extracted = [
        (name, stream.read())
        for name, stream in utils.extract_zip_contents(zip_buffer.getvalue())
    ]
    self.assertEqual(
        extracted,
        [('dup.pkl', b'first_payload'), ('dup.pkl', b'second_payload')],
    )

  def test_extract_tar_contents_symlink_and_path_traversal_raises(self):
    for mode, name, linkname in (
        (tarfile.SYMTYPE, 'safe_name', '../../etc/passwd'),
        (tarfile.LNKTYPE, 'safe_link', '/etc/shadow'),
        (tarfile.DIRTYPE, '../escaped_dir', ''),
    ):
      tar_buffer = io.BytesIO()
      with tarfile.open(fileobj=tar_buffer, mode='w') as tf:
        info = tarfile.TarInfo(name=name)
        info.type = mode
        info.linkname = linkname
        tf.addfile(info)
      with self.assertRaises(tarfile.TarError):
        list(utils.extract_tar_contents(tar_buffer.getvalue()))


class PickleDetectionTests(parameterized.TestCase):

  @parameterized.named_parameters(
      dict(
          testcase_name='Safe Pickle file',
          input_file='safe.pkl',
          expected=(True, 107),
      ),
      dict(
          testcase_name='Malicious Pickle file',
          input_file='malicious.pkl',
          expected=(True, 15),
      ),
      dict(
          testcase_name='Large Tensor Checkpoint Pickle file',
          input_file='tensor_checkpoint_400mb.pkl',
          expected=(True, 129),
      ),
      dict(
          testcase_name='Pickle file with invalid bytes',
          input_file='picklescan_tests/malicious-invalid-bytes.pkl',
          expected=(True, 20),
      ),
      dict(
          testcase_name='Pickle file that errors out on unpickling',
          input_file='error_on_unpickling.pkl',
          expected=(True, 16),
      ),
      dict(
          testcase_name='Not a pickle file',
          input_file='not_a_pickle_file.pkl',
          expected=(False, 0),
      ),
  )
  def test_is_pickle_file(self, input_file, expected):
    full_path = os.path.join(_TESTDATA_DIR, input_file)
    if not os.path.exists(full_path):
      self.skipTest(f'{full_path} not present')

    with open(full_path, 'rb') as f:
      data_bytes = f.read()
      self.assertEqual(
          utils.is_pickle_file(data_bytes, return_num_bytes_read=True),
          expected,
      )

  def test_first_byte_not_valid_opcode(self):
    # Starts with an invalid byte
    data = b'\xe9abc'
    is_pickle, count = utils.is_pickle_file(data, return_num_bytes_read=True)
    self.assertFalse(is_pickle)
    self.assertEqual(count, 0)

  def test_2_opcodes_payload_without_stop(self):
    # MARK and INST -> under threshold (3)
    data = b'(iposix\nsystem\n'
    is_pickle, count = utils.is_pickle_file(data, return_num_bytes_read=True)
    self.assertFalse(is_pickle)
    self.assertEqual(count, 2)

  def test_3_opcodes_payload_without_stop(self):
    # MARK, UNICODE, INST -> 3 opcodes
    data = b'(Vls\niposix\nsystem\n'
    is_pickle, count = utils.is_pickle_file(data, return_num_bytes_read=True)
    self.assertTrue(is_pickle)
    self.assertEqual(count, 3)

  def test_magic_byte_bypass_exploit(self):
    # Starts with BM magic bytes but continues with valid opcodes
    standard_exploit = b'cposix\nsystem\n(V/bin/sh\ntR.'
    payload = b'BM\x00\x00\x00' + b'A' * 77 + standard_exploit
    is_pickle, count = utils.is_pickle_file(payload, return_num_bytes_read=True)
    self.assertTrue(is_pickle)
    self.assertEqual(count, 7)

  def test_magic_byte_non_exploit_image(self):
    # Starts with BM magic bytes (which maps to B BINBYTES), but next byte is
    # invalid image byte
    payload = b'BM\x00\x00\x00' + b'A' * 77 + b'\xff\xff'
    is_pickle, count = utils.is_pickle_file(payload, return_num_bytes_read=True)
    self.assertFalse(is_pickle)
    self.assertEqual(count, 1)

  def test_find_pickle_start_offset(self):
    # Standard clean pickle payload
    clean_payload = b'(dp0\n.'
    self.assertEqual(utils.find_pickle_start_offset(clean_payload), 0)

    # Payload hidden behind non-pickle JPEG magic bytes
    standard_exploit = b'cposix\nsystem\n(V/bin/sh\ntR.'
    payload = b'\xff\xd8\xff\xe0' + standard_exploit
    self.assertEqual(utils.find_pickle_start_offset(payload), 4)

    # Completely invalid non-pickle bytes
    invalid_data = b'\xff\x00\xff\x00\xdd\xaa'
    self.assertEqual(utils.find_pickle_start_offset(invalid_data), 0)

  def test_npy_numeric_vs_object_dtype_detection(self):
    def make_npy_bytes(descr: str, payload: bytes) -> tuple[bytes, int]:
      header_dict = (
          f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,)}}"
      ).encode('latin1')
      padding_len = (64 - ((10 + len(header_dict) + 1) % 64)) % 64
      header_body = header_dict + (b' ' * padding_len) + b'\n'
      header = (
          b'\x93NUMPY\x01\x00'
          + len(header_body).to_bytes(2, 'little')
          + header_body
      )
      return header + payload, len(header)

    numeric_npy, _ = make_npy_bytes('<f8', b'\x00' * 128)
    self.assertFalse(utils.is_pickle_file(numeric_npy))
    self.assertEqual(utils.find_pickle_start_offset(numeric_npy), 0)
    self.assertEqual(utils.find_pickle_start_offset(io.BytesIO(numeric_npy)), 0)

    embedded_pickle = pickle.dumps({'hello': 'world'}, protocol=4)
    object_npy, expected_offset = make_npy_bytes('|O', embedded_pickle)
    self.assertTrue(utils.is_pickle_file(object_npy))
    self.assertEqual(
        utils.find_pickle_start_offset(object_npy), expected_offset
    )
    self.assertEqual(
        utils.find_pickle_start_offset(io.BytesIO(object_npy)), expected_offset
    )

  def test_is_pickle_file_large_first_opcode_on_zip_ext_file(self):
    large_first_opcode_pickle = (
        b'\x80\x04B'
        + (4000).to_bytes(4, 'little')
        + (b'x' * 4000)
        + b'\x8c\x05posix\x8c\x06system\x93.'
    )
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
      zf.writestr('model/data.pkl', large_first_opcode_pickle)

    zip_buffer.seek(0)
    with zipfile.ZipFile(zip_buffer, 'r') as zf:
      info = zf.infolist()[0]
      with zf.open(info) as entry_stream:
        self.assertTrue(utils.is_pickle_file(entry_stream))
        self.assertEqual(entry_stream.tell(), 0)

  @parameterized.named_parameters(
      dict(
          testcase_name='single_byte_0_arg_opcodes',
          byte_values=[
              0x28,
              0x29,
              0x2E,
              0x30,
              0x31,
              0x32,
              0x4E,
              0x7D,
              0x5D,
              0x61,
              0x65,
              0x73,
              0x75,
              0x74,
              0x6C,
              0x64,
              0x85,
              0x86,
              0x87,
              0x88,
              0x89,
              0x8F,
              0x90,
              0x91,
              0x94,
              0x97,
              0x98,
          ],
          expected_stride=1,
      ),
      dict(
          testcase_name='two_byte_1_arg_opcodes',
          byte_values=[0x80, 0x4B, 0x68, 0x71],
          expected_stride=2,
      ),
      dict(
          testcase_name='three_byte_2_arg_opcodes',
          byte_values=[0x4D],
          expected_stride=3,
      ),
      dict(
          testcase_name='five_byte_4_arg_opcodes',
          byte_values=[0x4A, 0x6A, 0x72],
          expected_stride=5,
      ),
      dict(
          testcase_name='nine_byte_8_arg_opcodes',
          byte_values=[0x47, 0x95],
          expected_stride=9,
      ),
      dict(
          testcase_name='variable_and_execution_opcodes',
          byte_values=[
              0x8C,
              0x58,
              0x8D,
              0x56,
              0x53,
              0x63,
              0x93,
              0x52,
              0x43,
              0x42,
              0x8E,
              0x96,
              0x69,
              0x6F,
              0x81,
              0x92,
              0x62,
          ],
          expected_stride=-1,
      ),
  )
  def test_opcode_strides(self, byte_values, expected_stride):
    for opcode_byte in byte_values:
      self.assertEqual(utils.OPCODE_STRIDES[opcode_byte], expected_stride)

  def test_opcode_stride_payload_skipping(self):
    # Construct a byte stream with 9-byte, 5-byte, 3-byte, and 2-byte opcodes
    # followed by string opcodes to ensure parser strides skip binary payloads
    # accurately.
    payload = (
        b'\x80\x04'  # PROTO 4 (stride 2)
        b'\x95\x20\x00\x00\x00\x00\x00\x00\x00'  # FRAME 32 (stride 9)
        b'\x47\x40\x24\x00\x00\x00\x00\x00\x00'  # FLOAT 10.0 (stride 9)
        b'\x4a\x00\x04\x00\x00'  # BININT 1024 (stride 5)
        b'\x4d\x2a\x00'  # BININT2 42 (stride 3)
        b'\x4b\x07'  # BININT1 7 (stride 2)
        b'\x94'  # MEMOIZE (stride 1)
        b'\x8c\x06secret'  # SHORT_BINUNICODE 'secret'
        b'\x94'  # MEMOIZE (stride 1)
        b'\x58\x0b\x00\x00\x00large_token'  # BINUNICODE 'large_token'
        b'.'  # STOP (stride 1)
    )

    extracted = [
        operand
        for _, operand in utils.custom_genops_from_bytes(payload)
        if operand is not None
    ]
    self.assertIn('secret', extracted)
    self.assertIn('large_token', extracted)
    self.assertNotIn('FRAME', extracted)

  def test_partition_pickle_chunks_multi_chunk_alignment(self):
    item = b'\x8c\x05alpha\x94\x8c\x04beta\x94'
    payload = b'\x80\x04' + item * 50 + b'.'
    chunks = utils.partition_pickle_chunks(payload, target_chunk_size=128)
    self.assertGreater(len(chunks), 1)
    # Ensure all chunk boundaries align on valid offsets
    for start_offset, end_offset, _ in chunks:
      self.assertLessEqual(start_offset, end_offset)
      self.assertLessEqual(end_offset, len(payload))

    # Verify SHORT_BINUNICODE (0x8c), DUP (0x32), BINUNICODE (0x58), and POP
    # (0x30) update seed_stack across chunk boundaries.
    stack_ops_chunk = (
        b'\x8c\x05posix\x32\x58\x06\x00\x00\x00system\x8c\x07discard\x30'
    )
    stack_payload = b'\x80\x04' + stack_ops_chunk + b'\x8c\x04tail.'
    stack_chunks = utils.partition_pickle_chunks(
        stack_payload, target_chunk_size=len(b'\x80\x04' + stack_ops_chunk)
    )
    self.assertLen(stack_chunks, 2)
    self.assertEqual(stack_chunks[1][2], ['posix', 'posix', 'system'])

  def test_decode_string_operand(self):
    data = b'hello world'
    self.assertEqual(utils.decode_string_operand(data, 0, 5), 'hello')
    self.assertIsNone(utils.decode_string_operand(data, 0, 1))

  def test_custom_genops_from_bytes(self):
    payload = pickle.dumps('test_operand', protocol=4)
    ops = list(utils.custom_genops_from_bytes(payload))
    self.assertTrue(any(operand == 'test_operand' for _, operand in ops))


class IsSafeClassDynamicTest(parameterized.TestCase):

  @parameterized.named_parameters(
      ('torch_layer', 'torch.nn.Linear', utils.Classification.SAFE),
      ('torch_tensor', 'torch.Tensor', utils.Classification.SAFE),
      ('torch_function', 'torch.load', utils.Classification.UNKNOWN),
      ('numpy_ndarray', 'numpy.ndarray', utils.Classification.SAFE),
      ('numpy_function', 'numpy.size', utils.Classification.UNKNOWN),
      ('unsafe_package', 'os.system', utils.Classification.UNSAFE),
      ('unlisted_package', 'unlisted_mod.some_class', None),
  )
  def test_is_safe_class_dynamic(self, symbol, expected):
    self.assertEqual(utils.is_safe_class_dynamic(symbol), expected)

  def test_trojan_mro_subclass_is_flagged_unsafe(self):
    mock_mod = types.ModuleType('custom_pkg.mock_test_tools')
    sys.modules['custom_pkg.mock_test_tools'] = mock_mod
    self.addCleanup(sys.modules.pop, 'custom_pkg.mock_test_tools', None)

    class TrojanProcess(subprocess.Popen):
      pass

    TrojanProcess.__module__ = 'custom_pkg.mock_test_tools'
    mock_mod.TrojanProcess = TrojanProcess

    self.assertEqual(
        utils.is_safe_class_dynamic('custom_pkg.mock_test_tools.TrojanProcess'),
        utils.Classification.UNSAFE,
    )

  def test_custom_internal_layer_is_classified_safe(self):
    mock_mod = types.ModuleType('custom_pkg.mock_gemini_layers')
    sys.modules['custom_pkg.mock_gemini_layers'] = mock_mod
    self.addCleanup(sys.modules.pop, 'custom_pkg.mock_gemini_layers', None)

    class CustomTransformerBlock(torch.nn.Module):
      pass

    CustomTransformerBlock.__module__ = 'custom_pkg.mock_gemini_layers'
    mock_mod.CustomTransformerBlock = CustomTransformerBlock

    self.assertEqual(
        utils.is_safe_class_dynamic(
            'custom_pkg.mock_gemini_layers.CustomTransformerBlock'
        ),
        utils.Classification.SAFE,
    )

  def test_reduce_override_is_flagged_suspicious(self):
    mock_mod = types.ModuleType('custom_pkg.mock_custom_layers')
    sys.modules['custom_pkg.mock_custom_layers'] = mock_mod
    self.addCleanup(sys.modules.pop, 'custom_pkg.mock_custom_layers', None)

    class LayerWithReduce(torch.nn.Module):

      def __reduce__(self):
        return (dict, ())

    LayerWithReduce.__module__ = 'custom_pkg.mock_custom_layers'
    mock_mod.LayerWithReduce = LayerWithReduce

    self.assertEqual(
        utils.is_safe_class_dynamic(
            'custom_pkg.mock_custom_layers.LayerWithReduce'
        ),
        utils.Classification.SUSPICIOUS,
    )

  def test_ast_fallback_without_importing_module(self):
    temp_dir = self.create_tempdir()
    submod_source = (
        'import dataclasses\n'
        'import subprocess\n'
        'import typing\n'
        'from torch import nn\n'
        'raise RuntimeError("Should never be imported!")\n\n'
        'class UnimportedSafeLayer(typing.Generic[int], nn.Module):\n'
        '  pass\n\n'
        '@dataclasses.dataclass(frozen=True)\n'
        'class UnimportedDataclass:\n'
        '  value: int = 1\n\n'
        'class UnimportedTrojan(subprocess.Popen):\n'
        '  pass\n\n'
        'class UnimportedReduceOverride(nn.Module):\n'
        '  def __reduce__(self):\n'
        '    return (dict, ())\n\n'
        'def unimported_helper_func():\n'
        '  return 42\n'
    )
    temp_dir.create_file('unimported_ast_target.py', content=submod_source)

    mock_pkg = types.ModuleType('custom_pkg.mock_ast_pkg')
    mock_pkg.__path__ = [temp_dir.full_path]
    sys.modules['custom_pkg.mock_ast_pkg'] = mock_pkg
    self.addCleanup(sys.modules.pop, 'custom_pkg.mock_ast_pkg', None)
    self.addCleanup(utils.classify_symbol.cache_clear)
    self.addCleanup(utils._inspect_class_via_ast.cache_clear)

    for cls_name, expected in (
        ('UnimportedSafeLayer', utils.Classification.SAFE),
        ('UnimportedDataclass', utils.Classification.SAFE),
        ('UnimportedTrojan', utils.Classification.UNSAFE),
        ('UnimportedReduceOverride', utils.Classification.SUSPICIOUS),
        ('unimported_helper_func', utils.Classification.UNKNOWN),
    ):
      self.assertEqual(
          utils.is_safe_class_dynamic(
              f'custom_pkg.mock_ast_pkg.unimported_ast_target.{cls_name}'
          ),
          expected,
      )
    self.assertNotIn('custom_pkg.mock_ast_pkg.unimported_ast_target', sys.modules)

  def test_custom_pkg_non_class_function_not_marked_safe(self):
    self.assertEqual(
        utils.classify_symbol('custom_pkg.io.file_utils.delete_recursively'),
        utils.Classification.UNKNOWN,
    )
    self.assertEqual(
        utils.classify_symbol('numpy.core.multiarray._reconstruct'),
        utils.Classification.SAFE,
    )

  @parameterized.named_parameters(
      ('truncated_prefix_short', b'\x80\x04B\x01\x00', False, 2),
      ('truncated_prefix_suspected', b'\x80\x04}\x94B\x01', True, 4),
      ('truncated_payload_short', b'\x80\x04B\x10\x00\x00\x00abc', False, 2),
      (
          'truncated_payload_suspected',
          b'\x80\x04}\x94B\x10\x00\x00\x00abc',
          True,
          4,
      ),
  )
  def test_is_pickle_file_length_prefix_truncation_and_bounds(
      self, payload, expected_ok, expected_bytes
  ):
    self.assertEqual(utils.is_pickle_file(payload), expected_ok)
    self.assertEqual(
        utils.is_pickle_file(payload, return_num_bytes_read=True),
        (expected_ok, expected_bytes),
    )

  def test_paired_quote_token_extraction_and_unsafe_primitives(self):
    log_stream = io.StringIO(
        'WARNING:picklemagic:FakeClass method eval called on <class'
        " 'corrupy.picklemagic.FakeWarning'> with"
        " args=(\"__import__('os').system('id')\",), kwargs={}\n"
    )
    _, unsafe_results, _, _ = utils.categorize_picklemagic(log_stream)
    self.assertIn("__import__('os').system('id')", unsafe_results)

    for unsafe_symbol in (
        'torch.utils.collect_env.run',
        'multiprocessing.util.spawnv_passfds',
        'mlflow.projects.backend.local._run_entry_point',
        'pandas.io.parsers.readers.read_csv',
        'transformers.AutoModelForCausalLM.from_pretrained',
        'torch._inductor.codecache.getattribute_from_module',
    ):
      self.assertEqual(
          utils.classify_symbol(unsafe_symbol),
          utils.Classification.UNSAFE,
          msg=f'Expected {unsafe_symbol} to be UNSAFE',
      )

  def test_self_protected_symbols_cannot_be_allowlisted(self):
    for protected_symbol in (
        'safer_pickle.unhook_pickle',
        'saferpickle.safer_pickle.unhook_pickle',
        'corrupy.picklemagic.SafeUnpickler',
        'picklemagic.SafeUnpickler',
        'config.set_config_path',
        'set_config_path',
    ):
      self.assertTrue(utils.is_self_protected_symbol(protected_symbol))

    for non_protected_symbol in (
        'corrupy.picklemagic.FakeWarning',
        'picklemagic.failed_reduce',
        'numpy.ndarray',
    ):
      self.assertFalse(utils.is_self_protected_symbol(non_protected_symbol))

    temp_dir = self.create_tempdir()
    cfg_file = temp_dir.create_file(
        'config.json',
        content=(
            '{"safer_pickle": {"allow_list": ["safer_pickle", "saferpickle",'
            ' "corrupy", "picklemagic", "config.set_config_path"]}}'
        ),
    )
    utils.config.set_config_path(cfg_file.full_path)
    self.addCleanup(utils.config.set_config_path, None)

    self.assertTrue(utils.is_unsafe_for_fail_fast('safer_pickle.unhook_pickle'))
    self.assertTrue(
        utils.is_unsafe_for_fail_fast('saferpickle.safer_pickle.unhook_pickle')
    )
    self.assertTrue(utils.is_unsafe_for_fail_fast('config.set_config_path'))

  def test_resolve_extension_code_and_ext_opcodes(self):
    copyreg.add_extension('posix', 'system', 142)
    copyreg.add_extension('shutil', 'rmtree', 1042)
    copyreg.add_extension('collections', 'OrderedDict', 100042)
    self.addCleanup(copyreg.remove_extension, 'posix', 'system', 142)
    self.addCleanup(copyreg.remove_extension, 'shutil', 'rmtree', 1042)
    self.addCleanup(
        copyreg.remove_extension, 'collections', 'OrderedDict', 100042
    )

    self.assertEqual(utils.resolve_extension_code(142), 'posix.system')
    self.assertEqual(utils.resolve_extension_code(1042), 'shutil.rmtree')
    self.assertEqual(
        utils.resolve_extension_code(100042), 'collections.OrderedDict'
    )
    self.assertEqual(
        utils.resolve_extension_code(999999),
        'unregistered_extension.code_999999',
    )

    # EXT1 (0x82), EXT2 (0x83), EXT4 (0x84), plus unregistered EXT1
    payload = (
        b'\x80\x04'
        + b'\x82'
        + (142).to_bytes(1, 'little')
        + b'\x83'
        + (1042).to_bytes(2, 'little')
        + b'\x84'
        + (100042).to_bytes(4, 'little', signed=True)
        + b'\x82\xff.'
    )
    emitted = [
        (op.name, arg) for op, arg in utils.custom_genops_from_bytes(payload)
    ]
    self.assertEqual(
        emitted,
        [
            ('EXT1', 'posix.system'),
            ('EXT2', 'shutil.rmtree'),
            ('EXT4', 'collections.OrderedDict'),
            ('EXT1', 'unregistered_extension.code_255'),
        ],
    )
    chunks = utils.partition_pickle_chunks(payload, target_chunk_size=4)
    self.assertNotEmpty(chunks)

  def test_protocol0_put_get_and_persid_binpersid_opcodes(self):
    # Protocol 0 PUT ('p') and GET ('g') used to reassemble STACK_GLOBAL (\x93)
    proto0_put_get_payload = (
        b"S'shutil'\np0\n0S'rmtree'\np1\n0g0\ng1\n\x93(S'/tmp/x'\ntR."
    )
    emitted = [
        (op.name, arg)
        for op, arg in utils.custom_genops_from_bytes(proto0_put_get_payload)
    ]
    self.assertIn(('STACK_GLOBAL', 'shutil.rmtree'), emitted)

    # PERSID ('P') and BINPERSID ('Q')
    persid_payload = b'Pcustom_external_ref\n.'
    persid_ops = [
        (op.name, arg)
        for op, arg in utils.custom_genops_from_bytes(persid_payload)
    ]
    self.assertEqual(
        persid_ops, [('PERSID', 'persistent_id.custom_external_ref')]
    )

    # Verify a 'storage' BINPERSID clears recent_strings so a subsequent
    # non-storage BINPERSID is still caught.
    binpersid_payload = (
        b'\x80\x04\x8c\x07storage\x8c\x03cpu\x86Q\x8c\x0cevil_ref_objQ.'
    )
    binpersid_ops = [
        (op.name, arg)
        for op, arg in utils.custom_genops_from_bytes(binpersid_payload)
        if op.name == 'BINPERSID'
    ]
    self.assertEqual(
        binpersid_ops, [('BINPERSID', 'persistent_id.evil_ref_obj')]
    )

  def test_approved_root_submodule_and_literal_false_positive_guards(self):
    # Approved root package submodule named _pickle is not flagged UNSAFE
    self.assertEqual(
        utils.classify_symbol('numpy.random._pickle.__randomstate_ctor'),
        utils.Classification.UNKNOWN,
    )

    # Benign domain names, filenames, and multi-line docs are not flagged
    for benign_literal in (
        'code.org',
        'docs.example.com',
        'profile.txt',
        'site.html',
        'prod.cluster.os.worker.r0',
        'import os\nimport json\n',
    ):
      self.assertFalse(
          utils.is_potentially_dangerous_literal(benign_literal),
          f'Unexpectedly flagged benign literal: {benign_literal}',
      )

    # Indirect execution traversals, dunder chains, and one-liners are flagged
    for dangerous_literal in (
        'torch.serialization.os.system',
        '__class__.__base__.__subclasses__',
        "__import__('os').system('id')",
        "import requests; requests.get('http://127.0.0.1')",
    ):
      self.assertTrue(
          utils.is_potentially_dangerous_literal(dangerous_literal),
          f'Failed to flag dangerous literal: {dangerous_literal}',
      )

  def test_get_module_members_handles_find_spec_errors_and_frozen_origin(self):
    with unittest.mock.patch.object(
        utils.importlib.util,
        'find_spec',
        side_effect=ImportError('missing parent'),
    ):
      self.assertIsNone(utils.get_module_members('unimported_parent.child'))

    mock_frozen_spec = unittest.mock.MagicMock()
    mock_frozen_spec.origin = 'frozen'
    with unittest.mock.patch.object(
        utils.importlib.util, 'find_spec', return_value=mock_frozen_spec
    ):
      self.assertIsNone(utils.get_module_members('frozen_stdlib_mod'))

  @parameterized.named_parameters(
      (
          'py2_builtin_globals',
          '__builtin__.globals',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'py2_builtin_type',
          '__builtin__.type',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'py2_builtin_breakpoint',
          '__builtin__.breakpoint',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'py2_builtin_ellipsis',
          '__builtin__.Ellipsis',
          utils.Classification.SAFE,
      ),
      (
          'py3_builtins_ellipsis',
          'builtins.Ellipsis',
          utils.Classification.SAFE,
      ),
      (
          'compat_cpickle_loads',
          'cPickle.loads',
          utils.Classification.UNSAFE,
      ),
      (
          'compat_xmlrpc_dotted_attr',
          'SimpleXMLRPCServer.resolve_dotted_attribute',
          utils.Classification.UNSAFE,
      ),
      (
          'compat_builtin_intern',
          '__builtin__.intern',
          utils.Classification.UNSAFE,
      ),
      (
          'compat_userdict',
          'UserDict.UserDict',
          utils.Classification.SAFE,
      ),
      (
          'pathway_a_closure_dict',
          'collections.OrderedDict.__init__.__closure__.dict',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_a_base_dict_list',
          'collections.OrderedDict.__base__.__dict__.list',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'introspection_prefix_f_globals',
          'torch.nn.Module.__init__.f_globals.Module',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_b_custom_pkg_dunder_chain',
          'custom_pkg.pkg.mod.Cls.__init__.__dict__.TargetClass',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_b_custom_pkg_class_hop',
          'custom_pkg.pkg.mod.Cls.attr.TargetClass',
          utils.Classification.UNKNOWN,
      ),
      (
          'pathway_c_closure_attr',
          'collections.OrderedDict.__closure__',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_c_defaults_attr',
          'collections.OrderedDict.__defaults__',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_c_kwdefaults_attr',
          'collections.OrderedDict.__kwdefaults__',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'safe_terminal_name_metadata',
          'collections.OrderedDict.__name__',
          utils.Classification.SAFE,
      ),
      (
          'safe_terminal_doc_metadata',
          'collections.OrderedDict.__doc__',
          utils.Classification.SAFE,
      ),
  )
  def test_structural_builtin_compat_and_dunder_classifications(
      self, symbol, expected_classification
  ):
    """Verifies builtin, Python 2 compatibility, and dunder chain classifications.

    Args:
      symbol: Dotted symbol string to classify.
      expected_classification: Expected `utils.Classification` enum value.

    Returns:
      None.
    """
    utils.classify_symbol.cache_clear()
    self.assertEqual(utils.classify_symbol(symbol), expected_classification)

  def test_all_base_class_specs_safe_when_unimported(self):
    """Verifies `ALL_BASE_CLASS_SPECS` entries classify as SAFE when unimported.

    Temporarily removes `datetime` from `sys.modules` and checks every base
    class specification in `constants.ALL_BASE_CLASS_SPECS`.

    Returns:
      None.
    """
    self.addCleanup(utils.classify_symbol.cache_clear)
    saved_datetime = sys.modules.pop('datetime', None)
    if saved_datetime is not None:
      self.addCleanup(sys.modules.__setitem__, 'datetime', saved_datetime)

    utils.classify_symbol.cache_clear()
    for base_spec in utils.constants.ALL_BASE_CLASS_SPECS:
      self.assertEqual(
          utils.classify_symbol(base_spec),
          utils.Classification.SAFE,
          f'Expected {base_spec} to be SAFE even when unimported',
      )


if __name__ == '__main__':
  googletest.main()

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

import abc
from collections.abc import Mapping
import copyreg
import dataclasses
import decimal
import functools
import importlib.machinery
import io
import os
import pickle
import subprocess
import sys
import tarfile
import types
from typing import Any
import unittest.mock
import uuid
import zipfile
# Imported so runtime library hooks can resolve these modules during tests.
import cloudpickle
import dill
import joblib
from lib import utils
import torch
from absl.testing import absltest
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
    self.assertEmpty(
        utils.constants.SAFE_STRINGS & utils.constants.APPROVED_ROOT_PACKAGES
    )
    base_short_names = {
        spec.rsplit('.', 1)[-1] for spec in utils.constants.ALL_BASE_CLASS_SPECS
    }
    self.assertEmpty(base_short_names - utils.constants.APPROVED_AST_BASE_NAMES)

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

  def test_trailing_zip_v7_tar_and_bounded_lzma_alone_matchers(self):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
      zf.writestr('safe.pkl', pickle.dumps({'k': 1}, protocol=4))
    prefixed_zip = b'JUNK_PREFIX_NOT_PK' + zip_buf.getvalue()
    prefixed_stream = io.BytesIO(prefixed_zip)
    prefixed_stream.seek(4)

    self.assertFalse(utils.is_zip_bytes(prefixed_zip))
    self.assertEqual(utils.detect_archive_type(prefixed_zip), 'zip')
    self.assertEqual(utils.detect_archive_type(prefixed_stream), 'zip')
    self.assertEqual(prefixed_stream.tell(), 4)

    lzma_alone = utils.lzma.compress(
        pickle.dumps('hello'), format=utils.lzma.FORMAT_ALONE
    )
    self.assertTrue(utils.is_lzma_bytes(lzma_alone))

    tar_buf = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buf, mode='w', format=tarfile.USTAR_FORMAT
    ) as tf:
      payload = pickle.dumps({'x': 1}, protocol=4)
      info = tarfile.TarInfo(name='entry.pkl')
      info.size = len(payload)
      tf.addfile(info, io.BytesIO(payload))
    raw_v7 = bytearray(tar_buf.getvalue())
    raw_v7[257:265] = b'\x00' * 8
    raw_v7[148:156] = b' ' * 8
    chksum = sum(raw_v7[:512])
    raw_v7[148:156] = f'{chksum:06o}\x00 '.encode('ascii')
    v7_tar_bytes = bytes(raw_v7)

    self.assertTrue(utils.is_tar_bytes(v7_tar_bytes))
    self.assertEqual(utils.detect_archive_type(v7_tar_bytes), 'tar')

    benign_ustar_pickle = pickle.dumps(
        {'pad': 'a' * 222, 'flavor': 'mustard', 'tail': 'b' * 300},
        protocol=4,
    )
    self.assertEqual(benign_ustar_pickle[257:262], b'ustar')
    self.assertFalse(utils.is_tar_bytes(benign_ustar_pickle))

    tiny_file = os.path.join(self.create_tempdir().full_path, 'tiny_18b.pkl')
    with open(tiny_file, 'wb') as f:
      f.write(pickle.dumps({'ok': 123}))
    with open(tiny_file, 'rb') as f:
      self.assertFalse(utils.is_zip_bytes(f))
      self.assertIsNone(utils.detect_archive_type(f))
      self.assertEqual(f.tell(), 0)

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

    # Text prefix bytes that are valid non-initial opcodes ('l', 'a', 'i', 't')
    text_prefixed = b'plain text\n' + standard_exploit
    self.assertEqual(utils.find_pickle_start_offset(text_prefixed), 11)

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

  @parameterized.named_parameters(
      ('repeat_count', "{'descr': '2O'}", True),
      ('comma_fields', "{'descr': 'i4,O'}", True),
      ('subarray', "{'descr': '(2,)O'}", True),
      ('object_alias', "{'descr': 'object_'}", True),
      ('nested_field', "{'descr': [('a', [('b', '|O')])]}", True),
      ('escaped', r"{'descr': '\x4f'}", True),
      ('py2_long_shape_object', "{'descr': 'O', 'shape': (8L,)}", True),
      ('unparseable', "{'descr': <f8}", True),
      ('numeric', "{'descr': '<f8'}", False),
      ('numeric_field_named_o', "{'descr': [('O', '<f8')]}", False),
      ('py2_long_shape_numeric', "{'descr': '<f8', 'shape': (8L,)}", False),
  )
  def test_is_object_npy_header(self, header, expected):
    self.assertEqual(utils._is_object_npy_header(header.encode()), expected)

  @parameterized.named_parameters(
      ('zlib_pickle', ('zlib',), b'\x80\x04N.', 'zlib'),
      ('zlib_npy', ('zlib',), b'\x93NUMPY\x01\x00', 'zlib'),
      ('zlib_wrapping_gzip', ('gzip', 'zlib'), b'plain text', 'zlib'),
      ('zlib_empty_stream', ('zlib',), b'', 'zlib'),
      ('zlib_full_peek_of_empty_blocks', ('empty_blocks',), b'', 'zlib'),
      ('zlib_text', ('zlib',), b'plain text', None),
      ('zlib_nested_text', ('zlib', 'zlib'), b'plain text', None),
      (
          'zlib_nesting_limit_trusts_header',
          ('zlib',) * 4,
          b'plain text',
          'zlib',
      ),
      ('joblib_zfile_pickle', ('zfile',), b'\x80\x04N.', 'zlib'),
      ('lzma_alone_pickle', ('alone',), b'\x80\x04N.', 'lzma'),
      ('lzma_alone_text', ('alone',), b'plain text', None),
      ('protocol0_pickle_with_zlib_like_header', (), b"(S'abc'\np0\n.", None),
      (
          'int32_tensor_with_lzma_like_header',
          (),
          b'\x03\0\0\0\x01\0\0\0' * 40,
          None,
      ),
  )
  def test_detect_archive_type_weak_magic_streams(self, layers, data, expected):
    def to_zfile(raw):
      return b'ZF' + hex(len(raw)).encode().ljust(19) + utils.zlib.compress(raw)

    def to_empty_blocks(unused_raw):
      return b'\x78\x01' + b'\x00\x00\x00\xff\xff' * 60

    encoders = {
        'zlib': utils.zlib.compress,
        'gzip': utils.gzip.compress,
        'zfile': to_zfile,
        'empty_blocks': to_empty_blocks,
        'alone': functools.partial(
            utils.lzma.compress, format=utils.lzma.FORMAT_ALONE
        ),
    }
    for layer in layers:
      data = encoders[layer](data)

    self.assertEqual(utils.detect_archive_type(data), expected)

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
    self.assertEqual(utils.classify_approved_root_symbol(symbol), expected)

  def _register_fake_module_symbol(
      self, module_name: str, cls: type[object]
  ) -> str:
    """Registers a synthetic module and class in `sys.modules` for the test.

    Args:
      module_name: Dotted module path to register in `sys.modules`.
      cls: Class object to attach to the synthetic module.

    Returns:
      The fully qualified dotted symbol path `<module_name>.<cls.__name__>`.
    """
    mock_mod = types.ModuleType(module_name)
    sys.modules[module_name] = mock_mod
    self.addCleanup(sys.modules.pop, module_name, None)

    cls.__module__ = module_name
    setattr(mock_mod, cls.__name__, cls)
    return f'{module_name}.{cls.__name__}'

  def _register_temp_ast_package(
      self, pkg_name: str, file_name: str, source: str
  ) -> None:
    """Creates an unimported `.py` file under a synthetic package in `sys.modules`.

    Args:
      pkg_name: Dotted package name to register in `sys.modules`.
      file_name: Relative `.py` filename to create inside the temp directory.
      source: Python source code written to `file_name`.

    Returns:
      None.
    """
    temp_dir = self.create_tempdir()
    temp_dir.create_file(file_name, content=source)

    mock_pkg = types.ModuleType(pkg_name)
    mock_pkg.__path__ = [temp_dir.full_path]
    sys.modules[pkg_name] = mock_pkg
    self.addCleanup(sys.modules.pop, pkg_name, None)
    self.addCleanup(utils.classify_symbol.cache_clear)
    self.addCleanup(utils._inspect_class_via_ast.cache_clear)

  def test_trojan_mro_subclass_is_flagged_unsafe(self):
    class TrojanProcess(subprocess.Popen):
      pass

    symbol = self._register_fake_module_symbol(
        'typing.mock_test_tools', TrojanProcess
    )
    self.assertEqual(
        utils.classify_approved_root_symbol(symbol), utils.Classification.UNSAFE
    )

  def test_custom_internal_layer_is_classified_safe(self):
    class CustomTransformerBlock(torch.nn.Module):
      pass

    symbol = self._register_fake_module_symbol(
        'typing.mock_transformer_layers', CustomTransformerBlock
    )
    self.assertEqual(
        utils.classify_approved_root_symbol(symbol), utils.Classification.SAFE
    )

  def test_reduce_override_is_flagged_suspicious(self):
    class LayerWithReduce(torch.nn.Module):

      def __reduce__(self):
        return (dict, ())

    symbol = self._register_fake_module_symbol(
        'typing.mock_custom_layers', LayerWithReduce
    )
    self.assertEqual(
        utils.classify_approved_root_symbol(symbol),
        utils.Classification.SUSPICIOUS,
    )

  def test_ast_fallback_without_importing_module(self):
    self._register_temp_ast_package(
        'typing.mock_ast_pkg',
        'unimported_ast_target.py',
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
        '  return 42\n',
    )

    for cls_name, expected in (
        ('UnimportedSafeLayer', utils.Classification.SAFE),
        ('UnimportedDataclass', utils.Classification.SAFE),
        ('UnimportedTrojan', utils.Classification.UNSAFE),
        ('UnimportedReduceOverride', utils.Classification.SUSPICIOUS),
        ('unimported_helper_func', utils.Classification.UNKNOWN),
    ):
      self.assertEqual(
          utils.classify_approved_root_symbol(
              f'typing.mock_ast_pkg.unimported_ast_target.{cls_name}'
          ),
          expected,
      )
    self.assertNotIn('typing.mock_ast_pkg.unimported_ast_target', sys.modules)

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
        'third_party.corrupy.picklemagic.SafeUnpickler',
        'picklemagic.SafeUnpickler',
        'config.set_config_path',
        'set_config_path',
    ):
      self.assertTrue(utils.is_self_protected_symbol(protected_symbol))

    for non_protected_symbol in (
        'corrupy.picklemagic.FakeClass',
        'corrupy.picklemagic.FakeWarning',
        'third_party.corrupy.picklemagic.FakeClass',
        'third_party.corrupy.picklemagic.FakeWarning',
        'picklemagic.failed_reduce',
        'numpy.ndarray',
    ):
      self.assertFalse(utils.is_self_protected_symbol(non_protected_symbol))

    temp_dir = self.create_tempdir()
    cfg_file = temp_dir.create_file(
        'config.json',
        content=(
            '{"safer_pickle": {"allow_list": ["safer_pickle", "saferpickle",'
            ' "corrupy", "third_party.corrupy", "picklemagic",'
            ' "config.set_config_path"]}}'
        ),
    )
    utils.config.set_config_path(cfg_file.full_path)
    self.addCleanup(utils.config.set_config_path, None)

    self.assertTrue(utils.is_unsafe_for_fail_fast('safer_pickle.unhook_pickle'))
    self.assertTrue(
        utils.is_unsafe_for_fail_fast('saferpickle.safer_pickle.unhook_pickle')
    )
    self.assertTrue(
        utils.is_unsafe_for_fail_fast(
            'third_party.corrupy.picklemagic.SafeUnpickler'
        )
    )
    self.assertTrue(utils.is_unsafe_for_fail_fast('config.set_config_path'))

  def test_oss_corrupy_and_fake_class_symbols_classified_accurately(self):
    for safe_symbol in (
        'corrupy.picklemagic.FakeClass',
        'corrupy.picklemagic.FakeWarning',
        'third_party.corrupy.picklemagic.FakeClass',
        'third_party.corrupy.picklemagic.FakeWarning',
        'third_party.corrupy.picklemagic._SaferFakeWarning',
        'third_party.corrupy.picklemagic._BoundSaferFakeWarning',
    ):
      self.assertEqual(
          utils.classify_symbol(safe_symbol), utils.Classification.SAFE
      )

    self.assertEqual(
        utils.classify_symbol('third_party.corrupy.picklemagic.SafeUnpickler'),
        utils.Classification.UNSAFE,
    )

    log_stream = io.StringIO(
        'WARNING:picklemagic:FakeClass method eval called on <class'
        " 'third_party.corrupy.picklemagic.FakeWarning'> with"
        " args=('x',), kwargs={}\n"
        'WARNING:picklemagic:FakeWarning.__setstate__ called on <class'
        " 'third_party.corrupy.picklemagic.FakeClass'> with"
        " unexpected state={'a': 1}\n"
    )
    _, unsafe_results, suspicious_results, _ = utils.categorize_picklemagic(
        log_stream
    )
    self.assertEqual(unsafe_results, {'eval'})
    self.assertEmpty(suspicious_results)

  def test_ast_plain_object_constructor_checks_dangerous_names(self):
    self._register_temp_ast_package(
        'scipy.mock_ast_plain_pkg',
        'plain_ast_target.py',
        'from pydoc import locate as benign_alias\n'
        'raise RuntimeError("Should never be imported!")\n\n'
        'class SafePlainConfig:\n'
        '  def __init__(self, lr: float = 0.01):\n'
        '    self.lr = lr\n\n'
        'class DangerousImportCtor:\n'
        '  def __init__(self, cmd: str):\n'
        '    import os\n'
        '    os.system(cmd)\n\n'
        'class DangerousAliasCtor:\n'
        '  def __init__(self, target: str):\n'
        '    benign_alias(target)\n\n'
        'class DangerousAttrCtor:\n'
        '  def __init__(self, runner):\n'
        '    runner.popen("id")\n\n'
        'class AssignedCtor:\n'
        '  __init__ = len\n',
    )

    for cls_name, expected in (
        ('SafePlainConfig', utils.Classification.SAFE),
        ('DangerousImportCtor', utils.Classification.UNKNOWN),
        ('DangerousAliasCtor', utils.Classification.UNKNOWN),
        ('DangerousAttrCtor', utils.Classification.UNKNOWN),
        ('AssignedCtor', utils.Classification.UNKNOWN),
    ):
      self.assertEqual(
          utils.classify_approved_root_symbol(
              f'scipy.mock_ast_plain_pkg.plain_ast_target.{cls_name}'
          ),
          expected,
      )
    self.assertNotIn('scipy.mock_ast_plain_pkg.plain_ast_target', sys.modules)

  def _register_fake_class(
      self,
      module_name: str,
      *,
      bases: tuple[type[Any], ...] = (),
      is_dataclass: bool = False,
      methods: Mapping[str, Any] | None = None,
  ) -> str:
    """Creates a synthetic class and registers it under `module_name`.

    Args:
      module_name: Dotted module path to register in `sys.modules`.
      bases: Base classes for the synthetic class.
      is_dataclass: Whether to wrap the class with `@dataclasses.dataclass`.
      methods: Optional mapping of method names to callables.

    Returns:
      The fully qualified dotted symbol path `<module_name>.SampleClass`.
    """
    attrs: dict[str, Any] = {'__annotations__': {'x': str}, 'x': ''}
    for name, fn in (methods or {}).items():
      if isinstance(fn, types.FunctionType):
        cloned = types.FunctionType(
            fn.__code__,
            fn.__globals__,
            name,
            fn.__defaults__,
            fn.__closure__,
        )
        cloned.__module__ = module_name
        attrs[name] = cloned
      else:
        attrs[name] = fn

    cls: Any = type('SampleClass', bases, attrs)
    if is_dataclass:
      cls = dataclasses.dataclass(cls)
    return self._register_fake_module_symbol(module_name, cls)

  @parameterized.named_parameters(
      dict(
          testcase_name='safe_dataclass_setstate',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={
              '__setstate__': lambda self, state: object.__setattr__(
                  self, 'x', state
              )
          },
          expected=utils.Classification.SAFE,
      ),
      dict(
          testcase_name='dataclass_direct_os_system',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={'__setstate__': lambda self, state: os.system('id')},
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='dataclass_missing_object_setattr',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={'__setstate__': lambda self, state: state[0](state[1])},
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='dataclass_method_delegation',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={
              '_helper': lambda self, cmd: os.system(cmd),
              '__setstate__': lambda self, state: (
                  object.__setattr__(self, 'x', 'ok'),
                  self._helper('id'),
              ),
          },
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='dataclass_partial_callable',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={
              '__setstate__': lambda self, state, fn=functools.partial(
                  os.system
              ): (
                  object.__setattr__(self, 'x', 'ok'),
                  fn('id'),
              )
          },
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='dataclass_external_torch_load',
          pkg='typing.mock_dc',
          is_dataclass=True,
          methods={
              '__setstate__': lambda self, state: (
                  object.__setattr__(self, 'x', 'ok'),
                  torch.load(state),
              )
          },
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='bare_abc_in_restricted_root',
          pkg='typing.mock_abc',
          bases=(abc.ABC,),
          expected=utils.Classification.UNKNOWN,
      ),
      dict(
          testcase_name='torch_module_with_unsafe_new',
          pkg='typing.mock_new',
          bases=(torch.nn.Module,),
          methods={'__new__': lambda cls, *args: os.system('id')},
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='sklearn_unsafe_init_does_not_mask_setstate',
          pkg='sklearn.mock_est',
          methods={
              '__init__': lambda self: os.system('id'),
              '__setstate__': lambda self, state: os.system('id'),
          },
          expected=utils.Classification.SUSPICIOUS,
      ),
  )
  def test_loaded_class_hook_classification(
      self, pkg, expected, bases=(), is_dataclass=False, methods=None
  ):
    symbol = self._register_fake_class(
        pkg, bases=bases, is_dataclass=is_dataclass, methods=methods
    )
    self.assertEqual(utils.classify_approved_root_symbol(symbol), expected)

  @parameterized.named_parameters(
      (
          'safe_slotted_dataclass',
          (
              '@dataclasses.dataclass(frozen=True, slots=True)\n'
              'class Target:\n'
              '  x: str = ""\n'
              '  def __setstate__(self, state):\n'
              '    object.__setattr__(self, "x", "ok")\n'
          ),
          utils.Classification.SAFE,
      ),
      (
          'dataclass_helper_calls_aliased_popen',
          (
              'from subprocess import Popen as Alias\n'
              'def _helper(cmd):\n'
              '  Alias(cmd)\n'
              '@dataclasses.dataclass\n'
              'class Target:\n'
              '  def __setstate__(self, state):\n'
              '    object.__setattr__(self, "x", "ok")\n'
              '    _helper("id")\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'dataclass_inherited_method_delegation',
          (
              'class Base:\n'
              '  def _exec(self, cmd):\n'
              '    import os\n'
              '    os.system(cmd)\n'
              '@dataclasses.dataclass\n'
              'class Target(Base):\n'
              '  def __setstate__(self, state):\n'
              '    object.__setattr__(self, "x", "ok")\n'
              '    self._exec("id")\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'dataclass_unapproved_dotted_import',
          (
              '@dataclasses.dataclass\n'
              'class Target:\n'
              '  def __setstate__(self, state):\n'
              '    import torch.hub\n'
              '    object.__setattr__(self, "x", "ok")\n'
              '    torch.hub.load("x", "y")\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'bare_abc_in_restricted_root',
          'import abc\nclass Target(abc.ABC):\n  pass\n',
          utils.Classification.UNKNOWN,
      ),
      (
          'torch_module_with_unsafe_new',
          (
              'from torch import nn\n'
              'class Target(nn.Module):\n'
              '  def __new__(cls, *args):\n'
              '    import os\n'
              '    os.system("id")\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'local_import_shadowing_top_func',
          (
              'def _helper(x):\n'
              '  return x\n'
              '@dataclasses.dataclass\n'
              'class Target:\n'
              '  def __setstate__(self, state):\n'
              '    from torch.hub import load as _helper\n'
              '    object.__setattr__(self, "x", "ok")\n'
              '    _helper(state)\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'positional_only_self_delegation',
          (
              'class Base:\n'
              '  def _exec(self, cmd):\n'
              '    import os\n'
              '    os.system(cmd)\n'
              '@dataclasses.dataclass\n'
              'class Target(Base):\n'
              '  def __setstate__(self, /, state):\n'
              '    object.__setattr__(self, "x", "ok")\n'
              '    self._exec(state)\n'
          ),
          utils.Classification.SUSPICIOUS,
      ),
      (
          'non_restricted_helper_class_method_and_unsafe_init',
          (
              'import subprocess\n'
              'class UnknownHelper:\n'
              '  def __init__(self):\n'
              '    import os\n'
              '    os.system("id")\n'
              'class UnsafeHelper(subprocess.Popen):\n'
              '  pass\n'
              'class Target:\n'
              '  def __init__(self, cmd):\n'
              '    UnknownHelper()\n'
              '    UnsafeHelper(cmd)\n'
          ),
          utils.Classification.UNSAFE,
          'scipy.mock_ast_hooks',
      ),
      (
          'non_restricted_helper_class_method_call',
          (
              'class Helper:\n'
              '  def run(self, cmd):\n'
              '    import os\n'
              '    os.system(cmd)\n'
              'class Target:\n'
              '  def run(self, cmd):\n'
              '    return cmd\n'
              '  def __setstate__(self, state):\n'
              '    Helper().run(state)\n'
          ),
          utils.Classification.SUSPICIOUS,
          'scipy.mock_ast_hooks',
      ),
  )
  def test_ast_unimported_class_hook_classification(
      self, snippet, expected, pkg='typing.mock_ast_hooks'
  ):
    self._register_temp_ast_package(
        pkg,
        'target_mod.py',
        'import dataclasses\nraise RuntimeError("Never import!")\n\n' + snippet,
    )
    self.assertEqual(
        utils.classify_approved_root_symbol(f'{pkg}.target_mod.Target'),
        expected,
    )
    self.assertNotIn(f'{pkg}.target_mod', sys.modules)

  def test_ast_reexport_classification(self):
    temp_dir = self.create_tempdir()
    ext_suffix = utils.constants.EXTENSION_SUFFIXES[0]
    temp_dir.create_file(f'_compiled_ext{ext_suffix}', content='')
    temp_dir.create_file(
        'reexport.py',
        content=(
            'from ._compiled_ext import SafeCompiledClass\n'
            'from ._compiled_ext import arbitrary_c_func\n'
            'from ._compiled_ext import savetxt as alias_savetxt\n'
            'from builtins import getattr as alias_getattr\n'
            'import subprocess as alias_subproc\n'
        ),
    )

    mock_pkg = types.ModuleType('scipy.mock_reexport_pkg')
    mock_pkg.__path__ = [temp_dir.full_path]
    sys.modules['scipy.mock_reexport_pkg'] = mock_pkg
    self.addCleanup(sys.modules.pop, 'scipy.mock_reexport_pkg', None)
    self.addCleanup(utils.classify_symbol.cache_clear)
    self.addCleanup(utils._inspect_class_via_ast.cache_clear)

    for attr_name, expected in (
        ('SafeCompiledClass', utils.Classification.SAFE),
        ('arbitrary_c_func', utils.Classification.UNKNOWN),
        ('alias_savetxt', utils.Classification.UNSAFE),
        ('alias_subproc', utils.Classification.UNSAFE),
        ('alias_getattr', utils.Classification.SUSPICIOUS),
    ):
      self.assertEqual(
          utils.classify_approved_root_symbol(
              f'scipy.mock_reexport_pkg.reexport.{attr_name}'
          ),
          expected,
      )

  def test_approved_root_reconstructors_and_lazy_base_cache(self):
    self.assertIsNone(utils._find_module_source_file('sklearn./tmp/evil'))
    self.assertIsNone(
        utils.classify_approved_root_symbol('sklearn./tmp/evil.Cls')
    )

    mock_mod = types.ModuleType('scipy.mock_pyx_mod')
    fake_pyx = lambda *args: os.system('id')
    fake_pyx.__module__ = 'scipy.mock_pyx_mod'
    setattr(mock_mod, '__pyx_unpickle_Fake', fake_pyx)
    callable_instance = type(
        'CallableObj',
        (),
        {
            '__call__': lambda self, *args: None,
            '__module__': 'scipy.mock_pyx_mod',
        },
    )()
    setattr(mock_mod, '_reconstruct', callable_instance)
    setattr(mock_mod, '_reconstruct_eval', eval)
    sys.modules['scipy.mock_pyx_mod'] = mock_mod
    self.addCleanup(sys.modules.pop, 'scipy.mock_pyx_mod', None)
    self.addCleanup(utils.classify_symbol.cache_clear)

    for symbol, expected in (
        (
            'typing.io.delete_recursively',
            utils.Classification.UNKNOWN,
        ),
        ('numpy.core.multiarray._reconstruct', utils.Classification.SAFE),
        ('typing.pkg.newObj', utils.Classification.UNKNOWN),
        ('typing.pkg._reconstruct', utils.Classification.UNKNOWN),
        (
            'scipy.mock_pyx_mod.__pyx_unpickle_Fake',
            utils.Classification.SUSPICIOUS,
        ),
        ('scipy.mock_pyx_mod._reconstruct', utils.Classification.UNKNOWN),
        ('scipy.mock_pyx_mod._reconstruct_eval', utils.Classification.UNSAFE),
    ):
      self.assertEqual(utils.classify_symbol(symbol), expected)

    flax_root = types.ModuleType('flax')
    sys.modules['flax'] = flax_root
    self.addCleanup(sys.modules.pop, 'flax', None)
    before_bases = utils.get_all_active_approved_base_classes()

    flax_linen = types.ModuleType('flax.linen')
    mock_flax_cls = type('MockFlaxModule', (), {})
    setattr(flax_linen, 'Module', mock_flax_cls)
    setattr(flax_root, 'linen', flax_linen)
    sys.modules['flax.linen'] = flax_linen
    self.addCleanup(sys.modules.pop, 'flax.linen', None)
    self.assertNotIn(mock_flax_cls, before_bases)
    self.assertIn(mock_flax_cls, utils.get_all_active_approved_base_classes())

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
        utils.Classification.SAFE,
    )
    self.assertEqual(
        utils.classify_symbol('numpy.random._pickle.custom_unknown_helper'),
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
        autospec=True,
    ):
      self.assertIsNone(utils.get_module_members('unimported_parent.child'))

    frozen_spec = importlib.machinery.ModuleSpec(
        name='frozen_stdlib_mod', loader=None, origin='frozen'
    )
    with unittest.mock.patch.object(
        utils.importlib.util,
        'find_spec',
        return_value=frozen_spec,
        autospec=True,
    ):
      self.assertIsNone(utils.get_module_members('frozen_stdlib_mod'))

  def test_mark_pop_empty_frame_preserves_outer_stack(self):
    payload = (
        b'\x80\x04'
        b'\x8c\x0bcollections'
        b'\x8c\x0bOrderedDict'
        b'\x8c\x06shutil'
        b'\x8c\x06rmtree'
        b'(0(0'
        b'\x93.'
    )
    emitted = [
        (op.name, arg) for op, arg in utils.custom_genops_from_bytes(payload)
    ]
    self.assertIn(('STACK_GLOBAL', 'shutil.rmtree'), emitted)

    chunks = utils.partition_pickle_chunks(payload, target_chunk_size=12)
    self.assertNotEmpty(chunks)

  def test_decimal_and_uuid_classify_as_safe(self):
    utils.classify_symbol.cache_clear()
    _ = decimal.Decimal('3.14')
    _ = uuid.UUID(int=42)
    self.assertEqual(
        utils.classify_symbol('decimal.Decimal'),
        utils.Classification.SAFE,
    )
    self.assertEqual(
        utils.classify_symbol('uuid.UUID'),
        utils.Classification.SAFE,
    )

  def test_unimported_installed_package_resolves_via_cached_find_spec(self):
    temp_dir = self.create_tempdir()
    temp_dir.create_file(
        'sklearn/__init__.py',
        content='raise RuntimeError("Never import!")\n',
    )
    temp_dir.create_file(
        'sklearn/_models.py',
        content=(
            'import dataclasses\n'
            'raise RuntimeError("Never import!")\n\n'
            '@dataclasses.dataclass\n'
            'class ModelA:\n'
            '  coef: float = 0.0\n\n'
            '@dataclasses.dataclass\n'
            'class ModelB:\n'
            '  depth: int = 1\n'
        ),
    )

    saved_sklearn = {}
    for mod_key in list(sys.modules):
      if mod_key == 'sklearn' or mod_key.startswith('sklearn.'):
        saved_sklearn[mod_key] = sys.modules.pop(mod_key)
    self.addCleanup(sys.modules.update, saved_sklearn)

    sys.path.insert(0, temp_dir.full_path)
    self.addCleanup(sys.path.remove, temp_dir.full_path)

    def clear_caches() -> None:
      utils._find_root_package_spec_info.cache_clear()
      utils._inspect_class_via_ast.cache_clear()
      utils.classify_symbol.cache_clear()

    clear_caches()
    self.addCleanup(clear_caches)

    self.assertEqual(
        utils.classify_symbol('sklearn._models.ModelA'),
        utils.Classification.SAFE,
    )
    self.assertEqual(
        utils.classify_symbol('sklearn._models.ModelB'),
        utils.Classification.SAFE,
    )
    self.assertNotIn('sklearn', sys.modules)
    self.assertGreaterEqual(
        utils._find_root_package_spec_info.cache_info().hits, 1
    )

  @parameterized.named_parameters(
      dict(
          testcase_name='unsafe_os_doc',
          symbol='os.__doc__',
          expected=utils.Classification.UNSAFE,
      ),
      dict(
          testcase_name='unsafe_antigravity_doc',
          symbol='antigravity.__doc__',
          expected=utils.Classification.UNSAFE,
      ),
      dict(
          testcase_name='suspicious_unrecognized_pkg_doc',
          symbol='unrecognized_custom_pkg.__doc__',
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='suspicious_intermediate_dunder_doc',
          symbol='collections.OrderedDict.__subclasses__.__doc__',
          expected=utils.Classification.SUSPICIOUS,
      ),
      dict(
          testcase_name='safe_approved_class_doc',
          symbol='collections.OrderedDict.__doc__',
          expected=utils.Classification.SAFE,
      ),
      dict(
          testcase_name='safe_approved_root_doc',
          symbol='torch.__doc__',
          expected=utils.Classification.SAFE,
      ),
  )
  def test_metadata_attributes_require_safe_or_approved_prefix(
      self, symbol: str, expected: utils.Classification
  ):
    """Tests metadata attributes require a safe or approved prefix."""
    utils.classify_symbol.cache_clear()
    self.assertEqual(utils.classify_symbol(symbol), expected)

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
          'pathway_b_restricted_dunder_chain',
          'typing.pkg.mod.Cls.__init__.__dict__.TargetClass',
          utils.Classification.SUSPICIOUS,
      ),
      (
          'pathway_b_restricted_class_hop',
          'typing.pkg.mod.Cls.attr.TargetClass',
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
  )
  def test_structural_builtin_compat_and_dunder_classifications(
      self, symbol, expected_classification
  ):
    """Verifies builtin, Python 2 compatibility, and dunder chain classifications."""
    utils.classify_symbol.cache_clear()
    self.assertEqual(utils.classify_symbol(symbol), expected_classification)

  def test_all_base_class_specs_safe_when_unimported(self):
    """Verifies `ALL_BASE_CLASS_SPECS` entries classify as SAFE when unimported."""
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

  def test_get_module_members_does_not_invoke_pep562_getattr(self):
    """Verifies `get_module_members` reads `dir()` without module `__getattr__`."""
    module_name = '_saferpickle_test_lazy_mod'
    lazy_module = types.ModuleType(module_name)
    getattr_calls = []

    def _module_dir():
      return ['loaded_fn', 'lazy_submod']

    def _module_getattr(name):
      getattr_calls.append(name)
      raise AssertionError(f'Unexpected __getattr__({name!r}) during scan')

    lazy_module.__dir__ = _module_dir
    lazy_module.__getattr__ = _module_getattr

    self.addCleanup(utils.get_module_members.cache_clear)
    self.addCleanup(sys.modules.pop, module_name, None)
    sys.modules[module_name] = lazy_module
    utils.get_module_members.cache_clear()

    members = utils.get_module_members(module_name)
    self.assertIsNotNone(members)
    self.assertIn('loaded_fn', members)
    self.assertIn('lazy_submod', members)
    self.assertEmpty(getattr_calls)


if __name__ == '__main__':
  absltest.main()

import bz2
import gzip
import io
import lzma
import os
import pickle
import sys
import tarfile
import types
from unittest import mock
import zipfile
import zlib
import saferpickle as safer_pickle
from lib import exceptions
from absl.testing import absltest
from absl.testing import parameterized

_MALICIOUS_PKL = b'\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'


def _zip_of(*members, compression=zipfile.ZIP_STORED):
  zip_buf = io.BytesIO()
  with zipfile.ZipFile(zip_buf, 'w', compression=compression) as zf:
    for name, payload in members:
      zf.writestr(name, payload)
  return zip_buf.getvalue()


class CompressionTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    if 'TEST_SRCDIR' in os.environ:
      self.testdata_dir = os.path.join(
          os.environ['TEST_SRCDIR'],
          'testdata/compressed',
      )
    else:
      self.testdata_dir = (
          'testdata/compressed'
      )

  def assert_safe(self, scores):
    self.assertEqual(scores['unsafe'], 0)

  def assert_malicious(self, scores):
    self.assertGreater(scores['unsafe'], 0)

  def assert_flagged(self, data):
    self.assert_malicious(safer_pickle.security_scan(data))
    for scan_fn in (safer_pickle.picklemagic_scan, safer_pickle.genops_scan):
      self.assertNotEmpty(scan_fn(data).unsafe_results)
    self.assertTrue(safer_pickle.strict_security_scan(data))

  def assert_extraction_error(self, data):
    self.assert_malicious(safer_pickle.security_scan(data))
    for scan_fn in (safer_pickle.picklemagic_scan, safer_pickle.genops_scan):
      self.assertIn('archive_extraction_error', scan_fn(data).unsafe_results)

  @parameterized.parameters(
      ('malicious.zip', True),
      ('benign.zip', False),
      ('malicious.bz2', True),
      ('benign.bz2', False),
      ('malicious.lzma', True),
      ('benign.lzma', False),
      ('malicious.gz', True),
      ('benign.gz', False),
      ('malicious.tar', True),
      ('benign.tar', False),
      ('nested_malicious.zip', True),
      ('nested_benign.zip', False),
      ('zip_slip.zip', True),
      ('pytorch_malicious.pt', True),
      ('pytorch_malicious.pth', True),
      ('pytorch_malicious_raw.pth', True),
  )
  def test_single_layer_compression(self, filename, is_malicious):
    path = os.path.join(self.testdata_dir, filename)
    with open(path, 'rb') as f:
      data = f.read()

    scores = safer_pickle.security_scan(data)
    if is_malicious:
      self.assert_malicious(scores)
    else:
      self.assert_safe(scores)

  def test_deep_recursion_exceeded(self):
    benign_pkl = pickle.dumps({'safe': 123}, protocol=4)
    depth_4_archive = gzip.compress(
        bz2.compress(lzma.compress(gzip.compress(benign_pkl)))
    )
    for deep_filename in ('deep_recursion_10.zip', 'deep_recursion_11.zip'):
      path = os.path.join(self.testdata_dir, deep_filename)
      with open(path, 'rb') as f:
        deep_zip = f.read()
      for archive_payload in (depth_4_archive, deep_zip):
        with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
          safer_pickle.security_scan(archive_payload)
        with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
          safer_pickle.picklemagic_scan(archive_payload)
        with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
          safer_pickle.genops_scan(archive_payload)
        with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
          safer_pickle.strict_security_scan(archive_payload)

  def test_deep_recursion_allowed(self):
    def make_depth_3_archive(leaf_pkl: bytes) -> bytes:
      inner_zip = _zip_of(('model/data.pkl', leaf_pkl))

      tar_buf = io.BytesIO()
      with tarfile.open(fileobj=tar_buf, mode='w') as tf:
        info = tarfile.TarInfo(name='checkpoint.pt')
        info.size = len(inner_zip)
        tf.addfile(info, io.BytesIO(inner_zip))
      return gzip.compress(tar_buf.getvalue())

    benign_depth_3 = make_depth_3_archive(pickle.dumps({'ok': 1}, protocol=4))
    malicious_depth_3 = make_depth_3_archive(_MALICIOUS_PKL)
    self.assert_safe(safer_pickle.security_scan(benign_depth_3))
    self.assertFalse(safer_pickle.strict_security_scan(benign_depth_3))
    self.assert_malicious(safer_pickle.security_scan(malicious_depth_3))
    self.assertTrue(safer_pickle.strict_security_scan(malicious_depth_3))

    path_10 = os.path.join(self.testdata_dir, 'deep_recursion_10.zip')
    with open(path_10, 'rb') as f:
      data_10 = f.read()
    path_11 = os.path.join(self.testdata_dir, 'deep_recursion_11.zip')
    with open(path_11, 'rb') as f:
      data_11 = f.read()

    with mock.patch.object(
        safer_pickle.constants, 'MAX_ARCHIVE_RECURSION_DEPTH', 10
    ):
      self.assert_safe(safer_pickle.security_scan(data_10))
      with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
        safer_pickle.security_scan(data_11)

  def test_large_first_opcode_pickle_and_non_pickle_skipping_in_zip_and_tar(
      self,
  ):
    # First opcode after PROTO 4 is a 4000-byte BINBYTES (> 1024 bytes),
    # followed by posix.system('id').
    large_first_opcode_pickle = (
        b'\x80\x04B'
        + (4000).to_bytes(4, 'little')
        + (b'A' * 4000)
        + b'\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'
    )
    non_pickle_tensor_blob = b'\x00\xff\xfe\xfd' * 4096  # 16 KB non-pickle

    members = (
        ('archive/data/0', non_pickle_tensor_blob),
        ('archive/data.pkl', large_first_opcode_pickle),
    )
    zip_bytes = _zip_of(*members)

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      for name, payload in members:
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    tar_bytes = tar_buf.getvalue()

    for archive_bytes in (zip_bytes, tar_bytes):
      self.assert_flagged(archive_bytes)

    # Verify non-pickle entries are never read fully into memory.
    orig_extract = safer_pickle.utils.extract_zip_contents
    bytes_read_by_entry = {}

    class ReadTrackingProxy:

      def __init__(self, name, stream):
        self._name = name
        self._stream = stream

      def read(self, size=-1):
        chunk = self._stream.read() if size == -1 else self._stream.read(size)
        bytes_read_by_entry[self._name] = bytes_read_by_entry.get(
            self._name, 0
        ) + len(chunk)
        return chunk

      def __getattr__(self, attr):
        return getattr(self._stream, attr)

    def tracking_extract(file_bytes):
      for name, stream in orig_extract(file_bytes):
        yield name, ReadTrackingProxy(name, stream)

    with mock.patch.object(
        safer_pickle.utils,
        'extract_zip_contents',
        side_effect=tracking_extract,
        autospec=True,
    ):
      safer_pickle.genops_scan(zip_bytes)
      self.assertLessEqual(bytes_read_by_entry['archive/data/0'], 1500)
      self.assertGreater(bytes_read_by_entry['archive/data.pkl'], 4000)

  def test_encrypted_flag_bit_zip_bypass_cve_2025_1944(self):
    raw = bytearray(_zip_of(('data.pkl', _MALICIOUS_PKL)))
    # Set bit 0 (encrypted flag) in local file header (offset 6) and central dir
    raw[6] |= 0x1
    cd_offset = raw.find(b'PK\x01\x02')
    self.assertGreaterEqual(cd_offset, 0)
    raw[cd_offset + 8] |= 0x1
    tampered_zip = bytes(raw)

    self.assert_extraction_error(tampered_zip)

  def test_corrupted_crc_zip_bypass_cve_2025_10156(self):
    large_pickle = (
        b'\x80\x04B'
        + (3000).to_bytes(4, 'little')
        + (b'Z' * 3000)
        + b'\x8c\x05posix\x8c\x06system\x93.'
    )
    raw = bytearray(_zip_of(('data.pkl', large_pickle)))
    # Corrupt CRC-32 in local file header (offset 14..18) and central directory
    raw[14] ^= 0xFF
    cd_offset = raw.find(b'PK\x01\x02')
    self.assertGreaterEqual(cd_offset, 0)
    raw[cd_offset + 16] ^= 0xFF
    corrupted_crc_zip = bytes(raw)

    self.assert_extraction_error(corrupted_crc_zip)

  def test_duplicate_filename_zip_shadowing_cve_2025_1889(self):
    benign_pkl = pickle.dumps({'safe': 123}, protocol=4)

    for first, second in (
        (_MALICIOUS_PKL, benign_pkl),
        (benign_pkl, _MALICIOUS_PKL),
    ):
      self.assert_flagged(
          _zip_of(('archive/data.pkl', first), ('archive/data.pkl', second))
      )

  def test_tar_symlink_and_windows_path_traversal_blocked(self):
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      sym = tarfile.TarInfo(name='link_entry')
      sym.type = tarfile.SYMTYPE
      sym.linkname = '../../etc/passwd'
      tf.addfile(sym)
    tar_bytes = tar_buf.getvalue()

    self.assert_flagged(tar_bytes)

    for unsafe_zip_path in ('\\evil.pkl', 'C:\\evil.pkl'):
      zip_bytes = _zip_of((unsafe_zip_path, pickle.dumps({'a': 1})))
      self.assert_malicious(safer_pickle.security_scan(zip_bytes))
      self.assertIn(
          'zip_slip_detected',
          safer_pickle.picklemagic_scan(zip_bytes).unsafe_results,
      )
      self.assertIn(
          'zip_slip_detected',
          safer_pickle.genops_scan(zip_bytes).unsafe_results,
      )

  def test_npy_and_npz_numeric_safe_and_object_dtype_malicious(self):
    def make_npy(descr: str, payload: bytes) -> bytes:
      header_dict = (
          f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,)}}"
      ).encode('latin1')
      padding_len = (64 - ((10 + len(header_dict) + 1) % 64)) % 64
      header_body = header_dict + (b' ' * padding_len) + b'\n'
      return (
          b'\x93NUMPY\x01\x00'
          + len(header_body).to_bytes(2, 'little')
          + header_body
          + payload
      )

    numeric_npy = make_npy('<f8', b'\x00' * 64)
    self.assert_safe(safer_pickle.security_scan(numeric_npy))
    self.assertEmpty(safer_pickle.picklemagic_scan(numeric_npy).unsafe_results)
    self.assertEmpty(safer_pickle.genops_scan(numeric_npy).unsafe_results)

    object_npy = make_npy('|O', _MALICIOUS_PKL)
    self.assert_flagged(object_npy)
    self.assert_flagged(
        _zip_of(('numeric.npy', numeric_npy), ('malicious_obj.npy', object_npy))
    )

  def test_archive_decompression_byte_budget_fails_closed(self):
    oversized_benign_pkl = pickle.dumps({'blob': b'A' * 16384}, protocol=4)

    deflated_zip = _zip_of(
        ('oversized.pkl', oversized_benign_pkl),
        compression=zipfile.ZIP_DEFLATED,
    )

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      info = tarfile.TarInfo(name='oversized.pkl')
      info.size = len(oversized_benign_pkl)
      tf.addfile(info, io.BytesIO(oversized_benign_pkl))

    small_pkl = pickle.dumps({'blob': b'B' * 2500}, protocol=4)
    multi_zip = _zip_of(
        ('part1.pkl', small_pkl),
        ('part2.pkl', small_pkl),
        compression=zipfile.ZIP_DEFLATED,
    )

    nested_gzip_bomb = gzip.compress(
        gzip.compress(gzip.compress(oversized_benign_pkl))
    )

    archives = (
        deflated_zip,
        gzip.compress(oversized_benign_pkl),
        nested_gzip_bomb,
        bz2.compress(oversized_benign_pkl),
        lzma.compress(oversized_benign_pkl),
        tar_buf.getvalue(),
        multi_zip,
    )

    with mock.patch.object(
        safer_pickle.constants, 'MAX_ARCHIVE_DECOMPRESSED_BYTES', 4096
    ):
      for archive_bytes in archives:
        self.assert_extraction_error(archive_bytes)
        self.assertTrue(safer_pickle.strict_security_scan(archive_bytes))

  def test_prepended_data_zip_and_pickle_zip_polyglots(self):
    benign_pkl = pickle.dumps({'safe': 123}, protocol=4)
    malicious_zip = _zip_of(('model/data.pkl', _MALICIOUS_PKL))
    benign_zip = _zip_of(('model/data.pkl', benign_pkl))

    prepended_zip = (b'JUNK_PREFIX' * 200) + malicious_zip
    polyglot_malicious_pkl_first = _MALICIOUS_PKL + benign_zip
    polyglot_malicious_zip_last = benign_pkl + malicious_zip

    for payload in (
        prepended_zip,
        polyglot_malicious_pkl_first,
        polyglot_malicious_zip_last,
    ):
      self.assert_flagged(payload)

  def test_tar_pickle_polyglot_caught_across_all_scan_modes(self):
    tar_buf = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buf, mode='w', format=tarfile.USTAR_FORMAT
    ) as tf:
      safe_data = pickle.dumps({'safe_key': 123}, protocol=4)
      tar_info = tarfile.TarInfo(name='cos\nsystem\n(Vid\ntR.')
      tar_info.size = len(safe_data)
      tf.addfile(tar_info, io.BytesIO(safe_data))
    polyglot_bytes = tar_buf.getvalue()

    self.assert_flagged(polyglot_bytes)

  def test_large_npy_header_in_npz_and_null_padded_protocol0_in_zip(self):
    header_dict = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,)}"
    padded_header = header_dict + (b' ' * 4096) + b'\n'
    large_header_npy = (
        b'\x93NUMPY\x01\x00'
        + len(padded_header).to_bytes(2, 'little')
        + padded_header
        + _MALICIOUS_PKL
    )

    null_padded_proto0 = b'I1\x00ignored\n0cos\nsystem\n(Vid\ntR.'

    npz_bytes = _zip_of(('arr_0.npy', large_header_npy))
    null_zip_bytes = _zip_of(('entry_without_pkl_ext', null_padded_proto0))

    for payload in (npz_bytes, null_zip_bytes):
      self.assert_malicious(safer_pickle.security_scan(payload))
      self.assertNotEmpty(safer_pickle.genops_scan(payload).unsafe_results)
      self.assertTrue(safer_pickle.strict_security_scan(payload))

  def test_extensionless_archives_and_header_padded_named_pickle(self):
    prepended_inner_zip = b'NOT_PK_HEADER_BYTES' + _zip_of(
        ('weights_blob', _MALICIOUS_PKL)
    )
    extensionless_nested = _zip_of(
        ('nested_bundle_no_ext', prepended_inner_zip)
    )
    padded_named_zip = _zip_of(('archive/data.pkl', b'JUNK' + _MALICIOUS_PKL))

    for payload in (extensionless_nested, padded_named_zip):
      self.assert_flagged(payload)

  def test_check_magic_bytes_propagated_across_all_archive_layers(self):
    keyword_prefixed_proto0 = b'const \nfoo\n0cos\nsystem\n(Vid\ntR.'

    wrapped_archives = (
        gzip.compress(keyword_prefixed_proto0),
        bz2.compress(keyword_prefixed_proto0),
        lzma.compress(keyword_prefixed_proto0),
        _zip_of(('payload_blob', keyword_prefixed_proto0)),
    )
    for wrapped in wrapped_archives:
      self.assert_safe(
          safer_pickle.security_scan(wrapped, check_magic_bytes=True)
      )
      self.assert_malicious(
          safer_pickle.security_scan(wrapped, check_magic_bytes=False)
      )
      self.assertNotEmpty(
          safer_pickle.picklemagic_scan(
              wrapped, check_magic_bytes=False
          ).unsafe_results
      )
      self.assertNotEmpty(
          safer_pickle.genops_scan(
              wrapped, check_magic_bytes=False
          ).unsafe_results
      )

  def test_v7_tar_and_legacy_lzma_alone_archives(self):
    benign_pkl = pickle.dumps({'safe': 1}, protocol=4)

    lzma_alone_malicious = lzma.compress(
        _MALICIOUS_PKL, format=lzma.FORMAT_ALONE
    )
    lzma_alone_benign = lzma.compress(benign_pkl, format=lzma.FORMAT_ALONE)
    self.assert_malicious(safer_pickle.security_scan(lzma_alone_malicious))
    self.assert_safe(safer_pickle.security_scan(lzma_alone_benign))
    self.assertTrue(safer_pickle.strict_security_scan(lzma_alone_malicious))
    self.assertFalse(safer_pickle.strict_security_scan(lzma_alone_benign))

    tar_buf = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buf, mode='w', format=tarfile.USTAR_FORMAT
    ) as tf:
      info = tarfile.TarInfo(name='payload_no_ext')
      info.size = len(_MALICIOUS_PKL)
      tf.addfile(info, io.BytesIO(_MALICIOUS_PKL))
    raw_v7 = bytearray(tar_buf.getvalue())
    raw_v7[257:265] = b'\x00' * 8
    raw_v7[148:156] = b' ' * 8
    chksum = sum(raw_v7[:512])
    raw_v7[148:156] = f'{chksum:06o}\x00 '.encode('ascii')
    v7_tar = bytes(raw_v7)

    self.assert_flagged(v7_tar)

  @parameterized.named_parameters(
      ('multiline_npy_v1', 'multiline_npy', False),
      ('newline_len_npy_v2_npz', 'npy_v2_npz', False),
      ('deflated_prepended_inner_zip', 'deflated_zip', False),
      ('deflated_prepended_inner_zip_over_1mib', 'deflated_zip_large', False),
      ('padded_gzip_strict', 'padded_gzip', True),
      ('concat_gzip_strict', 'concat_gzip', True),
  )
  def test_npy_binary_length_deflated_eocd_and_strict_stream_bypasses(
      self, variant: str, strict_only: bool
  ):
    evil = _MALICIOUS_PKL
    if variant == 'multiline_npy':
      hdr = b"{'descr': '|O',\n'fortran_order': False, 'shape': (1,)}        \n"
      payload = (
          b'\x93NUMPY\x01\x00' + len(hdr).to_bytes(2, 'little') + hdr + evil
      )
    elif variant == 'npy_v2_npz':
      body = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,)}"
      hdr = body + b' ' * (0x0A04 - len(body) - 1) + b'\n'
      npy = b'\x93NUMPY\x02\x00' + len(hdr).to_bytes(4, 'little') + hdr + evil
      payload = _zip_of(('arr_0.npy', npy))
    elif variant.startswith('deflated_zip'):
      prefix = b'JUNK_PREFIX' * (100000 if variant.endswith('large') else 1)
      inner = _zip_of(('data.pkl', evil), compression=zipfile.ZIP_DEFLATED)
      payload = _zip_of(
          ('nested_blob', prefix + inner), compression=zipfile.ZIP_DEFLATED
      )
    elif variant == 'padded_gzip':
      payload = gzip.compress(b'JUNK_HEADER\n' + evil)
    else:
      payload = gzip.compress(b'plain text\n') + gzip.compress(evil)

    self.assertTrue(safer_pickle.strict_security_scan(payload))
    if not strict_only:
      self.assert_flagged(payload)

  @parameterized.named_parameters(
      ('lzma_alone_odd_dict', 'alone_5mib', False),
      ('lzma_alone_oversized_dict', 'alone_128mib', True),
      ('zlib', 'zlib', False),
      ('joblib_zfile', 'zfile', False),
      ('lz4_unavailable', 'lz4_missing', True),
      ('lz4_available', 'lz4', False),
      ('pickle_lzma_polyglot', 'polyglot', False),
  )
  def test_weak_magic_streams_and_raw_pickle_polyglot_flagged(
      self, variant, expect_extraction_error
  ):
    evil = _MALICIOUS_PKL
    lzma1 = {'id': lzma.FILTER_LZMA1}
    lz4_frame = None
    if variant.startswith('alone'):
      dict_size = (5 if variant == 'alone_5mib' else 128) << 20
      raw = lzma.compress(evil, format=lzma.FORMAT_RAW, filters=[lzma1])
      payload = b'\x5d' + dict_size.to_bytes(4, 'little') + b'\xff' * 8 + raw
    elif variant == 'zlib':
      payload = zlib.compress(evil)
    elif variant == 'zfile':
      payload = b'ZF' + hex(len(evil)).encode().ljust(19) + zlib.compress(evil)
    elif variant.startswith('lz4'):
      payload = b'\x04\x22\x4d\x18' + evil

      def fake_open(unused_stream):
        return io.BytesIO(evil)

      if variant == 'lz4':
        lz4_frame = types.SimpleNamespace(open=fake_open)
    else:
      benign = lzma.compress(
          pickle.dumps([1]),
          format=lzma.FORMAT_RAW,
          filters=[dict(lzma1, lc=4, lp=0, pb=3)],
      )
      operand = (b'\xff' * 8 + benign).ljust(4096, b'\x00')
      payload = b'\x8b\x00\x10\x00\x00' + operand + b'0' + evil[2:]

    with mock.patch.dict(sys.modules, {'lz4.frame': lz4_frame}):
      self.assert_malicious(safer_pickle.security_scan(payload))
      self.assertTrue(safer_pickle.strict_security_scan(payload))
      unsafe_results = safer_pickle.genops_scan(payload).unsafe_results

    self.assertEqual(
        'archive_extraction_error' in unsafe_results, expect_extraction_error
    )

  def test_weak_magic_benign_streams_and_tensor_members_not_flagged(self):
    benign = pickle.dumps({'safe': 1}, protocol=4)
    int32_tensor = (b'\x03\x00\x00\x00\x01\x00\x00\x00\x04' + b'\x00' * 23) * 8
    tensor_zip = _zip_of(
        ('archive/data.pkl', benign), ('archive/data/0', int32_tensor)
    )

    for payload in (zlib.compress(benign), tensor_zip):
      self.assert_safe(safer_pickle.security_scan(payload))
      self.assertFalse(safer_pickle.strict_security_scan(payload))


if __name__ == '__main__':
  absltest.main()

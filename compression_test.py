import bz2
import gzip
import io
import lzma
import os
import pickle
import tarfile
from unittest import mock
import zipfile
import saferpickle as safer_pickle
from lib import exceptions
from absl.testing import absltest as googletest
from absl.testing import parameterized


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

  def test_nested_malicious(self):
    path = os.path.join(self.testdata_dir, 'nested_malicious.zip')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_malicious(scores)

  def test_nested_benign(self):
    path = os.path.join(self.testdata_dir, 'nested_benign.zip')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_safe(scores)

  def test_deep_recursion_exceeded(self):
    path = os.path.join(self.testdata_dir, 'deep_recursion_11.zip')
    with open(path, 'rb') as f:
      data = f.read()
    with self.assertRaises(exceptions.MaxRecursionDepthExceededError):
      safer_pickle.security_scan(data)

  def test_deep_recursion_allowed(self):
    path = os.path.join(self.testdata_dir, 'deep_recursion_10.zip')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_safe(scores)

  def test_zip_slip(self):
    path = os.path.join(self.testdata_dir, 'zip_slip.zip')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_malicious(scores)

  def test_pytorch_malicious(self):
    path = os.path.join(self.testdata_dir, 'pytorch_malicious.pt')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_malicious(scores)

  def test_pytorch_pth_malicious(self):
    path = os.path.join(self.testdata_dir, 'pytorch_malicious.pth')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_malicious(scores)

  def test_pytorch_pth_raw_malicious(self):
    path = os.path.join(self.testdata_dir, 'pytorch_malicious_raw.pth')
    with open(path, 'rb') as f:
      data = f.read()
    scores = safer_pickle.security_scan(data)
    self.assert_malicious(scores)

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

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
      zf.writestr('archive/data/0', non_pickle_tensor_blob)
      zf.writestr('archive/data.pkl', large_first_opcode_pickle)
    zip_bytes = zip_buf.getvalue()

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      for name, payload in (
          ('archive/data/0', non_pickle_tensor_blob),
          ('archive/data.pkl', large_first_opcode_pickle),
      ):
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    tar_bytes = tar_buf.getvalue()

    for archive_bytes in (zip_bytes, tar_bytes):
      self.assert_malicious(safer_pickle.security_scan(archive_bytes))
      self.assertNotEmpty(
          safer_pickle.picklemagic_scan(archive_bytes).unsafe_results
      )
      self.assertNotEmpty(
          safer_pickle.genops_scan(archive_bytes).unsafe_results
      )

    # Verify non-pickle entries are never read fully into memory
    orig_iter = safer_pickle._iter_archive_entries
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

    def tracking_iter(data, archive_type):
      for name, stream in orig_iter(data, archive_type):
        yield name, ReadTrackingProxy(name, stream)

    safer_pickle._iter_archive_entries = tracking_iter
    try:
      safer_pickle.genops_scan(zip_bytes)
      self.assertLessEqual(bytes_read_by_entry['archive/data/0'], 1500)
      self.assertGreater(bytes_read_by_entry['archive/data.pkl'], 4000)
    finally:
      safer_pickle._iter_archive_entries = orig_iter

  def test_encrypted_flag_bit_zip_bypass_cve_2025_1944(self):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
      zf.writestr(
          'data.pkl', b'\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'
      )
    raw = bytearray(zip_buf.getvalue())
    # Set bit 0 (encrypted flag) in local file header (offset 6) and central dir
    raw[6] |= 0x1
    cd_offset = raw.find(b'PK\x01\x02')
    self.assertGreaterEqual(cd_offset, 0)
    raw[cd_offset + 8] |= 0x1
    tampered_zip = bytes(raw)

    self.assert_malicious(safer_pickle.security_scan(tampered_zip))
    self.assertIn(
        'archive_extraction_error',
        safer_pickle.picklemagic_scan(tampered_zip).unsafe_results,
    )
    self.assertIn(
        'archive_extraction_error',
        safer_pickle.genops_scan(tampered_zip).unsafe_results,
    )

  def test_corrupted_crc_zip_bypass_cve_2025_10156(self):
    large_pickle = (
        b'\x80\x04B'
        + (3000).to_bytes(4, 'little')
        + (b'Z' * 3000)
        + b'\x8c\x05posix\x8c\x06system\x93.'
    )
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
      zf.writestr('data.pkl', large_pickle)
    raw = bytearray(zip_buf.getvalue())
    # Corrupt CRC-32 in local file header (offset 14..18) and central directory
    raw[14] ^= 0xFF
    cd_offset = raw.find(b'PK\x01\x02')
    self.assertGreaterEqual(cd_offset, 0)
    raw[cd_offset + 16] ^= 0xFF
    corrupted_crc_zip = bytes(raw)

    self.assert_malicious(safer_pickle.security_scan(corrupted_crc_zip))
    self.assertIn(
        'archive_extraction_error',
        safer_pickle.picklemagic_scan(corrupted_crc_zip).unsafe_results,
    )
    self.assertIn(
        'archive_extraction_error',
        safer_pickle.genops_scan(corrupted_crc_zip).unsafe_results,
    )

  def test_duplicate_filename_zip_shadowing_cve_2025_1889(self):
    malicious_pkl = b'\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'
    benign_pkl = pickle.dumps({'safe': 123}, protocol=4)

    for first, second in (
        (malicious_pkl, benign_pkl),
        (benign_pkl, malicious_pkl),
    ):
      zip_buf = io.BytesIO()
      with zipfile.ZipFile(zip_buf, 'w') as zf:
        zf.writestr('archive/data.pkl', first)
        zf.writestr('archive/data.pkl', second)
      zip_bytes = zip_buf.getvalue()

      self.assert_malicious(safer_pickle.security_scan(zip_bytes))
      self.assertNotEmpty(
          safer_pickle.picklemagic_scan(zip_bytes).unsafe_results
      )
      self.assertNotEmpty(safer_pickle.genops_scan(zip_bytes).unsafe_results)

  def test_tar_symlink_and_windows_path_traversal_blocked(self):
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      sym = tarfile.TarInfo(name='link_entry')
      sym.type = tarfile.SYMTYPE
      sym.linkname = '../../etc/passwd'
      tf.addfile(sym)
    tar_bytes = tar_buf.getvalue()

    self.assert_malicious(safer_pickle.security_scan(tar_bytes))
    self.assertNotEmpty(safer_pickle.picklemagic_scan(tar_bytes).unsafe_results)
    self.assertNotEmpty(safer_pickle.genops_scan(tar_bytes).unsafe_results)

    for unsafe_zip_path in ('\\evil.pkl', 'C:\\evil.pkl'):
      zip_buf = io.BytesIO()
      with zipfile.ZipFile(zip_buf, 'w') as zf:
        zf.writestr(unsafe_zip_path, pickle.dumps({'a': 1}))
      zip_bytes = zip_buf.getvalue()
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

    malicious_pkl = b'\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.'
    object_npy = make_npy('|O', malicious_pkl)
    self.assert_malicious(safer_pickle.security_scan(object_npy))
    self.assertNotEmpty(
        safer_pickle.picklemagic_scan(object_npy).unsafe_results
    )
    self.assertNotEmpty(safer_pickle.genops_scan(object_npy).unsafe_results)

    npz_buf = io.BytesIO()
    with zipfile.ZipFile(npz_buf, 'w') as zf:
      zf.writestr('numeric.npy', numeric_npy)
      zf.writestr('malicious_obj.npy', object_npy)
    npz_bytes = npz_buf.getvalue()
    self.assert_malicious(safer_pickle.security_scan(npz_bytes))
    self.assertNotEmpty(safer_pickle.picklemagic_scan(npz_bytes).unsafe_results)
    self.assertNotEmpty(safer_pickle.genops_scan(npz_bytes).unsafe_results)

  def test_archive_decompression_byte_budget_fails_closed(self):
    oversized_benign_pkl = pickle.dumps({'blob': b'A' * 16384}, protocol=4)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
      zf.writestr('oversized.pkl', oversized_benign_pkl)

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
      info = tarfile.TarInfo(name='oversized.pkl')
      info.size = len(oversized_benign_pkl)
      tf.addfile(info, io.BytesIO(oversized_benign_pkl))

    multi_zip_buf = io.BytesIO()
    small_pkl = pickle.dumps({'blob': b'B' * 2500}, protocol=4)
    with zipfile.ZipFile(
        multi_zip_buf, 'w', compression=zipfile.ZIP_DEFLATED
    ) as zf:
      zf.writestr('part1.pkl', small_pkl)
      zf.writestr('part2.pkl', small_pkl)

    archives = (
        zip_buf.getvalue(),
        gzip.compress(oversized_benign_pkl),
        bz2.compress(oversized_benign_pkl),
        lzma.compress(oversized_benign_pkl),
        tar_buf.getvalue(),
        multi_zip_buf.getvalue(),
    )

    with mock.patch.object(
        safer_pickle.constants, 'MAX_ARCHIVE_DECOMPRESSED_BYTES', 4096
    ):
      for archive_bytes in archives:
        self.assert_malicious(safer_pickle.security_scan(archive_bytes))
        self.assertIn(
            'archive_extraction_error',
            safer_pickle.picklemagic_scan(archive_bytes).unsafe_results,
        )
        self.assertIn(
            'archive_extraction_error',
            safer_pickle.genops_scan(archive_bytes).unsafe_results,
        )
        self.assertTrue(safer_pickle.strict_security_scan(archive_bytes))


if __name__ == '__main__':
  googletest.main()

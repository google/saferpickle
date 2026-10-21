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

"""Utility functions for saferpickle."""

import ast
import bz2
import codecs
import copyreg
import enum
import functools
import gzip
import importlib
import importlib.util
import inspect
import io
import lzma
import math
import mmap
import os
import pickletools
import re
import sys
import tarfile
import threading
import types
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    FrozenSet,
    Generator,
    IO,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    cast,
)
import zipfile

from absl import logging
from lib import config
from lib import constants
from lib import exceptions


@enum.unique
class Classification(enum.Enum):
  """Classification of a class name."""

  SAFE = "SAFE"
  UNSAFE = "UNSAFE"
  SUSPICIOUS = "SUSPICIOUS"
  UNKNOWN = "UNKNOWN"


_COMPAT_PICKLE = importlib.import_module("_compat_pickle")

PICKLEMAGIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "FakeWarning.__new__",
        re.compile(
            r"FakeWarning\.__new__ called on <class '(?P<class_name>.*?)'> with"
            r" args=(?P<args>.*), kwargs=(?P<kwargs>.*)"
        ),
    ),
    (
        "FakeWarning.__setstate__",
        re.compile(
            r"FakeWarning\.__setstate__ called on <class '(?P<class_name>.*?)'>"
            r" with unexpected state=(?P<state>.*)"
        ),
    ),
    (
        "FakeClass.__getattr__",
        re.compile(
            r"FakeClass\.__getattr__ called on <class '(?P<class_name>.*?)'>"
            r" with name=(?P<attr_name>.*)"
        ),
    ),
    (
        "FakeClass method",
        re.compile(
            r"FakeClass method (?P<method_name>.*?) called on <class"
            r" '(?P<class_name>.*?)'> with args=(?P<args>.*),"
            r" kwargs=(?P<kwargs>.*)"
        ),
    ),
    (
        "FakeClass.__call__",
        re.compile(
            r"FakeClass\.__call__ called on <class '(?P<class_name>.*?)'> with"
            r" args=(?P<args>.*), kwargs=(?P<kwargs>.*)"
        ),
    ),
    (
        "FakeModule.__getattr__",
        re.compile(
            r"FakeModule\.__getattr__ called on (?P<module_name>.*?) with"
            r" name=(?P<attr_name>.*)"
        ),
    ),
    (
        "Failed to ",
        re.compile(
            r"Failed to (?:reduce|set state|newobj|newobj_ex|instantiate)"
            r" <class '(?P<class_name>.*?)'> with (?P<args>.*?):"
        ),
    ),
)

_WHITESPACE_NORMALIZE_RE = re.compile(r"[ \t]+")
_BINARY_BYTES_HEX_RE = re.compile(
    r"bytearray\(b(?:'[^']*\\x[^']*'|\"[^\"]*\\x[^\"]*\")\)"
    r"|b(?:'[^']*\\x[^']*'|\"[^\"]*\\x[^\"]*\")"
    r"|\\x[0-9a-fA-F]{2}"
)
_HEX_TOKEN_PREFIX_RE = re.compile(r"^x[0-9a-fA-F]{2}")
_COMBINED_ARGS_TOKEN_RE = re.compile(
    r"'([^']*)'|\"([^\"]*)\"|([a-zA-Z_][a-zA-Z0-9_.]*(?:\(.*?\))?)"
)
_CLASS_REF_LOG_RE = re.compile(r"<class '([^']+)'>")
_OBJECT_REF_LOG_RE = re.compile(r"<([a-zA-Z_][a-zA-Z0-9_.]*) object at 0x")


# Creates a copy of the module
def copy_module(original_name: str, new_name: str) -> types.ModuleType | None:
  """Copies a module and creates a new module with the same attributes.

  Args:
    original_name: The name of the module to copy.
    new_name: The name of the new module.

  Returns:
    new_module: The new module, or None if original_name cannot be imported.
  """
  try:
    original_module = importlib.import_module(original_name)
  except ImportError:
    logging.debug("Failed to import module %s", original_name)
    return None
  except IOError:
    if original_name in sys.modules:
      logging.debug(
          "FileError during import of %s, but module is in sys.modules",
          original_name,
      )
      original_module = sys.modules[original_name]
    else:
      logging.debug(
          "Failed to import module %s due to FileError and module not in"
          " sys.modules",
          original_name,
      )
      return None

  new_module = types.ModuleType(new_name)
  new_module.__dict__.update(original_module.__dict__)
  new_module.__name__ = new_name
  if hasattr(original_module, "__file__"):
    new_module.__file__ = f"{new_name}.py"

  return new_module


_COPIED_MODS_CACHE: Dict[str, types.ModuleType] = {}
_COPIED_MODS_LOCK = threading.RLock()


def get_copied_module(name: str) -> types.ModuleType:
  """Get or create a copy of the module, caching it to avoid re-copying."""
  with _COPIED_MODS_LOCK:
    if name in _COPIED_MODS_CACHE:
      return _COPIED_MODS_CACHE[name]

    if name in ("pickle", "_pickle"):
      # We always copy _pickle for both pickle and _pickle
      if "_pickle" in _COPIED_MODS_CACHE:
        mod_copied = _COPIED_MODS_CACHE["_pickle"]
      else:
        mod_copied = copy_module("_pickle", "pickle_copy")
        if mod_copied is None:
          logging.error("Failed to copy critical module _pickle")
          sys.exit(1)
        _COPIED_MODS_CACHE["_pickle"] = mod_copied
        _COPIED_MODS_CACHE["pickle"] = mod_copied
    else:
      # Try to copy the module
      mod_copied = copy_module(name, f"{name}_copy")
      if mod_copied is None:
        # Fallback to pickle copy
        logging.warning(
            "%s could not be imported/copied, falling back to pickle_copy", name
        )
        if "_pickle" not in _COPIED_MODS_CACHE:
          _ = get_copied_module("_pickle")
        mod_copied = _COPIED_MODS_CACHE["_pickle"]

      _COPIED_MODS_CACHE[name] = mod_copied

    return mod_copied


def peek_bytes(file_bytes: bytes | IO[bytes], size: int) -> bytes:
  """Peeks at the first `size` bytes of a byte buffer or stream.

  Reads up to `size` bytes from `file_bytes` and restores the original stream
  offset if `file_bytes` is a seekable stream, or uses `.peek(size)` when
  available on non-seekable buffered streams.

  Args:
    file_bytes: The raw `bytes` buffer or binary stream to inspect.
    size: Maximum number of leading bytes to return.

  Returns:
    Up to `size` leading bytes from `file_bytes`, or `b""` if the stream
    cannot be peeked.
  """
  if isinstance(file_bytes, (bytes, bytearray, memoryview)):
    return bytes(file_bytes[:size])

  try:
    is_seekable = file_bytes.seekable()
  except (AttributeError, OSError, io.UnsupportedOperation, ValueError):
    is_seekable = False

  if is_seekable:
    try:
      current_pos = file_bytes.tell()
      peeked = file_bytes.read(size)
      file_bytes.seek(current_pos)
      return peeked
    except (OSError, io.UnsupportedOperation):
      pass

  if hasattr(file_bytes, "peek"):
    try:
      return file_bytes.peek(size)[:size]  # pyrefly: ignore[missing-attribute]
    except (OSError, io.UnsupportedOperation, AttributeError):
      pass

  return b""


def is_zip_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes/stream represent a zip file.

  Args:
    file_bytes: The bytes or stream to check.

  Returns:
    True if the input is a zip file, False otherwise.
  """
  if not file_bytes:
    return False
  return peek_bytes(file_bytes, 4).startswith(
      (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
  )


def read_bounded(
    stream: bytes | IO[bytes],
    max_bytes: Optional[int] = None,
    *,
    remaining_budget: Optional[list[int]] = None,
) -> bytes:
  """Reads a stream or byte buffer while enforcing a decompression byte budget.

  Reads `stream` in bounded chunks without upfront full-budget allocation,
  decrements `remaining_budget[0]` when a shared cumulative budget is supplied
  across nested or multi-entry archives, and raises `ValueError` if the limit
  is exceeded.

  Args:
    stream: Raw byte buffer or decompressed binary stream to read.
    max_bytes: Per-call maximum allowed byte count when `remaining_budget` is
      not provided. Defaults to `constants.MAX_ARCHIVE_DECOMPRESSED_BYTES`.
    remaining_budget: Optional single-element mutable list tracking the
      cumulative remaining byte budget across an archive tree.

  Returns:
    The complete byte contents read from `stream`.

  Raises:
    ValueError: If reading `stream` exceeds the allowed byte budget.
  """
  effective_max = (
      constants.MAX_ARCHIVE_DECOMPRESSED_BYTES
      if max_bytes is None
      else max_bytes
  )
  budget = (
      remaining_budget[0] if remaining_budget is not None else effective_max
  )
  if budget < 0:
    raise ValueError("Archive decompression byte budget exceeded.")

  if isinstance(stream, bytes):
    if len(stream) > budget:
      raise ValueError("Archive decompression byte budget exceeded.")
    if remaining_budget is not None:
      remaining_budget[0] -= len(stream)
    return stream

  chunks: list[bytes] = []
  bytes_read = 0
  while True:
    read_size = min(1024 * 1024, (budget - bytes_read) + 1)
    chunk = stream.read(read_size)
    if not chunk:
      break
    bytes_read += len(chunk)
    if bytes_read > budget:
      raise ValueError("Archive decompression byte budget exceeded.")
    chunks.append(chunk)

  if remaining_budget is not None:
    remaining_budget[0] -= bytes_read
  return b"".join(chunks)


def is_unsafe_archive_path(name: str) -> bool:
  """Checks whether an archive member path or link target contains traversal.

  Detects parent-directory traversal segments (`..`), leading POSIX or Windows
  root slashes, and Windows drive-letter prefixes (`C:`).

  Args:
    name: Archive entry filename or symbolic/hard link target path.

  Returns:
    True if `name` contains a path traversal or absolute path pattern, or
    False otherwise.
  """
  return (
      ".." in name
      or name.startswith(("/", "\\"))
      or (len(name) >= 2 and name[1] == ":")
  )


def extract_zip_contents(
    file_bytes: bytes | BinaryIO,
) -> Generator[Tuple[str, IO[bytes]], None, None]:
  """Extracts the list of files and their contents from a zip file/stream.

  Args:
    file_bytes: The bytes or stream to check.

  Yields:
    A tuple containing the file name and its stream.
  """
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  with zipfile.ZipFile(stream) as zf:
    for info in zf.infolist():
      if is_unsafe_archive_path(info.filename):
        yield info.filename, io.BytesIO(b"")
        continue
      if info.is_dir():
        continue
      with zf.open(info) as f:
        yield info.filename, f


def is_bz2_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a bz2 file."""
  return peek_bytes(file_bytes, 3).startswith(b"\x42\x5a\x68")


def extract_bz2_contents(file_bytes: bytes | BinaryIO) -> IO[bytes]:
  """Extracts contents from bz2 bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return bz2.open(stream)


def is_lzma_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent an lzma file."""
  return peek_bytes(file_bytes, 6).startswith(b"\xfd\x37\x7a\x58\x5a\x00")


def extract_lzma_contents(file_bytes: bytes | BinaryIO) -> IO[bytes]:
  """Extracts contents from lzma bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return lzma.open(stream)


def is_gzip_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a gzip file."""
  return peek_bytes(file_bytes, 2).startswith(b"\x1f\x8b")


def extract_gzip_contents(file_bytes: bytes | IO[bytes]) -> IO[bytes]:
  """Extracts contents from gzip bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return cast(IO[bytes], gzip.open(stream))


def is_tar_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a tar file."""
  peeked_bytes = peek_bytes(file_bytes, 512)
  if len(peeked_bytes) < 262 or peeked_bytes[257:262] != b"ustar":
    return False
  if peeked_bytes[0] == 0x80 and 1 <= peeked_bytes[1] <= 5:
    return False
  return True


def extract_tar_contents(
    file_bytes: bytes | BinaryIO,
) -> Generator[Tuple[str, IO[bytes]], None, None]:
  """Extracts contents from tar bytes/stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )

  with tarfile.open(fileobj=stream, mode="r:") as tf:
    for member in tf.getmembers():
      if (member.issym() or member.islnk()) and is_unsafe_archive_path(
          member.linkname
      ):
        raise tarfile.TarError(
            f"Unsafe tar link target detected: {member.linkname}"
        )

      if not member.isfile() and is_unsafe_archive_path(member.name):
        raise tarfile.TarError(
            f"Unsafe tar member path detected: {member.name}"
        )

      if member.isfile():
        f = tf.extractfile(member)
        if f is not None:
          yield member.name, cast(IO[bytes], f)


_OBJECT_NPY_DESCR_RE = re.compile(rb"['\"](?:[|<>=!]?O\d*|object)['\"]")


def _is_object_npy_header(header_bytes: bytes) -> bool:
  """Checks whether a NumPy `.npy` header declares an object-dtype array.

  Searches the `.npy` header dictionary bytes (and its escape-decoded form if
  backslash escapes are present) for `'O'` or `'object'` descriptor strings
  indicating embedded pickle payloads.

  Args:
    header_bytes: Leading bytes of a `.npy` file containing the header dict.

  Returns:
    True if the `.npy` header specifies an object dtype, or False otherwise.
  """
  if _OBJECT_NPY_DESCR_RE.search(header_bytes):
    return True
  if b"\\" in header_bytes:
    try:
      unescaped_bytes = codecs.escape_decode(header_bytes)[0]
      if _OBJECT_NPY_DESCR_RE.search(unescaped_bytes):
        return True
    except (ValueError, UnicodeDecodeError):
      pass
  return False


def _clean_protocol0_line(raw_bytes: bytes) -> bytes:
  r"""Strips null-byte truncation and trailing carriage returns from a line.

  C-accelerated `pickle` (`_pickle.c`) truncates Protocol 0 newline-terminated
  strings at the first embedded NUL (`\x00`) byte and strips trailing `\r`
  characters before decoding.

  Args:
    raw_bytes: Raw slice of bytes up to the newline delimiter.

  Returns:
    Cleaned `bytes` matching CPython's Protocol 0 line parser.
  """
  return raw_bytes.split(b"\x00", 1)[0].rstrip(b"\r")


def _is_valid_protocol0_global_prefix(raw_bytes: bytes) -> bool:
  """Checks whether `raw_bytes` begins with a valid Protocol 0 `GLOBAL`/`INST`.

  Verifies that a buffer starting with ASCII `'c'` (`GLOBAL`) or `'i'`
  (`INST`) is followed by two newline-delimited lines whose dot-separated
  segments are all valid Python identifiers.

  Args:
    raw_bytes: Leading bytes of the candidate stream.

  Returns:
    True if `raw_bytes` starts with a syntactically valid Protocol 0 `GLOBAL`
    or `INST` instruction, or False otherwise.
  """
  if not raw_bytes or raw_bytes[0] not in (ord("c"), ord("i")):
    return False

  first_newline_index = raw_bytes.find(b"\n")
  if first_newline_index <= 1:
    return False

  second_newline_index = raw_bytes.find(b"\n", first_newline_index + 1)
  if second_newline_index <= first_newline_index + 1:
    return False

  module_bytes = _clean_protocol0_line(raw_bytes[1:first_newline_index])
  attribute_bytes = _clean_protocol0_line(
      raw_bytes[first_newline_index + 1 : second_newline_index]
  )
  module_name = module_bytes.decode("latin1", errors="ignore")
  attribute_name = attribute_bytes.decode("latin1", errors="ignore")
  if not module_name or not attribute_name:
    return False

  module_parts_valid = all(
      identifier_part.isidentifier()
      for identifier_part in module_name.split(".")
  )
  attribute_parts_valid = all(
      identifier_part.isidentifier()
      for identifier_part in attribute_name.split(".")
  )
  return module_parts_valid and attribute_parts_valid


def _check_pickle_stream(
    raw_bytes: bytes,
    pickle_stream: IO[bytes],
    check_magic_bytes: bool,
) -> tuple[bool, int]:
  """Validates whether `pickle_stream` starts with valid pickle opcodes.

  Rejects known text prefixes and non-object `.npy` headers when
  `check_magic_bytes` is enabled, then walks up to
  `constants.MAX_BYTES_TO_CHECK` opcodes in `pickle_stream` to verify
  argument syntax and length bounds.

  Args:
    raw_bytes: Leading bytes peeked from the start of `pickle_stream`.
    pickle_stream: Binary stream positioned at the start of the candidate data.
    check_magic_bytes: Whether to fast-path reject text files and non-object
      NumPy arrays using magic-byte heuristics.

  Returns:
    A tuple `(is_valid_pickle, valid_opcodes_count)` indicating whether the
    stream is likely a valid pickle payload and how many opcodes were read.
  """
  if raw_bytes and raw_bytes[0] not in constants.OPCODES_INFO_INT:
    return (False, 0)

  if check_magic_bytes:
    if raw_bytes.isascii():
      stripped_bytes = raw_bytes.lstrip()
      has_non_pickle_text_prefix = (
          stripped_bytes.startswith(constants.TEXT_BASED_PREFIXES)
          or stripped_bytes.startswith(constants.CODE_KEYWORDS)
          or stripped_bytes.isalpha()
      )
      if has_non_pickle_text_prefix and not _is_valid_protocol0_global_prefix(
          raw_bytes
      ):
        return (False, 0)

    if raw_bytes.startswith(b"\x93NUMPY"):
      npy_header_bytes = raw_bytes
      if b"\n" not in npy_header_bytes:
        try:
          stream_pos = pickle_stream.tell()
          npy_header_bytes = pickle_stream.read(65536)
          pickle_stream.seek(stream_pos)
        except (OSError, AttributeError, io.UnsupportedOperation):
          pass
      is_obj_npy = _is_object_npy_header(npy_header_bytes)
      return (is_obj_npy, 1 if is_obj_npy else 0)

  valid_opcodes_count = 0
  while True:
    charcode = pickle_stream.read(1)
    if not charcode:
      return (valid_opcodes_count >= 3, valid_opcodes_count)

    decoded_char = charcode.decode("latin-1")
    if decoded_char == ".":
      valid_opcodes_count += 1
      return (True, valid_opcodes_count)

    opcode = constants.OPCODES_INFO.get(decoded_char)
    if opcode is None:
      return (valid_opcodes_count >= 3, valid_opcodes_count)

    valid_opcodes_count += 1
    if valid_opcodes_count > constants.MAX_BYTES_TO_CHECK:
      return (True, valid_opcodes_count)

    if opcode.arg is None:
      continue

    if opcode.name in constants.PAYLOAD_PREFIX_SIZES and hasattr(
        pickle_stream, "seek"
    ):
      prefix_size = constants.PAYLOAD_PREFIX_SIZES[opcode.name]
      len_bytes = pickle_stream.read(prefix_size)
      if len(len_bytes) != prefix_size:
        return (valid_opcodes_count >= 3, valid_opcodes_count)

      payload_len = int.from_bytes(len_bytes, "little")
      cur_pos = pickle_stream.tell()
      known_end_pos = getattr(pickle_stream, "_orig_file_size", None)
      if known_end_pos is None:
        known_end_pos = getattr(pickle_stream, "size", None)
      if isinstance(known_end_pos, int):
        end_pos = known_end_pos
      else:
        pickle_stream.seek(0, io.SEEK_END)
        end_pos = pickle_stream.tell()
      if cur_pos + payload_len > end_pos:
        return (valid_opcodes_count >= 3, valid_opcodes_count)

      pickle_stream.seek(cur_pos + payload_len)
      continue

    try:
      if opcode.name in ("INT", "LONG", "PUT", "GET"):
        raw_line = pickle_stream.readline()
        if not raw_line.endswith(b"\n"):
          raise ValueError("Truncated newline argument")
        clean_number_bytes = _clean_protocol0_line(raw_line[:-1]).rstrip(b"L")
        if clean_number_bytes not in (b"00", b"01"):
          int(clean_number_bytes, 0)
      elif opcode.name == "FLOAT":
        raw_line = pickle_stream.readline()
        if not raw_line.endswith(b"\n"):
          raise ValueError("Truncated float argument")
        clean_float_bytes = _clean_protocol0_line(raw_line[:-1])
        float(clean_float_bytes)
      elif opcode.name == "STRING":
        raw_line = pickle_stream.readline()
        if not raw_line.endswith(b"\n"):
          raise ValueError("Truncated string argument")
        clean_str_bytes = raw_line[:-1].rstrip(b"\r")
        if (
            len(clean_str_bytes) < 2
            or clean_str_bytes[0:1] not in (b"'", b'"')
            or clean_str_bytes[-1:] != clean_str_bytes[0:1]
        ):
          raise ValueError("Unquoted string argument")
      elif opcode.name in ("UNICODE", "PERSID"):
        raw_line = pickle_stream.readline()
        if not raw_line.endswith(b"\n"):
          raise ValueError("Truncated unicode/persid argument")
      elif opcode.name in ("GLOBAL", "INST"):
        for _ in range(2):
          raw_line = pickle_stream.readline()
          if not raw_line.endswith(b"\n"):
            raise ValueError("Truncated global/inst argument")
      else:
        _ = opcode.arg.reader(pickle_stream)
    except ValueError:
      return (valid_opcodes_count >= 3, valid_opcodes_count)


def is_pickle_file(
    pickle_bytes: bytes | IO[bytes],
    return_num_bytes_read: bool = False,
    check_magic_bytes: bool = True,
) -> bool | tuple[bool, int]:
  """Checks if the provided bytes represent a valid pickle file.

  This function reads the beginning of the input byte stream, looking for
  valid pickle opcodes. It stops after reading a maximum number of bytes,
  defined by `_MAX_BYTES_TO_CHECK`, to avoid processing very large inputs.
  Do note that this is not foolproof and false positives are possible.

  Args:
      pickle_bytes: The bytes or stream to check.
      return_num_bytes_read: If True, returns a tuple containing a boolean
        indicating if the file is a valid pickle file and the number of bytes
        read. Otherwise, it returns only the boolean.
      check_magic_bytes: If True, checks for text-based or archive magic bytes
        to fast-path reject files that are not pickles.

  Returns:
      If `return_num_bytes_read` is True:
        - A tuple `(True, number_of_bytes_read)` if the input is likely a valid
          pickle file, and the number of bytes read.
        - A tuple `(False, number_of_bytes_read)` if the input is not a valid
          pickle file, and the number of bytes read.
      If `return_num_bytes_read` is False:
        - True if the input is likely a valid pickle file.
        - False if the input is not a valid pickle file.
  """
  original_pos = None
  is_seekable = True
  if isinstance(pickle_bytes, bytes):
    raw_bytes = pickle_bytes
    pickle_stream = io.BytesIO(pickle_bytes)
  else:
    try:
      original_pos = pickle_bytes.tell()
    except (OSError, io.UnsupportedOperation, AttributeError):
      is_seekable = False

    if is_seekable:
      raw_bytes = pickle_bytes.read(1024)
      pickle_bytes.seek(original_pos)  # pyrefly: ignore[bad-argument-type]
      pickle_stream = pickle_bytes
    elif hasattr(pickle_bytes, "peek"):
      try:
        raw_bytes = pickle_bytes.peek(1024)
        pickle_stream = pickle_bytes
      except (OSError, io.UnsupportedOperation):
        raw_bytes = pickle_bytes.read(1024)
        pickle_stream = io.BytesIO(raw_bytes)
    else:
      raw_bytes = pickle_bytes.read(1024)
      pickle_stream = io.BytesIO(raw_bytes)

  try:
    is_valid, opcodes_count = _check_pickle_stream(
        raw_bytes, pickle_stream, check_magic_bytes
    )
    return (is_valid, opcodes_count) if return_num_bytes_read else is_valid
  finally:
    if original_pos is not None:
      pickle_stream.seek(original_pos)


def find_pickle_start_offset(pickle_bytes: bytes | IO[bytes]) -> int:
  """Finds the start offset of a valid pickle payload in the bytes."""
  if isinstance(pickle_bytes, bytes):
    header_bytes = pickle_bytes[:1024]
    original_pos = 0
  else:
    try:
      original_pos = pickle_bytes.tell()
      header_bytes = pickle_bytes.read(1024)
      pickle_bytes.seek(original_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      return 0

  if header_bytes.startswith(b"\x93NUMPY"):
    npy_header_bytes = header_bytes
    if b"\n" not in npy_header_bytes[10:]:
      if isinstance(pickle_bytes, bytes):
        npy_header_bytes = pickle_bytes[:65536]
      else:
        try:
          npy_header_bytes = pickle_bytes.read(65536)
          pickle_bytes.seek(original_pos)
        except (OSError, AttributeError, io.UnsupportedOperation):
          pass
    if _is_object_npy_header(npy_header_bytes):
      newline_pos = npy_header_bytes.find(b"\n", 10)
      if newline_pos != -1 and (
          not isinstance(pickle_bytes, bytes)
          or is_pickle_file(pickle_bytes[newline_pos + 1 :])
      ):
        return newline_pos + 1
    return 0

  for offset in range(len(header_bytes)):
    if (
        header_bytes[offset : offset + 1].decode("latin-1")
        not in constants.OPCODES_INFO
    ):
      continue
    if isinstance(pickle_bytes, bytes):
      if is_pickle_file(pickle_bytes[offset:]):
        return offset
      continue
    try:
      pickle_bytes.seek(original_pos + offset)
      if is_pickle_file(pickle_bytes):
        return offset
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass
    finally:
      try:
        pickle_bytes.seek(original_pos)
      except (OSError, AttributeError, io.UnsupportedOperation):
        pass

  return 0


@functools.cache
def get_module_members(module_name: str) -> Set[str] | None:
  """Tries to get module members by parsing the source file without execution of __init__.py.

  Args:
    module_name: The name of the module to get members from.

  Returns:
    A set of module members, or None for the following cases:
    1. if the module could not be parsed.
    2. If an ImportError is raised.
    3. If AST parsing fails, and SyntaxError or ValueError is raised.
    4. If spec is not present and its origin does not exist.
  """

  # If module is already imported, __init__.py will not be called while
  # importing the module again
  if module_name in sys.modules:
    try:
      imported_module = importlib.import_module(module_name)
    except ImportError:
      return None
    members = {member for member, _ in inspect.getmembers(imported_module)}
    return members

  try:
    spec = importlib.util.find_spec(module_name)
  except (ImportError, AttributeError, ValueError):
    return None
  if spec is None:
    return None
  if (origin := spec.origin) is None or origin in ("built-in", "frozen"):
    return None

  try:
    with open(origin, "r") as f:
      tree = ast.parse(f.read(), filename=origin)
  except (
      IOError,
      OSError,
      ValueError,
      SyntaxError,
      RecursionError,
  ):
    return None

  members = {
      node.name
      for node in ast.walk(tree)
      if isinstance(node, (ast.FunctionDef, ast.ClassDef))
  }
  return members


def get_optimal_workers(file_size: int) -> int:
  """Calculates the optimal number of workers based on the file size using tiers.

  Args:
    file_size: The size of the file in bytes.

  Returns:
    The optimal number of workers to use.
  """
  if file_size is None:
    return 1
  for threshold, workers in constants.WORKER_TIERS:
    if file_size < threshold:
      return min(constants.MAX_NUM_CHUNKS or 1, workers)

  # If file size is larger than or equal to the largest threshold,
  # use logarithmic scaling.
  largest_threshold, largest_workers = constants.WORKER_TIERS[-1]
  # Ensure largest_workers is capped at MAX_NUM_CHUNKS before scaling up.
  largest_workers = min(largest_workers, constants.MAX_NUM_CHUNKS or 1)
  scaled_workers = largest_workers + int(
      math.log(file_size / largest_threshold, 2)
  )

  # Cap at around half the number of available CPU cores.
  return min(constants.MAX_NUM_CHUNKS or 1, scaled_workers)


def matches_symbol_prefix_list(
    symbol: str,
    prefixes: Sequence[str] | Set[str] | FrozenSet[str],
    *,
    match_suffix: bool = False,
) -> bool:
  """Checks whether a dotted symbol matches or is a child of any prefix.

  Evaluates whether `symbol` is an exact match for any entry in `prefixes` or
  starts with `<entry>.` as a submodule/attribute path (and optionally whether
  an entry ends with `.<symbol>` for uncombined opcode string operands).

  Args:
    symbol: The dotted module, class, or attribute name to check.
    prefixes: A collection of exact symbol names or package prefixes.
    match_suffix: Whether to also match when an entry in `prefixes` ends with
      `.<symbol>`.

  Returns:
    True if `symbol` matches an entry in `prefixes`, or False otherwise.
  """
  if not symbol:
    return False

  for item in prefixes:
    if symbol == item or symbol.startswith(f"{item}."):
      return True
    if match_suffix and item.endswith(f".{symbol}"):
      return True

  return False


def is_self_protected_symbol(symbol: str) -> bool:
  """Checks whether a symbol targets internal scanner or sandbox protections.

  Prevents project-level allow-list entries from overriding self-protection
  invariants on `saferpickle`, `corrupy`, `picklemagic`, or
  `config.set_config_path`, while excluding synthetic sandbox marker symbols.

  Args:
    symbol: The dotted module, class, function, or opcode string operand to
      check.

  Returns:
    True if `symbol` matches a non-overridable self-protection prefix, or False
    otherwise.
  """
  if not symbol or symbol in constants.INTERNAL_SANDBOX_SAFE_SYMBOLS:
    return False

  return matches_symbol_prefix_list(
      symbol, constants.SELF_PROTECTED_PREFIXES, match_suffix=True
  )


def is_unsafe_for_fail_fast(symbol: str) -> bool:
  """Checks whether a symbol is classified as `UNSAFE` for `fail_fast` scanning.

  Evaluates the given symbol against the configured allow-list first, and if
  not allow-listed, classifies the symbol using `classify_symbol`. Returns
  True only for `Classification.UNSAFE` so `Classification.SUSPICIOUS`
  operands do not prematurely terminate `fail_fast` opcode scanning before
  subsequent `UNSAFE` payloads are reached.

  Args:
    symbol: The module, class, function, or opcode string operand to evaluate.

  Returns:
    True if the symbol is not allow-listed and is classified as `UNSAFE`, or
    False otherwise.
  """
  if not is_self_protected_symbol(symbol) and matches_symbol_prefix_list(
      symbol, config.get_allow_list(), match_suffix=True
  ):
    return False

  classification = classify_symbol(symbol)
  return classification == Classification.UNSAFE


def resolve_library_modules_from_results(
    set_of_results: Set[str],
) -> Set[str]:
  """Processes a set of strings to combine Python libraries and their members.

  For example, given {"os", "system", "pickle.loads"}, this function will
  return {"os.system", "pickle.loads"}.

  Args:
    set_of_results: A set of strings, some of which may be Python library names
      and others may be their members.

  Returns:
    final_results: A set of strings with libraries and their corresponding
    members joined by a dot, along with any other strings from the original set.
  """
  final_results = {symbol for symbol in set_of_results if "." in symbol}
  candidates = set_of_results - final_results

  # Identify which of the remaining candidates are actual importable modules.
  importable_modules = {}
  for candidate_name in candidates:
    module_name = candidate_name.split(".")[0]
    if module_name == "__main__" or is_self_protected_symbol(candidate_name):
      continue

    # Find spec to avoid importing risky modules from a loose python file
    # like import.py or similar.
    try:
      module_spec = importlib.util.find_spec(candidate_name)
    except (ImportError, AttributeError, ValueError):
      module_spec = None
    if module_spec is not None:
      module_members = get_module_members(candidate_name)
      if module_members is not None:
        importable_modules[candidate_name] = module_members

  resolved_candidates = set()
  # Combine modules with any members found in the candidates list.
  for module_name, members in importable_modules.items():
    found_member_in_candidates = False
    for member_name in candidates:
      if member_name in members:
        final_results.add(f"{module_name}.{member_name}")
        resolved_candidates.add(module_name)
        resolved_candidates.add(member_name)
        found_member_in_candidates = True

    # If an importable module was not combined with any member, and it hasn't
    # been used as a member itself, add it as a standalone item.
    if (
        not found_member_in_candidates
        and module_name not in resolved_candidates
    ):
      final_results.add(module_name)
      resolved_candidates.add(module_name)

  # Add any remaining items that were not resolved as modules or members.
  final_results.update(candidates - resolved_candidates)

  # Filter out base libraries if a qualified member from that module is present.
  # Eg. Remove os if os.system is present.
  libraries_to_remove = set()
  modules_to_remove = set()
  for result in final_results:
    if "." not in result:
      continue
    base_library, base_module = result.split(".", 1)
    result_classification = classify_symbol(result)
    if (
        base_library in final_results
        and base_library not in ("builtins", "__builtin__")
        and (
            classify_symbol(base_library) == result_classification
            or result_classification == Classification.UNSAFE
        )
    ):
      libraries_to_remove.add(base_library)
    if (
        "." not in base_module
        and base_module in final_results
        and base_module not in constants.UNSAFE_STRINGS
        and base_module not in constants.SUSPICIOUS_STRINGS
        and base_module not in constants.DANGEROUS_PACKAGE_MEMBERS
        and not is_dunder_or_introspection_attr(base_module)
        and (
            classify_symbol(base_module) == result_classification
            or result_classification == Classification.UNSAFE
        )
    ):
      modules_to_remove.add(base_module)

  final_results.difference_update(libraries_to_remove)
  final_results.difference_update(modules_to_remove)

  # Remove less specific versions of qualified modules.
  # Eg. Remove requests.api if requests.api.post is present.
  underspecific_qualified_modules_to_remove = set()
  for qualified_result in final_results:
    result_classification = classify_symbol(qualified_result)
    attribute_parts = qualified_result.split(".")
    # Check for less specific versions of the current item
    for prefix_length in range(1, len(attribute_parts)):
      parent_symbol = ".".join(attribute_parts[:prefix_length])
      if parent_symbol not in final_results:
        continue
      parent_classification = classify_symbol(parent_symbol)
      if (
          parent_classification == result_classification
          or result_classification == Classification.UNSAFE
      ):
        underspecific_qualified_modules_to_remove.add(parent_symbol)

  final_results.difference_update(underspecific_qualified_modules_to_remove)

  return final_results


@functools.lru_cache(maxsize=1)
def get_all_active_approved_base_classes() -> tuple[type[Any], ...]:
  """Resolves active approved base classes currently loaded in `sys.modules`.

  Combines safe Python builtin primitive and container types with any class
  specifications in `constants.ALL_BASE_CLASS_SPECS` that are currently
  loaded in `sys.modules`, without importing new modules.

  Returns:
    A tuple of resolved `type` objects representing approved base classes.
  """
  bases = (dict, list, tuple, set, frozenset, int, float, str, bytes, bool)
  resolved = tuple(
      cls
      for spec in constants.ALL_BASE_CLASS_SPECS
      if isinstance(cls := _resolve_dotted_path_in_sys_modules(spec), type)
  )
  return bases + resolved


def _find_module_source_file(mod_path: str) -> str | None:
  """Locates a module's `.py` source file on disk without importing submodules.

  Walks backward from the most specific module prefix in `sys.modules` and
  resolves the remaining relative path segments against the loaded package's
  `__path__` directories.

  Args:
    mod_path: Dotted module path (e.g., `'torch.nn.modules.linear'`).

  Returns:
    The filesystem path to the module's `.py` or `__init__.py` file if found
    on disk, or None otherwise.
  """
  parts = mod_path.split(".")
  for idx in range(len(parts), 0, -1):
    loaded_mod = sys.modules.get(".".join(parts[:idx]))
    if (
        idx == len(parts)
        and isinstance(mod_file := getattr(loaded_mod, "__file__", None), str)
        and os.path.isfile(mod_file)
    ):
      return mod_file

    if mod_paths := getattr(loaded_mod, "__path__", None):
      for base_dir in mod_paths:
        candidate = os.path.join(base_dir, *parts[idx:])
        for path in (f"{candidate}.py", os.path.join(candidate, "__init__.py")):
          if os.path.isfile(path):
            return path
      break

  return None


def _ast_expr_to_dotted_name(expr: ast.AST, import_map: dict[str, str]) -> str:
  """Resolves an AST expression node into a fully qualified dotted string.

  Reconstructs dotted names from `ast.Name`, `ast.Attribute`, `ast.Call`, and
  `ast.Subscript` nodes and expands leading aliases using `import_map`.

  Args:
    expr: The AST expression node representing a base class or decorator.
    import_map: Mapping from local alias names to imported dotted module paths.

  Returns:
    The resolved dotted name string, or an empty string if `expr` cannot be
    represented as a dotted name.
  """
  if isinstance(expr, ast.Name):
    return import_map.get(expr.id, expr.id)

  if isinstance(expr, ast.Attribute):
    parent = _ast_expr_to_dotted_name(expr.value, import_map)
    return f"{parent}.{expr.attr}" if parent else expr.attr

  if isinstance(expr, (ast.Call, ast.Subscript)):
    target = expr.func if isinstance(expr, ast.Call) else expr.value
    return _ast_expr_to_dotted_name(target, import_map)

  return ""


def _code_object_has_dangerous_names(
    code_object: types.CodeType, visited_code_ids: set[int]
) -> bool:
  """Checks whether a bytecode object references any dangerous global names.

  Inspects `code_object.co_names` and recursively traverses nested code
  objects in `code_object.co_consts` to detect references to symbols in
  `constants.DANGEROUS_CODE_NAMES`.

  Args:
    code_object: The Python `CodeType` object to inspect.
    visited_code_ids: Set of already-visited `id(code_object)` values used to
      prevent cycles.

  Returns:
    True if `code_object` or any nested code constant references a dangerous
    name, or False otherwise.
  """
  if id(code_object) in visited_code_ids:
    return False
  visited_code_ids.add(id(code_object))

  if any(
      name in constants.DANGEROUS_CODE_NAMES for name in code_object.co_names
  ):
    return True

  return any(
      isinstance(const, types.CodeType)
      and _code_object_has_dangerous_names(const, visited_code_ids)
      for const in code_object.co_consts
  )


def _is_safe_approved_root_function(
    target_callable: Any, symbol_name: str, module_path: str
) -> bool:
  """Verifies whether a callable in an approved root is a safe reconstructor.

  Checks whether `symbol_name` matches known reconstructor names or markers
  in an approved package root, unwraps decorators, and inspects the
  underlying bytecode (`__code__`) to ensure no dangerous globals or builtins
  are used.

  Args:
    target_callable: The live function or callable object from `sys.modules`.
    symbol_name: The attribute name of the callable.
    module_path: The dotted module path from which the callable was resolved.

  Returns:
    True if `target_callable` is a verified-safe reconstructor function, or
    False otherwise.
  """
  symbol_lower = symbol_name.lower()
  callable_module = getattr(target_callable, "__module__", "") or module_path
  is_candidate_reconstructor = (
      symbol_name in constants.APPROVED_RECONSTRUCTOR_FUNCTIONS
      or any(
          marker in symbol_lower
          for marker in constants.RECONSTRUCTOR_NAME_MARKERS
      )
      or bool(
          {module_path, callable_module}
          & {"numpy._core.fromnumeric", "numpy.core.fromnumeric"}
      )
  )
  if not is_candidate_reconstructor:
    return False

  unwrapped = inspect.unwrap(target_callable)
  if isinstance(
      code_object := getattr(unwrapped, "__code__", None), types.CodeType
  ):
    return not _code_object_has_dangerous_names(code_object, set())

  return symbol_name in constants.APPROVED_RECONSTRUCTOR_FUNCTIONS


def _is_unsafe_class_path(full_name: str) -> bool:
  """Checks whether a class path belongs to an unsafe root or unsafe symbol.

  Evaluates a qualified class or base-class name from MRO or AST inspection.
  Excludes `builtins` and `__builtin__` from root-level blanket rejection so
  benign builtin base classes (such as `builtins.dict` or
  `builtins.Exception`) are only rejected when they match a specific entry in
  `UNSAFE_STRINGS`.

  Args:
    full_name: Fully qualified class or base-class path to check.

  Returns:
    True if `full_name` is under an unsafe root package or matches an entry in
    `UNSAFE_STRINGS`, or False otherwise.
  """
  if not full_name:
    return False

  root = full_name.split(".")[0]
  # Exclude builtins from root-level rejection so benign MRO ancestors (e.g.
  # builtins.dict) are evaluated per-symbol against UNSAFE_STRINGS below.
  if root in constants.UNSAFE_ROOT_PACKAGES and root not in (
      "builtins",
      "__builtin__",
  ):
    return True
  return any(
      full_name == unsafe or full_name.startswith(f"{unsafe}.")
      for unsafe in constants.UNSAFE_STRINGS
  )


@functools.lru_cache(maxsize=512)
def _inspect_class_via_ast(
    file_path: str, symbol_name: str, root_pkg: str
) -> Classification | None:
  """Classifies a class definition by statically parsing its `.py` source file.

  Parses `file_path` with `ast.parse` without importing the module, resolves
  top-level imports, and inspects the target `ast.ClassDef` node's base
  classes, decorators, and lifecycle hook methods.

  Args:
    file_path: Filesystem path to the `.py` module source file.
    symbol_name: Name of the class symbol to inspect within `file_path`.
    root_pkg: Top-level root package name (e.g., `"torch"` or `"custom_pkg"`).

  Returns:
    A `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) if the
    symbol is defined at top level in `file_path`, or None if the file cannot
    be parsed or the symbol is not found.
  """
  try:
    with open(
        file_path, "r", encoding="utf-8", errors="ignore"
    ) as source_file:
      tree = ast.parse(source_file.read(), filename=file_path)
  except (IOError, OSError, SyntaxError, ValueError, TypeError):
    return None

  import_map: dict[str, str] = {}
  for node in tree.body:
    if isinstance(node, ast.Import):
      for alias in node.names:
        import_map[alias.asname or alias.name] = alias.name
    elif isinstance(node, ast.ImportFrom) and node.module:
      for alias in node.names:
        import_map[alias.asname or alias.name] = f"{node.module}.{alias.name}"

  for node in tree.body:
    if getattr(node, "name", None) != symbol_name:
      continue
    if not isinstance(node, ast.ClassDef) or symbol_name.startswith("_"):
      return Classification.UNKNOWN

    method_names = {
        item.name
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    resolved_bases = [
        _ast_expr_to_dotted_name(base_expr, import_map)
        for base_expr in node.bases
    ]
    if any(_is_unsafe_class_path(base_name) for base_name in resolved_bases):
      return Classification.UNSAFE

    if method_names & {"__reduce__", "__reduce_ex__"}:
      return Classification.SUSPICIOUS

    if any(
        _ast_expr_to_dotted_name(dec, import_map).endswith("dataclass")
        for dec in node.decorator_list
    ):
      return Classification.SAFE

    if any(
        base_name in constants.APPROVED_AST_BASE_NAMES
        or (
            isinstance(
                live_base := _resolve_dotted_path_in_sys_modules(base_name),
                type,
            )
            and issubclass(live_base, get_all_active_approved_base_classes())
        )
        for base_name in resolved_bases
    ):
      return Classification.SAFE

    if (
        root_pkg not in ("custom_pkg", "collections", "datetime", "enum")
        and set(resolved_bases) <= {"object", "builtins.object"}
        and not (method_names & constants.DANGEROUS_CLASS_LIFECYCLE_HOOKS)
    ):
      return Classification.SAFE

    return Classification.UNKNOWN

  return None


def _resolve_dotted_path_in_sys_modules(dotted_path: str) -> Any | None:
  """Resolves a dotted module or attribute path from `sys.modules`.

  Looks up `dotted_path` directly in `sys.modules` first, and if not found,
  walks the attribute chain from the root module in `sys.modules` using
  `getattr` without importing any new modules.

  Args:
    dotted_path: Dotted module, class, or attribute path to resolve.

  Returns:
    The resolved module, class, or attribute object if present in
    `sys.modules`, or None if any segment is not loaded.
  """
  if (loaded_module := sys.modules.get(dotted_path)) is not None:
    return loaded_module

  path_parts = dotted_path.split(".")
  current_obj: Any = sys.modules.get(path_parts[0])
  for attribute_name in path_parts[1:]:
    if current_obj is None:
      return None
    current_obj = getattr(current_obj, attribute_name, None)

  return current_obj


def _is_installed_root_package(root_package: str) -> bool:
  """Checks whether a root package is loaded in `sys.modules` or installed.

  Verifies that `root_package` is a valid Python identifier and checks
  whether it is already present in `sys.modules` or discoverable via
  `importlib.util.find_spec`.

  Args:
    root_package: Top-level package name to check.

  Returns:
    True if `root_package` is loaded in `sys.modules` or has a valid module
    spec on disk, or False otherwise.
  """
  if not root_package or not root_package.isidentifier():
    return False

  try:
    return (
        root_package in sys.modules
        or importlib.util.find_spec(root_package) is not None
    )
  except (ImportError, AttributeError, ValueError):
    return False


def _classify_loaded_class_mro(
    target_class: type[Any], symbol_name: str, root_package: str
) -> Classification:
  """Classifies a live class object by inspecting its module, MRO, and methods.

  Walks `target_class.__mro__` to verify that no ancestor originates from an
  unsafe package or defines dangerous pickle lifecycle hooks, and checks
  whether `target_class` inherits from an approved base class or is a simple
  data class with safe constructor bytecode.

  Args:
    target_class: The live `type` object resolved from `sys.modules`.
    symbol_name: Name of the class symbol being classified.
    root_package: Expected top-level root package name from the symbol path.

  Returns:
    The `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) for
    `target_class`.
  """
  try:
    class_module = getattr(target_class, "__module__", "") or ""
    class_root = class_module.split(".")[0] if class_module else ""
    if (
        class_root != root_package
        and class_root not in constants.APPROVED_ROOT_PACKAGES
    ):
      if class_root in constants.UNSAFE_ROOT_PACKAGES:
        return Classification.UNSAFE
      return Classification.SUSPICIOUS

    approved_bases = get_all_active_approved_base_classes()
    is_approved_subclass = issubclass(target_class, approved_bases)
    has_suspicious_hook = False

    for ancestor in target_class.__mro__:
      if ancestor is object:
        continue

      ancestor_mod = getattr(ancestor, "__module__", "") or ""
      ancestor_qual = getattr(
          ancestor, "__qualname__", getattr(ancestor, "__name__", "")
      )
      if _is_unsafe_class_path(f"{ancestor_mod}.{ancestor_qual}"):
        return Classification.UNSAFE

      if ancestor in approved_bases:
        continue

      if not is_approved_subclass and any(
          hook in ancestor.__dict__
          for hook in constants.DANGEROUS_CLASS_LIFECYCLE_HOOKS
      ):
        has_suspicious_hook = True

      if root_package == "custom_pkg" and (
          "__reduce__" in ancestor.__dict__
          or "__reduce_ex__" in ancestor.__dict__
      ):
        has_suspicious_hook = True

    if target_class in approved_bases:
      return Classification.SAFE

    if has_suspicious_hook:
      return Classification.SUSPICIOUS

    if symbol_name.startswith("_"):
      return Classification.UNKNOWN

    if is_approved_subclass:
      return Classification.SAFE

    if (
        root_package not in ("custom_pkg", "collections", "datetime", "enum")
        and type(target_class) is type  # pylint: disable=unidiomatic-typecheck
        and target_class.__bases__ == (object,)
    ):
      for ctor_name in ("__new__", "__init__"):
        if ctor_name not in target_class.__dict__:
          continue
        ctor_code = getattr(target_class.__dict__[ctor_name], "__code__", None)
        if not isinstance(ctor_code, types.CodeType) or (
            _code_object_has_dangerous_names(ctor_code, set())
        ):
          return Classification.UNKNOWN
      return Classification.SAFE
  except (TypeError, AttributeError, ValueError, RuntimeError):
    return Classification.UNKNOWN

  return Classification.UNKNOWN


def classify_approved_root_symbol(symbol: str) -> Classification | None:
  """Classifies a dotted symbol under an approved root package.

  Inspects a dotted symbol without executing arbitrary module imports by
  checking (1) loaded modules and objects in `sys.modules` (verifying class
  MROs or reconstructor bytecode), (2) static `.py` source files on disk via
  `ast.parse`, and (3) structural naming rules for uninstalled approved
  roots.

  Args:
    symbol: Fully qualified dotted symbol string (e.g., `'torch.nn.Linear'`).

  Returns:
    The `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) if
    the symbol belongs to an unsafe or approved root package, or None if the
    symbol is unqualified or belongs to an unlisted root package.
  """
  if not symbol or "." not in symbol:
    return None

  symbol_parts = symbol.split(".")
  root_package = symbol_parts[0]
  if root_package in constants.UNSAFE_ROOT_PACKAGES:
    return Classification.UNSAFE
  if root_package not in constants.APPROVED_ROOT_PACKAGES:
    return None

  module_path = ".".join(symbol_parts[:-1])
  symbol_name = symbol_parts[-1]

  if symbol in constants.ALL_BASE_CLASS_SPECS:
    return Classification.SAFE

  target_module = _resolve_dotted_path_in_sys_modules(module_path)
  if target_module is not None:
    target_object = getattr(target_module, symbol_name, None)
    if target_object is None:
      return Classification.UNKNOWN

    if isinstance(target_object, types.ModuleType):
      module_root = (getattr(target_object, "__name__", "") or "").split(".")[0]
      if module_root in constants.UNSAFE_ROOT_PACKAGES:
        return Classification.UNSAFE
      has_private_segment = any(
          seg.startswith("_") and seg != "_core" for seg in symbol_parts[1:]
      )
      if module_root != root_package or has_private_segment:
        return Classification.SUSPICIOUS
      return Classification.SAFE

    if not isinstance(target_object, type):
      if _is_safe_approved_root_function(
          target_object, symbol_name, module_path
      ):
        return Classification.SAFE
      return Classification.UNKNOWN

    return _classify_loaded_class_mro(target_object, symbol_name, root_package)

  if (source_file := _find_module_source_file(module_path)) is not None:
    return (
        _inspect_class_via_ast(source_file, symbol_name, root_package)
        or Classification.UNKNOWN
    )

  if _find_module_source_file(symbol) is not None:
    return Classification.SAFE

  is_public_pascal_case = symbol_name[
      :1
  ].isupper() and not symbol_name.startswith("_")
  has_only_module_segments = all(
      not part.startswith("_") and part.islower() for part in symbol_parts[1:-1]
  )
  if (
      is_public_pascal_case
      and has_only_module_segments
      and (
          not _is_installed_root_package(root_package)
          or (root_package == "custom_pkg" and module_path not in sys.modules)
      )
  ):
    return Classification.SAFE

  return Classification.UNKNOWN


is_safe_class_dynamic = classify_approved_root_symbol


def is_dunder_or_introspection_attr(attribute_name: str) -> bool:
  """Checks if `attribute_name` is a non-reconstructor dunder or frame attr.

  Allows standard pickle reconstructor dunders in
  `constants.SAFE_DUNDER_RECONSTRUCTORS` (`__newobj__`, `__newobj_ex__`),
  while flagging all other `__*__` dunder names and frame/function/generator
  introspection attributes (`func_*`, `f_*`, `gi_*`, `cr_*`, `ag_*`, `co_*`).

  Args:
    attribute_name: Single identifier segment or attribute name to check.

  Returns:
    True if `attribute_name` is a non-reconstructor dunder or introspection
    attribute, or False otherwise.
  """
  if attribute_name in constants.SAFE_DUNDER_RECONSTRUCTORS:
    return False

  is_dunder = (
      len(attribute_name) > 4
      and attribute_name.startswith("__")
      and attribute_name.endswith("__")
  )
  is_introspection = (
      attribute_name.startswith(constants.INTROSPECTION_ATTRIBUTE_PREFIXES)
      or attribute_name in constants.INTROSPECTION_ATTRIBUTES
  )
  return is_dunder or is_introspection


@functools.lru_cache(maxsize=16384)
def classify_symbol(symbol: str) -> Classification:
  """Classifies a symbol's safety against configured static and dynamic rules.

  Normalizes two-token global strings, checks builtin types, dangerous
  package members, inline code patterns, unsafe/suspicious root packages and
  prefixes, safe metadata attributes on verified-safe prefixes, and
  dynamic/AST package hierarchy rules for approved root packages.

  Args:
    symbol: The symbol or operand string to classify.

  Returns:
    The `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) for
    the given symbol.
  """
  if not symbol:
    return Classification.UNKNOWN

  symbol_clean = symbol.strip()
  tokens = symbol_clean.split()
  if len(tokens) == 2:
    joined = f"{tokens[0]}.{tokens[1]}"
    root_mod = tokens[0].split(".")[0]
    if all(part.isidentifier() for part in joined.split(".")) and (
        root_mod in ("__builtin__",)
        or root_mod in constants.APPROVED_ROOT_PACKAGES
        or root_mod in constants.UNSAFE_ROOT_PACKAGES
        or root_mod in constants.ALL_STRINGS
        or _is_installed_root_package(root_mod)
    ):
      symbol_clean = joined

  raw_parts = (
      symbol_clean.split(".")
      if ("." in symbol_clean and " " not in symbol_clean)
      else []
  )
  parts = (
      raw_parts
      if all(identifier_part.isidentifier() for identifier_part in raw_parts)
      else []
  )
  if parts:
    if (
        parts[0] in ("builtins", "__builtin__")
        and len(parts) == 2
        and parts[1] in constants.SAFE_BUILTIN_TYPES
    ):
      return Classification.SAFE

    if any(part in constants.DANGEROUS_PACKAGE_MEMBERS for part in parts[1:]):
      return Classification.UNSAFE

  if symbol_clean in constants.UNSAFE_STRINGS:
    return Classification.UNSAFE

  symbol_normalized = _WHITESPACE_NORMALIZE_RE.sub(" ", symbol_clean.lower())
  if any(pat in symbol_normalized for pat in constants.UNSAFE_INLINE_PATTERNS):
    return Classification.UNSAFE

  if symbol_clean in constants.SUSPICIOUS_STRINGS:
    return Classification.SUSPICIOUS

  if (
      symbol_clean in constants.SAFE_STRINGS
      or symbol_clean in constants.INTERNAL_SANDBOX_SAFE_SYMBOLS
  ):
    return Classification.SAFE

  if parts and (
      parts[0] in constants.UNSAFE_ROOT_PACKAGES
      or any(part in constants.DANGEROUS_EXEC_MODULES for part in parts[1:])
  ):
    return Classification.UNSAFE

  if parts and any(
      symbol_clean.startswith(f"{u}.") for u in constants.UNSAFE_STRINGS
  ):
    return Classification.UNSAFE

  if (
      len(parts) >= 2
      and (mapped := _COMPAT_PICKLE.NAME_MAPPING.get((parts[0], parts[1])))
      is not None
  ):
    mapped_symbol = ".".join((*mapped, *parts[2:]))
    if mapped_symbol != symbol_clean:
      return classify_symbol(mapped_symbol)

  if parts and (
      any(
          symbol_clean.startswith(f"{suspicious_symbol}.")
          for suspicious_symbol in constants.SUSPICIOUS_STRINGS
      )
      or parts[-1] in constants.SUSPICIOUS_STRINGS
  ):
    return Classification.SUSPICIOUS

  if parts:
    prefix_symbol = ".".join(parts[:-1])
    has_intermediate_dunder = any(
        is_dunder_or_introspection_attr(part) for part in parts[1:-1]
    )
    if (
        not has_intermediate_dunder
        and parts[-1] in constants.SAFE_METADATA_ATTRIBUTES
        and (
            prefix_symbol in constants.APPROVED_ROOT_PACKAGES
            or classify_symbol(prefix_symbol) == Classification.SAFE
        )
    ):
      return Classification.SAFE

    if any(is_dunder_or_introspection_attr(part) for part in parts[1:]):
      return Classification.SUSPICIOUS
  elif (
      is_dunder_or_introspection_attr(symbol_clean)
      and symbol_clean not in constants.SAFE_METADATA_ATTRIBUTES
  ):
    return Classification.SUSPICIOUS

  if parts and parts[0] in constants.APPROVED_ROOT_PACKAGES:
    if parts[-1] in constants.APPROVED_RECONSTRUCTOR_FUNCTIONS:
      return Classification.SAFE

    return classify_approved_root_symbol(symbol_clean) or Classification.UNKNOWN

  if len(parts) >= 2 and parts[0] in _COMPAT_PICKLE.IMPORT_MAPPING:
    mapped_symbol = ".".join(
        (_COMPAT_PICKLE.IMPORT_MAPPING[parts[0]], *parts[1:])
    )
    if mapped_symbol != symbol_clean:
      return classify_symbol(mapped_symbol)

  return Classification.UNKNOWN


classify_class_name = classify_symbol


def resolve_extension_code(code: int) -> str:
  """Resolves a `copyreg` extension code to its registered `'module.name'`.

  Looks up `code` in `copyreg._inverted_registry` and formats the registered
  `(module, name)` pair, or returns a synthetic
  `'unregistered_extension.code_N'` token when the code is not registered.

  Args:
    code: Integer extension code read by `EXT1`, `EXT2`, or `EXT4`.

  Returns:
    The registered `'module.name'` string, or
    `'unregistered_extension.code_<code>'` if unregistered.
  """
  inverted_registry = getattr(copyreg, "_inverted_registry", {})
  key = inverted_registry.get(code)
  if isinstance(key, tuple) and len(key) == 2:
    return f"{key[0]}.{key[1]}"
  return f"unregistered_extension.code_{code}"


def is_potentially_dangerous_literal(operand: str) -> bool:
  """Checks whether a string operand matches dangerous literal or dunder rules.

  Evaluates string literals extracted from pickle opcodes against the
  configured deny-list, inline code execution patterns, dangerous
  code/function type names, non-metadata dunder/introspection attributes, and
  dangerous execution module paths.

  Args:
    operand: Decoded string literal from a pickle string or persistent ID
      opcode.

  Returns:
    True if `operand` matches a deny-listed or dangerous literal pattern, or
    False otherwise.
  """
  if not operand:
    return False

  deny_list = config.get_deny_list()
  if deny_list and matches_symbol_prefix_list(operand, deny_list):
    return True

  operand_lower = operand.lower()
  operand_normalized = _WHITESPACE_NORMALIZE_RE.sub(" ", operand_lower)
  if any(
      inline_pattern in operand_normalized
      for inline_pattern in constants.UNSAFE_INLINE_PATTERNS
  ):
    return True

  if operand in (
      "CodeType",
      "_builtin_type",
      "_make_function",
      "__builtin__",
  ) or (
      is_dunder_or_introspection_attr(operand)
      and operand not in constants.SAFE_METADATA_ATTRIBUTES
  ):
    return True

  if (
      "." in operand
      and " " not in operand
      and all(
          identifier_part.isidentifier()
          for identifier_part in operand.split(".")
      )
  ):
    operand_parts = operand.split(".")
    has_dangerous_dunder_or_attr = any(
        is_dunder_or_introspection_attr(identifier_part)
        for identifier_part in operand_parts
    )
    is_safe_terminal_metadata = (
        len(operand_parts) >= 2
        and operand_parts[-1] in constants.SAFE_METADATA_ATTRIBUTES
        and not any(
            is_dunder_or_introspection_attr(part)
            for part in operand_parts[1:-1]
        )
    )
    if has_dangerous_dunder_or_attr and not is_safe_terminal_metadata:
      return True

    if (
        len(operand_parts) >= 2
        and any(
            identifier_part in constants.DANGEROUS_EXEC_MODULES
            for identifier_part in operand_parts[:-1]
        )
        and operand_parts[-1] in constants.DANGEROUS_CODE_NAMES
    ):
      return True

  return False


def _strip_binary_bytes_repr(text: str) -> str:
  """Strips hex-escaped binary byte literals from a formatted log string.

  Replaces `bytes(...)`, `bytearray(...)`, and hex escape sequences in
  `picklemagic` warning log arguments with spaces so random binary tensor
  weights are not tokenized as identifier names.

  Args:
    text: Raw argument or state string extracted from a `picklemagic` log line.

  Returns:
    The input string with hex-escaped byte representations replaced by
    spaces.
  """
  return _BINARY_BYTES_HEX_RE.sub(" ", text) if "\\x" in text else text


def _parse_and_process_pattern(
    line: str,
    pattern: re.Pattern[str],
    register_item: Callable[..., None],
) -> bool:
  """Parses a log line using a named group regex and processes matches directly."""
  match = pattern.search(line)
  if not match:
    return False

  groups = match.groupdict()
  class_name = groups.get("class_name")
  method_name = groups.get("method_name")
  attr_name = groups.get("attr_name")
  module_name = groups.get("module_name")
  args = groups.get("args", "")
  kwargs = groups.get("kwargs", "")
  state = groups.get("state", "")

  if class_name:
    is_internal = class_name in constants.INTERNAL_FAKE_WARNING_CLASSES
    register_item(class_name)
    if method_name:
      register_item(
          method_name if is_internal else f"{class_name}.{method_name}"
      )

  if attr_name:
    register_item(attr_name)

  if module_name:
    register_item(module_name)

  combined_args = (args or state) + " " + kwargs
  if combined_args.strip():
    combined_args = _strip_binary_bytes_repr(combined_args)
    if "<" in combined_args:
      for class_reference in _CLASS_REF_LOG_RE.findall(combined_args):
        register_item(class_reference, allow_unknown=False)
      for object_reference in _OBJECT_REF_LOG_RE.findall(combined_args):
        register_item(object_reference, allow_unknown=False)

    is_risky_target = bool(class_name) and classify_symbol(class_name) in (
        Classification.UNSAFE,
        Classification.SUSPICIOUS,
    )
    for regex_group in _COMBINED_ARGS_TOKEN_RE.findall(combined_args):
      for candidate_token in regex_group:
        candidate_token = candidate_token.strip(".")
        if candidate_token and not _HEX_TOKEN_PREFIX_RE.match(candidate_token):
          if is_risky_target or is_potentially_dangerous_literal(
              candidate_token
          ):
            register_item(candidate_token, allow_unknown=False)

  return True


def _is_valid_dotted_log_symbol(symbol: str) -> bool:
  """Checks whether a symbol extracted from a log prefix is a valid dotted path.

  Args:
    symbol: Candidate module or class path string.

  Returns:
    True if `symbol` is a non-empty ASCII alphanumeric/underscore/dot token, or
    False otherwise.
  """
  if not symbol or not symbol.isascii():
    return False
  return symbol.replace(".", "").replace("_", "").isalnum()


def categorize_picklemagic(
    filtered_output: io.StringIO,
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
  """Parses and categorizes picklemagic log output."""
  results: dict[Classification, Set[str]] = {
      Classification.SAFE: set(),
      Classification.UNSAFE: set(),
      Classification.SUSPICIOUS: set(),
      Classification.UNKNOWN: set(),
  }

  def register_item(
      item: str,
      override: Classification | None = None,
      allow_unknown: bool = True,
  ):
    base_cls = classify_symbol(item) if item else None
    classification = (
        override
        if (override is not None and base_cls == Classification.UNKNOWN)
        else base_cls
    )
    if classification is not None and (
        allow_unknown or classification != Classification.UNKNOWN
    ):
      results[classification].add(item)

  lines = filtered_output.getvalue().split("\n")
  for line in lines:
    if not line:
      continue

    clean_line = line.removeprefix("WARNING:picklemagic:")
    if clean_line.startswith("Safe module/class imported:"):
      full_name = clean_line.removeprefix("Safe module/class imported:").strip()
      if _is_valid_dotted_log_symbol(full_name):
        results[Classification.SAFE].add(full_name)
        continue

    if clean_line.startswith("Unsafe module/class invoked:"):
      full_name = clean_line.removeprefix(
          "Unsafe module/class invoked:"
      ).strip()
      if _is_valid_dotted_log_symbol(full_name):
        cls = classify_symbol(full_name)
        if cls in (Classification.SAFE, Classification.SUSPICIOUS):
          results[cls].add(full_name)
        else:
          results[Classification.UNSAFE].add(full_name)
          if "." in full_name:
            results[Classification.UNSAFE].add(full_name.split(".", 1)[0])
        continue

    if clean_line.startswith("Unknown module/class imported:"):
      full_name = clean_line.removeprefix(
          "Unknown module/class imported:"
      ).strip()
      if _is_valid_dotted_log_symbol(full_name):
        register_item(full_name)
        continue

    for keyword, pattern in PICKLEMAGIC_PATTERNS:
      if keyword in line and _parse_and_process_pattern(
          line, pattern, register_item
      ):
        break

  return (
      results[Classification.SAFE],
      results[Classification.UNSAFE],
      results[Classification.SUSPICIOUS],
      results[Classification.UNKNOWN],
  )


def _build_opcode_strides() -> tuple[int, ...]:
  """Constructs a 256-element byte stride lookup table for fixed-size opcodes.

  Precomputes fixed byte offset advances for standard pickle opcodes so the
  parser can skip non-string operands in O(1) time without unpacking arguments.

  Returns:
    A 256-element integer tuple where indices represent opcode bytes and values
    represent the total stride in bytes, or -1 for variable-length opcodes.
  """
  strides = [-1] * 256
  for stride, opcodes in constants.OPCODE_STRIDE_GROUPS:
    for opcode_byte in opcodes:
      strides[opcode_byte] = stride
  return tuple(strides)


OPCODE_STRIDES = _build_opcode_strides()


def decode_string_operand(
    data: bytes | mmap.mmap,
    start: int,
    length: int,
    encoding: str = "utf-8",
    *,
    min_length: int = 2,
) -> str | None:
  """Decodes a byte slice into a string operand safely.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    start: The starting byte offset of the string payload.
    length: The byte length of the string payload.
    encoding: The character encoding to apply (defaults to utf-8).
    min_length: Minimum character length required to return the string.

  Returns:
    The decoded string operand if length >= min_length, otherwise None.
  """
  try:
    decoded_string = data[start : start + length].decode(
        encoding, errors="ignore"
    )
    return decoded_string if len(decoded_string) >= min_length else None
  except (UnicodeDecodeError, ValueError):
    return None


def _decode_protocol0_string(
    raw_bytes: bytes, *, min_length: int = 2
) -> str | None:
  """Decodes a Protocol 0 `STRING` (`0x53`) operand with escape sequences.

  Strips trailing carriage returns and surrounding single or double quotes,
  unescapes backslash sequences via `codecs.escape_decode`, and decodes the
  resulting bytes as UTF-8 (falling back to Latin-1).

  Args:
    raw_bytes: Raw newline-stripped operand bytes following a `STRING` opcode.
    min_length: Minimum decoded character length required to return a string.

  Returns:
    The decoded string if its length is at least `min_length`, or None
    otherwise.
  """
  if raw_bytes.endswith(b"\r"):
    raw_bytes = raw_bytes[:-1]

  if (
      len(raw_bytes) >= 2
      and raw_bytes[0] == raw_bytes[-1]
      and raw_bytes[0] in (0x27, 0x22)
  ):
    raw_bytes = raw_bytes[1:-1]

  if b"\\" in raw_bytes:
    try:
      raw_bytes = codecs.escape_decode(raw_bytes)[0]  # pyrefly: ignore[bad-assignment]
    except (ValueError, UnicodeDecodeError):
      pass

  try:
    decoded_string = raw_bytes.decode("utf-8")
  except UnicodeDecodeError:
    decoded_string = raw_bytes.decode("latin1", errors="ignore")

  return decoded_string if len(decoded_string) >= min_length else None


def _read_length_span(
    data: bytes | mmap.mmap,
    pos: int,
    total_length: int,
    header_size: int,
) -> tuple[int, int]:
  """Returns (length, next_pos) for a length-prefixed opcode or raises error."""
  payload_start = pos + header_size
  if payload_start > total_length:
    raise exceptions.UnsafePickleDetectedError(
        f"Parser error during security scan: truncated argument at offset {pos}"
    )
  payload_length = (
      data[pos + 1]
      if header_size == 2
      else int.from_bytes(data[pos + 1 : payload_start], "little")
  )
  next_offset = payload_start + payload_length
  if next_offset > total_length:
    raise exceptions.UnsafePickleDetectedError(
        f"Parser error during security scan: truncated argument at offset {pos}"
    )
  return payload_length, next_offset


def _read_newline(
    data: bytes | mmap.mmap,
    start: int,
    error_offset: int,
) -> int:
  """Returns index of next newline at or after start offset, or raises error."""
  newline_offset = data.find(b"\n", start)
  if newline_offset == -1:
    raise exceptions.UnsafePickleDetectedError(
        "Parser error during security scan: truncated newline at offset"
        f" {error_offset}"
    )
  return newline_offset


MAX_ABSTRACT_STACK_SIZE = 65536


def is_benign_storage_arg(argument_value: str) -> bool:
  """Checks whether a string token in a PyTorch `storage` tuple is benign.

  Verifies that `argument_value` is not a dangerous literal and is either a
  numeric storage key/size, a standard PyTorch device identifier (`'cpu'`,
  `'cuda'`, `'mps'`, etc.), or a symbol classified as `SAFE`.

  Args:
    argument_value: String element from a PyTorch `('storage', ...)` persistent
      ID tuple.

  Returns:
    True if `argument_value` is a safe PyTorch storage parameter, or False
    otherwise.
  """
  if is_potentially_dangerous_literal(argument_value):
    return False

  if (
      argument_value.isdigit()
      or argument_value in (
          "cpu",
          "cuda",
          "mps",
          "meta",
          "xpu",
          "hpu",
          "xla",
          "disk",
      )
      or argument_value.startswith(("cuda:", "xpu:", "hpu:", "mps:", "xla:"))
  ):
    return True

  return classify_symbol(argument_value) == Classification.SAFE


def _collapse_tuple_items(
    tuple_items: Sequence[Optional[str]],
) -> Optional[str]:
  """Collapses popped tuple elements into a summary token for `BINPERSID`.

  Inspects tuples beginning with `'storage'` (PyTorch persistent storage IDs)
  and returns the first non-benign element if one exists, or
  `'__pytorch_storage__'` if all elements are benign.

  Args:
    tuple_items: Sequence of abstract stack tokens popped for a tuple opcode.

  Returns:
    The first suspicious/unsafe element string from a `'storage'` tuple,
    `'__pytorch_storage__'` if all elements are benign, or None for
    non-storage tuples.
  """
  if not tuple_items or tuple_items[0] != "storage":
    return None
  for tuple_element in tuple_items[1:]:
    if tuple_element is not None and not is_benign_storage_arg(tuple_element):
      return tuple_element
  return "__pytorch_storage__"


def _advance_past_stop_opcode(
    data: bytes | mmap.mmap,
    pos: int,
    end: int,
) -> Optional[int]:
  """Advances past a STOP opcode and checks for a concatenated pickle stream.

  Skips NUL bytes and ASCII whitespace following a `STOP` (`0x2E`) opcode and
  verifies whether the remaining bytes begin another valid pickle stream.

  Args:
    data: The full pickle buffer or memory-mapped file.
    pos: Current byte offset immediately following the `0x2E` byte.
    end: Exclusive end byte offset of the slice being scanned.

  Returns:
    The next byte offset to resume scanning if a valid concatenated pickle
    stream follows, or None if scanning should stop.
  """
  while pos < end and data[pos] in (0x00, 0x0A, 0x0D, 0x20):
    pos += 1
  if pos < end and is_pickle_file(bytes(data[pos : min(end, pos + 1024)])):
    return pos
  return None


def _resolve_ext_opcode(
    data: bytes | mmap.mmap,
    current_offset: int,
    opcode_byte: int,
) -> str:
  """Resolves the registered symbol for an EXT1, EXT2, or EXT4 opcode.

  Reads the 1-, 2-, or 4-byte extension code operand following `opcode_byte`
  at `current_offset` and resolves its registered `'module.name'` via
  `resolve_extension_code`.

  Args:
    data: The pickle byte buffer or memory-mapped file.
    current_offset: Byte offset of the `0x82`, `0x83`, or `0x84` opcode byte.
    opcode_byte: The opcode byte (`0x82`, `0x83`, or `0x84`).

  Returns:
    The resolved `'module.name'` string, or
    `'unregistered_extension.code_<code>'` if unregistered.
  """
  stride = OPCODE_STRIDES[opcode_byte]
  ext_code = int.from_bytes(
      data[current_offset + 1 : current_offset + stride],
      "little",
      signed=(opcode_byte == 0x84),
  )
  return resolve_extension_code(ext_code)


def _decode_protocol0_text_opcode(
    data: bytes | mmap.mmap,
    current_offset: int,
    newline_offset: int,
    opcode_byte: int,
) -> Optional[str]:
  r"""Decodes a Protocol 0 STRING (`0x53`) or UNICODE (`0x56`) opcode operand.

  Skips binary Protocol 0 byte strings containing escaped NUL bytes and
  decodes up to 4096 bytes of the newline-delimited operand.

  Args:
    data: The pickle byte buffer or memory-mapped file.
    current_offset: Byte offset of the `0x53` or `0x56` opcode byte.
    newline_offset: Byte offset of the terminating newline (`\n`).
    opcode_byte: Either `0x53` (`STRING`) or `0x56` (`UNICODE`).

  Returns:
    The decoded string operand if non-empty and non-binary, or None otherwise.
  """
  span_length = newline_offset - current_offset - 1
  is_binary_protocol0_string = (
      opcode_byte == 0x53
      and span_length > 256
      and b"\\x00" in data[
          current_offset + 1 : min(newline_offset, current_offset + 65)
      ]
  )
  if is_binary_protocol0_string:
    return None

  decode_length = min(span_length, 4096)
  raw_slice = bytes(
      data[current_offset + 1 : current_offset + 1 + decode_length]
  )
  if opcode_byte == 0x56:
    cleaned_slice = raw_slice.rstrip(b"\r")
    return decode_string_operand(
        cleaned_slice,
        0,
        len(cleaned_slice),
        "raw-unicode-escape",
        min_length=1,
    )
  return _decode_protocol0_string(raw_slice, min_length=1)


def _parse_protocol0_memo_index(
    data: bytes | mmap.mmap,
    current_offset: int,
    newline_offset: int,
) -> Optional[int]:
  r"""Parses a newline-terminated integer memo key for PUT or GET opcodes.

  Extracts the line between `current_offset + 1` and `newline_offset`, strips
  embedded NUL bytes and trailing carriage returns, and parses the integer
  memo index using base-0 integer literal rules.

  Args:
    data: The pickle byte buffer or memory-mapped file.
    current_offset: Byte offset of the `0x70` or `0x67` opcode byte.
    newline_offset: Byte offset of the terminating newline (`\n`).

  Returns:
    The parsed integer memo key, or None if the line is not a valid integer.
  """
  try:
    return int(
        _clean_protocol0_line(data[current_offset + 1 : newline_offset]), 0
    )
  except ValueError:
    return None


def _apply_fixed_opcode_stack_effect(
    opcode_byte: int,
    data: bytes | mmap.mmap,
    current_offset: int,
    value_stack: list[Optional[str]],
    mark_stack: list[int],
    memo_table: dict[int, Optional[str]],
) -> None:
  """Updates value_stack, mark_stack, and memo_table for fixed-stride opcodes."""
  match opcode_byte:
    case 0x28:  # MARK
      mark_stack.append(len(value_stack))

    case 0x30 | 0x61 | 0x62:  # POP, APPEND, BUILD
      if value_stack:
        value_stack.pop()

    case 0x73:  # SETITEM
      for _ in range(2):
        if value_stack:
          value_stack.pop()

    case 0x31 | 0x65 | 0x75 | 0x90:  # POP_MARK, APPENDS, SETITEMS, ADDITEMS
      if mark_stack:
        mark_position = mark_stack.pop()
        del value_stack[mark_position:]
      else:
        value_stack.clear()

    case 0x74:  # TUPLE
      if mark_stack:
        mark_position = mark_stack.pop()
        popped_items = value_stack[mark_position:]
        del value_stack[mark_position:]
      else:
        popped_items = list(value_stack)
        value_stack.clear()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(_collapse_tuple_items(popped_items))

    case 0x64 | 0x69 | 0x6C | 0x6F | 0x91:
      # DICT, INST, LIST, OBJ, FROZENSET
      if mark_stack:
        mark_position = mark_stack.pop()
        del value_stack[mark_position:]
      else:
        value_stack.clear()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case 0x32:  # DUP
      if value_stack and len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(value_stack[-1])

    case 0x94:  # MEMOIZE
      memo_table[len(memo_table)] = value_stack[-1] if value_stack else None

    case 0x71:  # BINPUT
      memo_key = data[current_offset + 1]
      memo_table[memo_key] = value_stack[-1] if value_stack else None

    case 0x72:  # LONG_BINPUT
      memo_key = int.from_bytes(
          data[current_offset + 1 : current_offset + 5], "little"
      )
      memo_table[memo_key] = value_stack[-1] if value_stack else None

    case 0x68:  # BINGET
      memo_key = data[current_offset + 1]
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(memo_table.get(memo_key))

    case 0x6A:  # LONG_BINGET
      memo_key = int.from_bytes(
          data[current_offset + 1 : current_offset + 5], "little"
      )
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(memo_table.get(memo_key))

    case 0x82 | 0x83 | 0x84:  # EXT1, EXT2, EXT4
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(
            _resolve_ext_opcode(data, current_offset, opcode_byte)
        )

    case 0x85 | 0x86 | 0x87:  # TUPLE1, TUPLE2, TUPLE3
      tuple_arity = opcode_byte - 0x84
      popped_items: list[Optional[str]] = []
      for _ in range(tuple_arity):
        if value_stack:
          popped_items.append(value_stack.pop())
      popped_items.reverse()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(_collapse_tuple_items(popped_items))

    case 0x51 | 0x98:  # BINPERSID, READONLY_BUFFER
      if value_stack:
        value_stack.pop()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case 0x52 | 0x81:  # REDUCE, NEWOBJ
      for _ in range(2):
        if value_stack:
          value_stack.pop()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case 0x92:  # NEWOBJ_EX
      for _ in range(3):
        if value_stack:
          value_stack.pop()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case (
        0x29  # EMPTY_TUPLE
        | 0x4E  # NONE
        | 0x5D  # EMPTY_LIST
        | 0x7D  # EMPTY_DICT
        | 0x88  # NEWTRUE
        | 0x89  # NEWFALSE
        | 0x8F  # EMPTY_SET
        | 0x4B  # BININT1
        | 0x4D  # BININT2
        | 0x4A  # BININT
        | 0x47  # BINFLOAT
        | 0x8A  # LONG1
        | 0x8B  # LONG4
        | 0x43  # SHORT_BINBYTES
        | 0x42  # BINBYTES
        | 0x8E  # BINBYTES8
        | 0x96  # BYTEARRAY8
        | 0x97  # NEXT_BUFFER
        | 0x49  # INT
        | 0x4C  # LONG
        | 0x46  # FLOAT
    ):
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)


def partition_pickle_chunks(
    data: bytes | mmap.mmap,
    target_chunk_size: int,
    end: int | None = None,
    *,
    include_memo: bool = False,
) -> list[Any]:
  """Partitions pickle bytes into opcode-aligned chunk slices with seed state.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    target_chunk_size: Desired byte size for each worker partition chunk.
    end: Optional upper byte bound limiting the scan range.
    include_memo: Whether to include a memo_table snapshot in each chunk tuple.

  Returns:
    A list of 3-tuples (chunk_start, chunk_end, seed_stack) or 4-tuples
    (chunk_start, chunk_end, seed_stack, seed_memo) when include_memo is True.
  """
  effective_length = len(data) if end is None else min(end, len(data))
  chunk_starts = [0]
  seed_stacks: list[list[Optional[str]]] = [[]]
  seed_memos: list[dict[int, Optional[str]]] = [{}]
  value_stack: list[Optional[str]] = []
  mark_stack: list[int] = []
  memo_table: dict[int, Optional[str]] = {}
  current_offset = 0
  strides = OPCODE_STRIDES

  while current_offset < effective_length:
    opcode_byte = data[current_offset]
    stride = strides[opcode_byte]
    if stride > 0:
      if current_offset + stride > effective_length:
        break
      if opcode_byte == 0x2E:
        value_stack.clear()
        mark_stack.clear()
        memo_table.clear()
        next_pos = _advance_past_stop_opcode(
            data, current_offset + 1, effective_length
        )
        if next_pos is None:
          break
        current_offset = next_pos
        continue
      _apply_fixed_opcode_stack_effect(
          opcode_byte,
          data,
          current_offset,
          value_stack,
          mark_stack,
          memo_table,
      )
      current_offset += stride
    else:
      match opcode_byte:
        # 1-byte, 4-byte, or 8-byte length-prefixed string opcodes
        case 0x8C | 0x55 | 0x58 | 0x54 | 0x8D:
          if opcode_byte in (0x8C, 0x55):
            header_size = 2
          elif opcode_byte in (0x58, 0x54):
            header_size = 5
          else:
            header_size = 9
          if current_offset + header_size > effective_length:
            break
          if header_size == 2:
            operand_length = data[current_offset + 1]
          else:
            operand_length = int.from_bytes(
                data[current_offset + 1 : current_offset + header_size],
                "little",
            )
          next_offset = current_offset + header_size + operand_length
          if next_offset > effective_length:
            break
          encoding = "latin1" if opcode_byte in (0x55, 0x54) else "utf-8"
          decode_length = min(operand_length, 4096)
          decoded_value = decode_string_operand(
              data,
              current_offset + header_size,
              decode_length,
              encoding,
              min_length=1,
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(decoded_value)
          current_offset = next_offset

        # 1-byte length prefix non-string bytes to skip (SHORT_BINBYTES, LONG1)
        case 0x43 | 0x8A:
          if current_offset + 2 > effective_length:
            break
          current_offset += 2 + data[current_offset + 1]
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)

        # 4-byte or 8-byte length prefix non-string bytes to skip
        case 0x42 | 0x8B | 0x8E | 0x96:
          header_size = 5 if opcode_byte in (0x42, 0x8B) else 9
          if current_offset + header_size > effective_length:
            break
          current_offset += header_size + int.from_bytes(
              data[current_offset + 1 : current_offset + header_size], "little"
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)

        # Newline-terminated string opcodes (UNICODE, STRING)
        case 0x56 | 0x53:
          if (newline_offset := data.find(b"\n", current_offset + 1)) == -1:
            break
          decoded_value = _decode_protocol0_text_opcode(
              data, current_offset, newline_offset, opcode_byte
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(decoded_value)
          current_offset = newline_offset + 1

        # Protocol 0 PUT
        case 0x70:
          if (newline_offset := data.find(b"\n", current_offset + 1)) == -1:
            break
          memo_key = _parse_protocol0_memo_index(
              data, current_offset, newline_offset
          )
          if memo_key is not None:
            memo_table[memo_key] = value_stack[-1] if value_stack else None
          current_offset = newline_offset + 1

        # Protocol 0 GET
        case 0x67:
          if (newline_offset := data.find(b"\n", current_offset + 1)) == -1:
            break
          memo_key = _parse_protocol0_memo_index(
              data, current_offset, newline_offset
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(
                memo_table.get(memo_key) if memo_key is not None else None
            )
          current_offset = newline_offset + 1

        # Other newline-terminated opcodes (INT, FLOAT, LONG, PERSID)
        case 0x49 | 0x46 | 0x4C | 0x50:
          if (newline_offset := data.find(b"\n", current_offset + 1)) == -1:
            break
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)
          current_offset = newline_offset + 1

        # Two newline-terminated strings for module and attribute (GLOBAL, INST)
        case 0x63 | 0x69:
          if (first_newline := data.find(b"\n", current_offset + 1)) == -1 or (
              second_newline := data.find(b"\n", first_newline + 1)
          ) == -1:
            break
          if opcode_byte == 0x69:
            if mark_stack:
              mark_position = mark_stack.pop()
              del value_stack[mark_position:]
            else:
              value_stack.clear()
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)
          current_offset = second_newline + 1

        # STACK_GLOBAL
        case 0x93:
          for _ in range(2):
            if value_stack:
              value_stack.pop()
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)
          current_offset += 1

        # Unrecognized or single-byte variable opcode fallback
        case _:
          _apply_fixed_opcode_stack_effect(
              opcode_byte,
              data,
              current_offset,
              value_stack,
              mark_stack,
              memo_table,
          )
          current_offset += 1

    if (
        current_offset - chunk_starts[-1] >= target_chunk_size
        and current_offset < effective_length
    ):
      chunk_starts.append(current_offset)
      if include_memo:
        seed_stacks.append(list(value_stack[-64:]))
        seed_memos.append(dict(memo_table))
      else:
        non_null_strings: list[Optional[str]] = [
            stack_item for stack_item in value_stack if stack_item is not None
        ]
        seed_stacks.append(non_null_strings[-16:])

  chunk_partitions = []
  for chunk_index, chunk_start in enumerate(chunk_starts):
    chunk_end = (
        chunk_starts[chunk_index + 1]
        if chunk_index + 1 < len(chunk_starts)
        else effective_length
    )
    if include_memo:
      chunk_partitions.append((
          chunk_start,
          chunk_end,
          seed_stacks[chunk_index],
          seed_memos[chunk_index],
      ))
    else:
      chunk_partitions.append(
          (chunk_start, chunk_end, seed_stacks[chunk_index])
      )

  return chunk_partitions


def custom_genops_from_bytes(
    data: bytes | mmap.mmap,
    start: int = 0,
    end: int | None = None,
    seed_stack: Sequence[Optional[str]] = (),
    seed_memo: Optional[Mapping[int, Optional[str]]] = None,
) -> Iterator[tuple[Optional[pickletools.OpcodeInfo], Any | None]]:
  """Generates string-declaring opcodes and arguments from raw pickle bytes.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    start: Byte offset to start parsing from.
    end: Optional byte offset upper limit for parsing.
    seed_stack: Initial string operands to populate the stack context.
    seed_memo: Initial memo table mapping memo keys to string operands.

  Yields:
    A tuple of (opcode_info, operand_value) for each string-declaring opcode.

  Raises:
    exceptions.UnsafePickleDetectedError: If a length-prefixed opcode is
      truncated.
  """
  total_length = len(data)
  limit_offset = total_length if end is None else min(end, total_length)
  current_offset = start
  strides = OPCODE_STRIDES
  memo_table: dict[int, Optional[str]] = dict(seed_memo) if seed_memo else {}
  value_stack: list[Optional[str]] = list(seed_stack) if seed_stack else []
  mark_stack: list[int] = []

  while current_offset < limit_offset:
    opcode_byte = data[current_offset]
    stride = strides[opcode_byte]
    if stride > 0:
      if current_offset + stride > limit_offset:
        raise exceptions.UnsafePickleDetectedError(
            "Parser error during security scan: truncated argument at offset"
            f" {current_offset}"
        )
      if opcode_byte == 0x2E:
        value_stack.clear()
        mark_stack.clear()
        memo_table.clear()
        next_pos = _advance_past_stop_opcode(
            data, current_offset + 1, limit_offset
        )
        if next_pos is None:
          break
        current_offset = next_pos
        continue
      # EXT1, EXT2, EXT4 have fixed strides (2, 3, 5) in OPCODE_STRIDES
      if opcode_byte in (0x82, 0x83, 0x84):
        resolved_ext = _resolve_ext_opcode(data, current_offset, opcode_byte)
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(resolved_ext)
        yield constants.OPCODES_INFO_INT.get(opcode_byte), resolved_ext
        current_offset += stride
        continue
      _apply_fixed_opcode_stack_effect(
          opcode_byte,
          data,
          current_offset,
          value_stack,
          mark_stack,
          memo_table,
      )
      current_offset += stride
      continue

    match opcode_byte:
      # 1-byte, 4-byte, or 8-byte length-prefixed Unicode/ASCII text strings
      case 0x8C | 0x55 | 0x58 | 0x54 | 0x8D:
        header_size = (
            2
            if opcode_byte in (0x8C, 0x55)
            else (5 if opcode_byte in (0x58, 0x54) else 9)
        )
        payload_length, current_offset = _read_length_span(
            data, current_offset, limit_offset, header_size
        )
        encoding = "latin1" if opcode_byte in (0x55, 0x54) else "utf-8"
        decode_length = min(payload_length, 4096)
        string_value = decode_string_operand(
            data,
            current_offset - payload_length,
            decode_length,
            encoding,
            min_length=1,
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(string_value)
        if string_value is not None and len(string_value) >= 2:
          yield constants.OPCODES_INFO_INT.get(opcode_byte), string_value

      # Fast inline skip for 1-byte binary payloads (SHORT_BINBYTES, LONG1)
      case 0x43 | 0x8A:
        payload_start = current_offset + 2
        if (
            payload_start > limit_offset
            or payload_start + data[current_offset + 1] > limit_offset
        ):
          raise exceptions.UnsafePickleDetectedError(
              "Parser error during security scan: truncated argument at offset"
              f" {current_offset}"
          )
        current_offset = payload_start + data[current_offset + 1]
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)

      # Non-string 4-byte/8-byte binary byte buffers and bytearrays to skip
      case 0x42 | 0x8B | 0x8E | 0x96:
        header_size = 5 if opcode_byte in (0x42, 0x8B) else 9
        _, current_offset = _read_length_span(
            data, current_offset, limit_offset, header_size
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)

      # Newline-terminated string literals (Protocol 0 UNICODE / STRING)
      case 0x56 | 0x53:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        string_value = _decode_protocol0_text_opcode(
            data, current_offset, newline_offset, opcode_byte
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(string_value)
        if string_value is not None and len(string_value) >= 2:
          yield constants.OPCODES_INFO_INT.get(opcode_byte), string_value
        current_offset = newline_offset + 1

      # Two newline-terminated strings for module and attribute (GLOBAL, INST)
      case 0x63 | 0x69:
        module_newline = _read_newline(data, current_offset + 1, current_offset)
        name_newline = _read_newline(data, module_newline + 1, current_offset)
        module_name = _clean_protocol0_line(
            data[current_offset + 1 : module_newline]
        ).decode("utf-8", errors="ignore")
        attribute_name = _clean_protocol0_line(
            data[module_newline + 1 : name_newline]
        ).decode("utf-8", errors="ignore")
        if opcode_byte == 0x69:
          if mark_stack:
            mark_position = mark_stack.pop()
            del value_stack[mark_position:]
          else:
            value_stack.clear()
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        qualified_name = f"{module_name}.{attribute_name}"
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(qualified_name if opcode_byte == 0x63 else None)
        yield opcode_info, qualified_name
        current_offset = name_newline + 1

      # Stack global resolution opcode referencing stack operands
      case 0x93:
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        attribute_member = value_stack.pop() if value_stack else None
        module_member = value_stack.pop() if value_stack else None
        if isinstance(module_member, str) and isinstance(attribute_member, str):
          qualified_name = f"{module_member}.{attribute_member}"
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(qualified_name)
          yield opcode_info, qualified_name
        else:
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)
          yield opcode_info, "STACK_GLOBAL"
        current_offset += 1

      # Protocol 0 PUT (newline-terminated decimal memo index)
      case 0x70:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        memo_key = _parse_protocol0_memo_index(
            data, current_offset, newline_offset
        )
        if memo_key is not None:
          memo_table[memo_key] = value_stack[-1] if value_stack else None
        current_offset = newline_offset + 1

      # Protocol 0 GET (newline-terminated decimal memo index)
      case 0x67:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        memo_key = _parse_protocol0_memo_index(
            data, current_offset, newline_offset
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(
              memo_table.get(memo_key) if memo_key is not None else None
          )
        current_offset = newline_offset + 1

      # Protocol 0 PERSID (newline-terminated persistent ID string)
      case 0x50:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        pid_string = _clean_protocol0_line(
            data[current_offset + 1 : newline_offset]
        ).decode("utf-8", errors="ignore")
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)
        if pid_string:
          if is_potentially_dangerous_literal(pid_string):
            yield opcode_info, pid_string
          else:
            yield opcode_info, f"persistent_id.{pid_string}"
        else:
          yield opcode_info, "persistent_id.PERSID"
        current_offset = newline_offset + 1

      # BINPERSID (persistent ID popped from stack)
      case 0x51:
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        pid_string = value_stack.pop() if value_stack else None
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)
        if pid_string == "__pytorch_storage__":
          pass
        elif pid_string:
          if is_potentially_dangerous_literal(pid_string):
            yield opcode_info, pid_string
          else:
            yield opcode_info, f"persistent_id.{pid_string}"
        else:
          yield opcode_info, "persistent_id.BINPERSID"
        current_offset += 1

      # Newline-terminated numeric arguments to skip (INT, FLOAT, LONG)
      case 0x49 | 0x46 | 0x4C:
        current_offset = (
            _read_newline(data, current_offset + 1, current_offset) + 1
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)

      # Unrecognized or variable-stride single-byte opcode (REDUCE, BUILD, etc.)
      case _:
        _apply_fixed_opcode_stack_effect(
            opcode_byte,
            data,
            current_offset,
            value_stack,
            mark_stack,
            memo_table,
        )
        current_offset += 1

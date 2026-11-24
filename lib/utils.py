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
import collections
import dataclasses
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
import subprocess
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
    Iterable,
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


PICKLEMAGIC_PATTERNS = [
    (
        "FakeWarning.__new__",
        re.compile(
            r"FakeWarning\.__new__ called on <class '(?P<class_name>.*?)'> with"
            r" args=(?P<args>.*), kwargs=(?P<kwargs>.*)"
        ),
        False,
    ),
    (
        "FakeWarning.__setstate__",
        re.compile(
            r"FakeWarning\.__setstate__ called on <class '(?P<class_name>.*?)'>"
            r" with unexpected state=(?P<state>.*)"
        ),
        True,
    ),
    (
        "FakeClass.__getattr__",
        re.compile(
            r"FakeClass\.__getattr__ called on <class '(?P<class_name>.*?)'>"
            r" with name=(?P<attr_name>.*)"
        ),
        False,
    ),
    (
        "FakeClass method",
        re.compile(
            r"FakeClass method (?P<method_name>.*?) called on <class"
            r" '(?P<class_name>.*?)'> with args=(?P<args>.*),"
            r" kwargs=(?P<kwargs>.*)"
        ),
        False,
    ),
    (
        "FakeClass.__call__",
        re.compile(
            r"FakeClass\.__call__ called on <class '(?P<class_name>.*?)'> with"
            r" args=(?P<args>.*), kwargs=(?P<kwargs>.*)"
        ),
        False,
    ),
    (
        "FakeModule.__getattr__",
        re.compile(
            r"FakeModule\.__getattr__ called on (?P<module_name>.*?) with"
            r" name=(?P<attr_name>.*)"
        ),
        False,
    ),
    (
        "Failed to ",
        re.compile(
            r"Failed to (?:reduce|set state|newobj|newobj_ex|instantiate)"
            r" <class '(?P<class_name>.*?)'> with (?P<args>.*?):"
        ),
        False,
    ),
]

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
          "I/O error during import of %s, but module is in sys.modules",
          original_name,
      )
      original_module = sys.modules[original_name]
    else:
      logging.debug(
          "Failed to import module %s due to I/O error and module not in"
          " sys.modules",
          original_name,
      )
      return None

  new_module = types.ModuleType(new_name)
  new_module.__dict__.update(original_module.__dict__)
  new_module.__name__ = new_name
  if hasattr(original_module, "__file__"):
    new_module.__file__ = f"{new_name}.py"
  sys.modules[new_name] = new_module

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
        # Fallback to pickle copy. Optional libraries such as torch are often
        # not linked into the binary, so only warn if the module is installed.
        try:
          spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
          spec = None
        log_fn = logging.debug if spec is None else logging.warning
        log_fn(
            "%s could not be imported/copied, falling back to pickle_copy", name
        )
        if "_pickle" not in _COPIED_MODS_CACHE:
          _ = get_copied_module("_pickle")
        mod_copied = _COPIED_MODS_CACHE["_pickle"]

      _COPIED_MODS_CACHE[name] = mod_copied

    return mod_copied


def _peek_bytes(file_bytes: bytes | BinaryIO, size: int) -> bytes:
  """Peeks at the first `size` bytes of a bytes object or file stream."""
  if isinstance(file_bytes, bytes):
    return file_bytes[:size]

  try:
    is_seekable = file_bytes.seekable()
  except (AttributeError, ValueError):
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
      return file_bytes.peek(size)[:size]
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
  return _peek_bytes(file_bytes, 4).startswith(
      (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
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
    for name in zf.namelist():
      with zf.open(name) as f:
        yield name, f


def is_bz2_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a bz2 file."""
  return _peek_bytes(file_bytes, 3).startswith(b"\x42\x5a\x68")


def extract_bz2_contents(file_bytes: bytes | BinaryIO) -> IO[bytes]:
  """Extracts contents from bz2 bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return bz2.open(stream)


def is_lzma_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent an lzma file."""
  return _peek_bytes(file_bytes, 6).startswith(b"\xfd\x37\x7a\x58\x5a\x00")


def extract_lzma_contents(file_bytes: bytes | BinaryIO) -> IO[bytes]:
  """Extracts contents from lzma bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return lzma.open(stream)


def is_gzip_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a gzip file."""
  return _peek_bytes(file_bytes, 2).startswith(b"\x1f\x8b")


def extract_gzip_contents(file_bytes: bytes | IO[bytes]) -> IO[bytes]:
  """Extracts contents from gzip bytes/stream as a stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  return cast(IO[bytes], gzip.open(stream))


def is_tar_bytes(file_bytes: bytes | BinaryIO) -> bool:
  """Checks if the provided bytes represent a tar file."""
  peeked = _peek_bytes(file_bytes, 262)
  return len(peeked) >= 262 and peeked[257:262] == b"ustar"


def extract_tar_contents(
    file_bytes: bytes | BinaryIO,
) -> Generator[Tuple[str, IO[bytes]], None, None]:
  """Extracts contents from tar bytes/stream."""
  stream = (
      io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
  )
  with tarfile.open(fileobj=stream, mode="r:*") as tf:
    for member in tf.getmembers():
      if member.isfile():
        f = tf.extractfile(member)
        if f is not None:
          yield member.name, cast(IO[bytes], f)


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
      # Read a chunk to check text-based and non-pickle-magic prefixes safely
      raw_bytes = pickle_bytes.read(1024)
      pickle_bytes.seek(original_pos)  # pyrefly: ignore[bad-argument-type]
      pickle_stream = pickle_bytes
    else:
      # Fallback for non-seekable stream: try to peek without advancing pointer
      if hasattr(pickle_bytes, "peek"):
        try:
          raw_bytes = pickle_bytes.peek(1024)
          pickle_stream = pickle_bytes
        except (OSError, io.UnsupportedOperation):
          raw_bytes = pickle_bytes.read(1024)
          pickle_stream = io.BytesIO(raw_bytes)
      else:
        raw_bytes = pickle_bytes.read(1024)
        pickle_stream = io.BytesIO(raw_bytes)

  if raw_bytes:
    first_byte = raw_bytes[0]
    if first_byte not in constants.OPCODES_INFO_INT:
      if return_num_bytes_read:
        return (False, 0)
      return False

  if check_magic_bytes:
    pickle_file_is_ascii = raw_bytes.isascii()

    if pickle_file_is_ascii:
      stripped_bytes = raw_bytes.lstrip()
      if stripped_bytes.startswith(
          constants.TEXT_BASED_PREFIXES
      ) or stripped_bytes.startswith(constants.CODE_KEYWORDS):
        if return_num_bytes_read:
          return (False, 0)
        return False

    if raw_bytes.startswith(constants.NON_PICKLE_MAGIC_BYTES):
      if raw_bytes[0] not in constants.OPCODES_INFO_INT:
        if return_num_bytes_read:
          return (False, 0)
        return False

  valid_opcodes_count = 0
  try:
    while True:
      charcode = pickle_stream.read(1)
      if not charcode:  # EOF reached without STOP
        is_suspected_pickle = valid_opcodes_count >= 3
        if return_num_bytes_read:
          return (is_suspected_pickle, valid_opcodes_count)
        return is_suspected_pickle

      decoded_char = charcode.decode("latin-1")
      if decoded_char == ".":  # STOP opcode found
        valid_opcodes_count += 1
        if return_num_bytes_read:
          return (True, valid_opcodes_count)
        return True

      opcode = constants.OPCODES_INFO.get(decoded_char)
      if opcode is None:  # Invalid opcode before STOP
        is_suspected_pickle = valid_opcodes_count >= 3
        if return_num_bytes_read:
          return (is_suspected_pickle, valid_opcodes_count)
        return is_suspected_pickle

      valid_opcodes_count += 1
      if valid_opcodes_count > constants.MAX_BYTES_TO_CHECK:
        if return_num_bytes_read:
          return (True, valid_opcodes_count)
        return True

      if opcode.arg is None:
        continue

      if opcode.name in constants.PAYLOAD_PREFIX_SIZES and hasattr(
          pickle_stream, "seek"
      ):
        prefix_size = constants.PAYLOAD_PREFIX_SIZES[opcode.name]
        len_bytes = pickle_stream.read(prefix_size)
        if len(len_bytes) != prefix_size:
          is_suspected_pickle = valid_opcodes_count >= 3
          return (
              (is_suspected_pickle, valid_opcodes_count)
              if return_num_bytes_read
              else is_suspected_pickle
          )

        payload_len = int.from_bytes(len_bytes, "little")
        cur_pos = pickle_stream.tell()
        stream_end_pos = pickle_stream.seek(0, io.SEEK_END)
        if cur_pos + payload_len > stream_end_pos:
          is_suspected_pickle = valid_opcodes_count >= 3
          return (
              (is_suspected_pickle, valid_opcodes_count)
              if return_num_bytes_read
              else is_suspected_pickle
          )

        pickle_stream.seek(cur_pos + payload_len)
        continue

      try:
        _ = opcode.arg.reader(pickle_stream)
      except ValueError:
        is_suspected_pickle = valid_opcodes_count >= 3
        if return_num_bytes_read:
          return (is_suspected_pickle, valid_opcodes_count)
        return is_suspected_pickle
  finally:
    if original_pos is not None:
      pickle_stream.seek(original_pos)


def find_pickle_start_offset(pickle_bytes: bytes | IO[bytes]) -> int:
  """Finds the start offset of a valid pickle payload in the bytes."""
  if isinstance(pickle_bytes, bytes):
    max_search_len = min(len(pickle_bytes), 1024)
    for offset in range(max_search_len):
      char = pickle_bytes[offset : offset + 1]
      if not char:
        break
      try:
        decoded_char = char.decode("latin-1")
      except UnicodeDecodeError:
        continue
      if decoded_char not in constants.OPCODES_INFO:
        continue
      if is_pickle_file(pickle_bytes[offset:]):
        return offset
    return 0

  # It is a stream
  stream = pickle_bytes
  try:
    original_pos = stream.tell()
    # Read 1024 bytes to find candidates
    header_bytes = stream.read(1024)
    stream.seek(original_pos)
  except (OSError, AttributeError, io.UnsupportedOperation):
    return 0

  max_search_len = len(header_bytes)
  for offset in range(max_search_len):
    char = header_bytes[offset : offset + 1]
    if not char:
      break
    try:
      decoded_char = char.decode("latin-1")
    except UnicodeDecodeError:
      continue
    if decoded_char not in constants.OPCODES_INFO:
      continue

    # Verify candidate offset using the stream
    try:
      stream.seek(original_pos + offset)
      if is_pickle_file(stream):
        return offset
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass
    finally:
      try:
        stream.seek(original_pos)
      except (OSError, AttributeError, io.UnsupportedOperation):
        pass  # If we can't seek back, it poses an issue

  return 0


@functools.lru_cache(maxsize=None)
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

  if (spec := importlib.util.find_spec(module_name)) is None:
    return None
  if (origin := spec.origin) is None:
    return None

  try:
    with open(origin, "r") as f:
      tree = ast.parse(f.read(), filename=origin)
  except (IOError, ValueError, SyntaxError, RecursionError):
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

  Matches exact entries, `<entry>.` submodule prefixes, and optional
  `.<symbol>` suffixes in `prefixes`.

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
    if (
        symbol == item
        or symbol.startswith(f"{item}.")
        or (match_suffix and item.endswith(f".{symbol}"))
    ):
      return True

  return False


def _normalize_corrupy_symbol(symbol: str) -> str:
  """Normalizes open-source `third_party.corrupy` symbol paths to `corrupy`.

  Open-source exports vendor `corrupy` under `third_party.corrupy`, changing
  runtime `__module__` strings on `picklemagic` classes.

  Args:
    symbol: Raw symbol or module path string.

  Returns:
    The symbol with a leading `third_party.` prefix stripped when targeting
    `third_party.corrupy`, or `symbol` unchanged otherwise.
  """
  if symbol == "third_party.corrupy" or symbol.startswith(
      ("third_party.corrupy.", "third_party.corrupy ")
  ):
    return symbol.removeprefix("third_party.")

  return symbol


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
  normalized_symbol = _normalize_corrupy_symbol(symbol.strip())
  if (
      not normalized_symbol
      or normalized_symbol in constants.INTERNAL_SANDBOX_SAFE_SYMBOLS
  ):
    return False

  return matches_symbol_prefix_list(
      normalized_symbol, constants.SELF_PROTECTED_PREFIXES, match_suffix=True
  )


def is_unsafe_for_fail_fast(symbol: str) -> bool:
  """Checks whether a symbol is classified as `UNSAFE` for `fail_fast` scanning.

  Returns True only for non-allow-listed `Classification.UNSAFE` symbols so
  `SUSPICIOUS` operands do not halt `fail_fast` scanning early.

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
  # Items with a dot are assumed to be fully qualified already.
  # In case we run into cases such as os.path and join, this is a non-issue
  # since this is moreso for better readability than precise library-to-member
  # connections (ideal final result being os.path.join).
  # Without explicit runtime introspection, the above case is not
  # possible to resolve without risks of accidentally importing a
  # module we don't want to.
  final_results = {s for s in set_of_results if "." in s}
  candidates = set_of_results - final_results

  # Identify which of the remaining candidates are actual importable modules.
  importable_modules = {}
  for name in candidates:
    module_name = name.split(".")[0]
    if module_name == "__main__":
      continue

    # Find spec to avoid importing risky modules from a loose python file
    # like import.py or similar.
    module_spec = importlib.util.find_spec(name)
    if module_spec is not None:
      module_members = get_module_members(name)
      if module_members is not None:
        importable_modules[name] = module_members

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
        and base_library != "builtins"
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


def is_valid_python_interpreter(path: str) -> bool:
  """Checks if a given path points to a valid Python interpreter.

  Args:
    path: The path to the potential Python interpreter.

  Returns:
    True if the path is a valid and executable Python interpreter, False
    otherwise.
  """
  if not path or not os.path.exists(path):
    return False

  if "python" not in path:
    return False

  try:
    # pass is a valid python keyword to test in python -c
    subprocess.check_call(
        [path, "-c", "pass"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return True
  # If "python -c pass" doesn't work, we assume the interpreter is not valid.
  except (OSError, subprocess.CalledProcessError):
    return False


def get_interpreter_path_to_patch() -> str | None:
  """Returns a valid Python interpreter path if one can be found."""
  py_intrp_candidate = sys.argv[0]
  python_path = "/usr/bin/python3"

  if is_valid_python_interpreter(py_intrp_candidate):
    return py_intrp_candidate

  logging.warning(
      "Warning: %s (sys.argv[0]) is not a valid interpreter.",
      py_intrp_candidate,
  )
  if os.path.exists(python_path):
    return python_path

  return None


def is_sys_executable_to_path_set(path: str | None) -> bool:
  """Checks if sys.executable is set to the given path."""
  if sys.executable == path or (sys.executable and "python" in sys.executable):
    return True
  elif path:
    logging.info("Patching sys.executable to %s", path)
    sys.executable = path
    return True

  logging.warning("sys.executable is not set to a valid interpreter.")
  sys.executable = None  # pyrefly: ignore[bad-assignment]
  return False


def is_sys_executable_patched() -> bool:
  """Patches `sys.executable` if it's not set.

  This function attempts to set `sys.executable` to a valid Python interpreter
  path. It first tries `sys.argv[0]`. If that's not a valid interpreter, it
  falls back to "/usr/bin/python3". If neither is valid, `sys.executable` is
  set to None.

  Returns:
    True if `sys.executable` was successfully patched to a valid path, False
    otherwise.
  """
  if sys.executable and os.path.exists(sys.executable):
    return True

  py_interpreter_candidate = sys.argv[0]

  # If sys.executable is not set, we patch it with the interpreter path that
  # was passed to the subprocess. If the path is not valid, we patch it with an
  # empty string to indicate that it's invalid.
  if not sys.executable:
    valid_py_interpreter_path = get_interpreter_path_to_patch()

    for interpreter_path in [
        valid_py_interpreter_path,
        py_interpreter_candidate,
    ]:
      if (
          interpreter_path and os.path.exists(interpreter_path)
      ) and is_sys_executable_to_path_set(interpreter_path):
        return True

  logging.warning("Warning: sys.executable is not set to a valid interpreter.")
  return False


@functools.lru_cache(maxsize=32)
def _resolve_approved_base_classes(
    loaded_specs: tuple[str, ...],
) -> tuple[type[Any], ...]:
  """Resolves approved base classes for the given loaded module specs."""
  bases = (dict, list, tuple, set, frozenset, int, float, str, bytes, bool)
  resolved = tuple(
      cls
      for spec in loaded_specs
      if isinstance(cls := _resolve_dotted_path_in_sys_modules(spec), type)
  )
  return bases + resolved


def get_all_active_approved_base_classes() -> tuple[type[Any], ...]:
  """Resolves active approved base classes currently loaded in `sys.modules`.

  Combines safe Python builtin primitive and container types with any class
  specifications in `constants.ALL_BASE_CLASS_SPECS` whose owning modules are
  currently loaded in `sys.modules`, without importing new modules.

  Returns:
    A tuple of resolved `type` objects representing approved base classes.
  """
  loaded_specs = tuple(
      spec
      for spec in constants.ALL_BASE_CLASS_SPECS
      if spec.rsplit(".", 1)[0] in sys.modules
  )
  return _resolve_approved_base_classes(loaded_specs)


@functools.lru_cache(maxsize=256)
def _find_root_package_spec_info(
    root_package: str,
) -> tuple[bool, tuple[str, ...], str | None]:
  """Resolves and caches `find_spec` metadata for an unimported root package."""
  if not root_package or not root_package.isidentifier():
    return False, (), None

  try:
    spec = importlib.util.find_spec(root_package)
  except (ImportError, AttributeError, ValueError):
    return False, (), None

  if spec is None:
    return False, (), None

  search_locations = tuple(spec.submodule_search_locations or ())
  origin_file = (
      spec.origin
      if isinstance(spec.origin, str) and os.path.isfile(spec.origin)
      else None
  )
  return True, search_locations, origin_file


def _find_module_source_file(
    mod_path: str, *, compiled: bool = False
) -> str | None:
  """Locates a module's `.py` or extension file on disk without importing it.

  Args:
    mod_path: Dotted module path (e.g., `'torch.nn.modules.linear'`).
    compiled: Whether to search for a compiled extension instead of `.py`.

  Returns:
    The filesystem path to the module file if found on disk, or None otherwise.
  """
  parts = mod_path.split(".")
  if not mod_path or not all(part.isidentifier() for part in parts):
    return None

  suffixes = constants.EXTENSION_SUFFIXES if compiled else (".py",)
  base_dirs: tuple[str, ...] | None = None
  rel_parts: list[str] = []

  for idx in range(len(parts), 0, -1):
    loaded_mod = sys.modules.get(".".join(parts[:idx]))
    if (
        idx == len(parts)
        and isinstance(mod_file := getattr(loaded_mod, "__file__", None), str)
        and mod_file.endswith(suffixes)
        and os.path.isfile(mod_file)
    ):
      return mod_file

    if mod_paths := getattr(loaded_mod, "__path__", None):
      base_dirs = tuple(mod_paths)
      rel_parts = parts[idx:]
      break

  if base_dirs is None:
    is_installed, base_dirs, origin_file = _find_root_package_spec_info(
        parts[0]
    )
    if not is_installed:
      return None
    if len(parts) == 1 and origin_file and origin_file.endswith(suffixes):
      return origin_file
    rel_parts = parts[1:]

  for base_dir in base_dirs:
    candidate = os.path.join(base_dir, *rel_parts) if rel_parts else base_dir
    if compiled:
      exts = constants.EXTENSION_SUFFIXES if rel_parts else ()
      candidates = tuple(f"{candidate}{ext}" for ext in exts)
    elif rel_parts:
      candidates = (f"{candidate}.py", os.path.join(candidate, "__init__.py"))
    else:
      candidates = (os.path.join(candidate, "__init__.py"),)

    for path in candidates:
      if os.path.isfile(path):
        return path

  return None


def _ast_expr_to_dotted_name(
    expr: ast.AST, import_map: Mapping[str, str]
) -> str:
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


def _is_compiled_callable(obj: Any) -> bool:
  """Checks whether `obj` is a built-in C or Cython callable/descriptor."""
  if isinstance(obj, constants.COMPILED_CALLABLE_TYPES):
    return True
  obj_type = type(obj)
  if obj_type.__name__.startswith("cython_function_or_method"):
    return True
  type_root = (getattr(obj_type, "__module__", "") or "").split(".")[0]
  is_non_heap_c_type = not bool(
      getattr(obj_type, "__flags__", constants.PY_TPFLAGS_HEAPTYPE)
      & constants.PY_TPFLAGS_HEAPTYPE
  )
  return (
      is_non_heap_c_type
      and type_root in constants.APPROVED_ROOT_PACKAGES
      and type_root not in constants.RESTRICTED_APPROVED_ROOTS
  )


def _is_reconstructor_name(symbol_name: str) -> bool:
  """Checks whether `symbol_name` matches an approved reconstructor identifier."""
  symbol_lower = symbol_name.lower()
  return symbol_name in constants.APPROVED_RECONSTRUCTOR_FUNCTIONS or any(
      marker in symbol_lower for marker in constants.RECONSTRUCTOR_NAME_MARKERS
  )


def _collect_referenced_code_names(
    code_object: types.CodeType,
) -> frozenset[str]:
  """Collects `co_names` across `code_object` and nested `CodeType` constants."""
  referenced_names: set[str] = set()
  code_stack = [code_object]
  while code_stack:
    cur_code = code_stack.pop()
    referenced_names.update(cur_code.co_names)
    for const in cur_code.co_consts:
      if isinstance(const, types.CodeType):
        code_stack.append(const)

  return frozenset(referenced_names)


def _seed_bytecode_worklist(
    unwrapped: types.FunctionType,
    referenced_names: frozenset[str],
    owner_ancestors: Sequence[type[Any]],
) -> collections.deque[tuple[Any, str, Sequence[type[Any]]]]:
  """Seeds the bytecode inspection worklist from globals, closures, and MRO."""
  worklist: collections.deque[tuple[Any, str, Sequence[type[Any]]]] = (
      collections.deque()
  )
  fn_globals = getattr(unwrapped, "__globals__", None)
  for name in referenced_names:
    if isinstance(fn_globals, Mapping) and name in fn_globals:
      worklist.append((fn_globals[name], "", owner_ancestors))
    for anc in owner_ancestors:
      member = anc.__dict__.get(name)
      if member is None:
        continue
      anc_mod = getattr(anc, "__module__", "") or ""
      if isinstance(member, property):
        for accessor in (member.fget, member.fset, member.fdel):
          if accessor is not None:
            worklist.append((accessor, anc_mod, owner_ancestors))
      else:
        worklist.append((member, anc_mod, owner_ancestors))

  for cell in getattr(unwrapped, "__closure__", None) or ():
    try:
      worklist.append((cell.cell_contents, "", owner_ancestors))
    except ValueError:
      continue

  defaults = tuple(getattr(unwrapped, "__defaults__", None) or ()) + tuple(
      (getattr(unwrapped, "__kwdefaults__", None) or {}).values()
  )
  for default_val in defaults:
    worklist.append((default_val, "", owner_ancestors))

  return worklist


def _is_dangerous_referenced_module(
    module_obj: types.ModuleType,
    referenced_names: frozenset[str],
    *,
    is_restricted: bool,
) -> bool:
  """Checks whether a referenced `ModuleType` exposes dangerous attributes."""
  mod_name = getattr(module_obj, "__name__", "") or ""
  mod_root = mod_name.split(".")[0]
  return (
      mod_root in constants.UNSAFE_ROOT_PACKAGES
      or _is_unsafe_class_path(mod_name)
      or mod_name in constants.SUSPICIOUS_STRINGS
      or (
          is_restricted
          and mod_root not in constants.SAFE_RESTRICTED_STDLIB_ROOTS
      )
      or any(
          _is_unsafe_class_path(f"{mod_name}.{attr}")
          or f"{mod_name}.{attr}" in constants.SUSPICIOUS_STRINGS
          for attr in referenced_names
      )
  )


def _inspect_referenced_class(
    target_cls: type[Any],
    target_mod: str,
    target_ancs: Sequence[type[Any]],
    referenced_names: frozenset[str],
    approved_bases: tuple[type[Any], ...],
    seen_ids: set[Any],
    worklist: collections.deque[tuple[Any, str, Sequence[type[Any]]]],
) -> bool:
  """Checks a referenced helper `type` MRO and enqueues relevant class members."""
  target_root = target_mod.split(".")[0] if target_mod else ""
  if (
      (target_root in ("builtins", "__builtin__") and target_cls is not type)
      or issubclass(target_cls, BaseException)
      or target_cls in approved_bases
      or target_cls in target_ancs
      or target_mod == "collections.abc"
  ):
    return False
  if target_root not in constants.APPROVED_ROOT_PACKAGES:
    return True

  cls_ancs = tuple(
      anc
      for anc in target_cls.__mro__
      if anc is not object and anc not in approved_bases
  )
  for cls_anc in cls_ancs:
    cls_mod = getattr(cls_anc, "__module__", "") or target_mod
    if ("anc", id(cls_anc)) not in seen_ids:
      seen_ids.add(("anc", id(cls_anc)))
      cls_qual = getattr(cls_anc, "__qualname__", cls_anc.__name__)
      if _is_unsafe_class_path(f"{cls_mod}.{cls_qual}"):
        return True
    for member_name, member in cls_anc.__dict__.items():
      is_relevant = (
          member_name in referenced_names
          or member_name in constants.UNPICKLE_LIFECYCLE_HOOKS
          or member_name == "__call__"
      )
      member_key = ("mem", id(cls_anc), member_name)
      if is_relevant and member_key not in seen_ids:
        seen_ids.add(member_key)
        if isinstance(member, property):
          for accessor in (member.fget, member.fset, member.fdel):
            if accessor is not None:
              worklist.append((accessor, cls_mod, cls_ancs))
        else:
          worklist.append((member, cls_mod, cls_ancs))

  return False


def _callable_has_dangerous_bytecode(
    func: Any,
    *,
    owner_ancestors: Sequence[type[Any]] = (),
    is_restricted: bool = False,
    require_setattr: bool = False,
    depth: int = 0,
    visited_ids: set[Any] | None = None,
) -> bool:
  """Checks a Python function's bytecode, globals, closures, and helpers."""
  if isinstance(func, (staticmethod, classmethod)):
    func = func.__func__
  try:
    unwrapped = inspect.unwrap(func)
  except (TypeError, ValueError):
    unwrapped = func

  code_object = getattr(unwrapped, "__code__", None)
  if not isinstance(unwrapped, types.FunctionType) or not isinstance(
      code_object, types.CodeType
  ):
    return True

  referenced_names = _collect_referenced_code_names(code_object)
  if referenced_names & constants.DANGEROUS_CODE_NAMES:
    return True
  if require_setattr and not ({"object", "__setattr__"} <= referenced_names):
    return True

  approved_bases = get_all_active_approved_base_classes()
  seen_ids = visited_ids if visited_ids is not None else {id(unwrapped)}
  worklist = _seed_bytecode_worklist(
      unwrapped, referenced_names, owner_ancestors
  )

  while worklist:
    target, fallback_mod, target_ancs = worklist.popleft()
    if isinstance(target, (staticmethod, classmethod)):
      target = target.__func__
    try:
      target_unwrapped = inspect.unwrap(target)
    except (TypeError, ValueError):
      target_unwrapped = target

    if isinstance(target_unwrapped, types.ModuleType):
      if _is_dangerous_referenced_module(
          target_unwrapped, referenced_names, is_restricted=is_restricted
      ):
        return True
      continue

    if not (callable(target_unwrapped) or isinstance(target_unwrapped, type)):
      continue

    raw_mod = getattr(target_unwrapped, "__module__", "") or ""
    t_mod = (
        fallback_mod
        if fallback_mod and raw_mod in ("", "__main__")
        else raw_mod
    )
    t_name = getattr(target_unwrapped, "__name__", "") or ""
    t_qual = getattr(target_unwrapped, "__qualname__", t_name) or t_name
    t_root = t_mod.split(".")[0] if t_mod else ""
    if (
        _is_unsafe_class_path(f"{t_mod}.{t_qual}")
        or t_name in constants.DANGEROUS_CODE_NAMES
        or t_qual.split(".")[-1] in constants.DANGEROUS_CODE_NAMES
    ):
      return True

    if isinstance(target_unwrapped, type):
      if _inspect_referenced_class(
          target_unwrapped,
          t_mod,
          target_ancs,
          referenced_names,
          approved_bases,
          seen_ids,
          worklist,
      ):
        return True
      continue

    if t_root in ("builtins", "__builtin__"):
      continue
    if _is_compiled_callable(target_unwrapped) and not is_restricted:
      if not t_root or (
          t_root in constants.APPROVED_ROOT_PACKAGES
          and t_root not in constants.RESTRICTED_APPROVED_ROOTS
      ):
        continue
    if (
        t_root not in constants.APPROVED_ROOT_PACKAGES
        and t_root not in sys.stdlib_module_names
    ):
      return True
    if is_restricted and t_root not in constants.APPROVED_ROOT_PACKAGES:
      return True
    if (t_mod, t_name) == ("dataclasses", "fields") or (
        t_mod in ("numpy._core.fromnumeric", "numpy.core.fromnumeric")
    ):
      continue

    if isinstance(target_unwrapped, types.FunctionType):
      if id(target_unwrapped) in seen_ids:
        continue
      if depth >= constants.MAX_HELPER_CALL_DEPTH:
        return True
      seen_ids.add(id(target_unwrapped))
      if _callable_has_dangerous_bytecode(
          target_unwrapped,
          owner_ancestors=target_ancs,
          is_restricted=is_restricted,
          depth=depth + 1,
          visited_ids=seen_ids,
      ):
        return True
    elif (
        is_restricted
        or t_root in constants.RESTRICTED_APPROVED_ROOTS
        or not _is_compiled_callable(target_unwrapped)
    ):
      return True

  return False


def _classify_approved_root_function(
    target_callable: Any,
    symbol_name: str,
    module_path: str,
    root_package: str,
) -> Classification:
  """Classifies a live non-type callable under an approved root package."""
  if root_package in constants.RESTRICTED_APPROVED_ROOTS:
    if (
        root_package == "dataclasses" and symbol_name == "dataclass"
    ) or symbol_name in constants.SAFE_DUNDER_RECONSTRUCTORS:
      return Classification.SAFE
    return Classification.UNKNOWN

  callable_module = getattr(target_callable, "__module__", "") or module_path
  is_numpy_fromnumeric = bool(
      {module_path, callable_module}
      & {"numpy._core.fromnumeric", "numpy.core.fromnumeric"}
  )
  if not (_is_reconstructor_name(symbol_name) or is_numpy_fromnumeric):
    return Classification.UNKNOWN

  unwrapped = inspect.unwrap(target_callable)
  u_mod = (
      getattr(unwrapped, "__module__", "")
      or getattr(getattr(unwrapped, "__objclass__", None), "__module__", "")
      or ""
  )
  if not u_mod:
    t_root = (getattr(type(unwrapped), "__module__", "") or "").split(".")[0]
    if (
        t_root in constants.APPROVED_ROOT_PACKAGES
        and t_root not in constants.RESTRICTED_APPROVED_ROOTS
    ):
      u_mod = t_root
  u_name = getattr(unwrapped, "__name__", "") or ""
  u_qual = getattr(unwrapped, "__qualname__", u_name) or u_name
  u_root = u_mod.split(".")[0] if u_mod else ""
  u_full = f"{u_mod}.{u_qual}" if u_mod and u_qual else u_mod
  sym_full = f"{module_path}.{symbol_name}"

  if (
      _is_unsafe_class_path(u_full)
      or _is_unsafe_class_path(sym_full)
      or u_name in constants.UNSAFE_STRINGS
      or (
          u_root in constants.UNSAFE_ROOT_PACKAGES
          and u_root not in ("builtins", "__builtin__")
      )
  ):
    return Classification.UNSAFE
  if (
      u_name in constants.DANGEROUS_CODE_NAMES
      or u_qual.split(".")[-1] in constants.DANGEROUS_CODE_NAMES
      or u_name in constants.SUSPICIOUS_STRINGS
      or u_full in constants.SUSPICIOUS_STRINGS
      or sym_full in constants.SUSPICIOUS_STRINGS
      or u_root in constants.RESTRICTED_APPROVED_ROOTS
  ):
    return Classification.SUSPICIOUS

  if isinstance(unwrapped, types.FunctionType):
    if u_root not in constants.APPROVED_ROOT_PACKAGES:
      return Classification.UNKNOWN
    return (
        Classification.SUSPICIOUS
        if _callable_has_dangerous_bytecode(unwrapped)
        else Classification.SAFE
    )

  if (
      u_root in constants.APPROVED_ROOT_PACKAGES
      and u_root not in constants.RESTRICTED_APPROVED_ROOTS
      and _is_compiled_callable(unwrapped)
  ):
    return Classification.SAFE

  return Classification.UNKNOWN


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


def _collect_ast_imports(
    nodes: Iterable[ast.AST],
    pkg_parts: Sequence[str],
) -> tuple[dict[str, str], list[str], bool]:
  """Resolves `Import` and `ImportFrom` bindings across AST `nodes`."""
  imports: dict[str, str] = {}
  imported_names: list[str] = []
  had_invalid_rel = False

  for node in nodes:
    if isinstance(node, ast.Import):
      for alias in node.names:
        if alias.asname:
          imports[alias.asname] = alias.name
        else:
          top_name = alias.name.split(".")[0]
          imports[top_name] = top_name
        imported_names.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
      if node.level > 0:
        if pkg_parts and (node.level - 1) <= len(pkg_parts):
          anchor = list(pkg_parts[: len(pkg_parts) - (node.level - 1)])
          resolved_mod = ".".join(
              anchor + ([node.module] if node.module else [])
          )
        else:
          had_invalid_rel = True
          resolved_mod = ""
      else:
        resolved_mod = node.module or ""

      if node.module:
        imported_names.append(node.module)
      for alias in node.names:
        imported_names.append(alias.name)
        if resolved_mod:
          imports[alias.asname or alias.name] = f"{resolved_mod}.{alias.name}"

  return imports, imported_names, had_invalid_rel


def _has_unapproved_ast_externals(
    ext_syms: Iterable[str],
    call_attrs: frozenset[str],
    *,
    is_restricted: bool,
    depth: int,
) -> Classification:
  """Verifies imported external symbols referenced within an AST hook."""
  verified_non_modules: set[str] = set()
  failed = False

  for ext_sym in sorted(set(ext_syms), key=len):
    if not ext_sym:
      continue
    ext_parts = ext_sym.split(".")
    ext_root = ext_parts[0]
    if (
        _is_unsafe_class_path(ext_sym)
        or ext_sym in constants.SUSPICIOUS_STRINGS
        or ext_root in constants.UNSAFE_ROOT_PACKAGES
        or (
            ext_root not in constants.APPROVED_ROOT_PACKAGES
            and ext_root not in sys.stdlib_module_names
        )
        or (
            is_restricted
            and ext_sym not in constants.APPROVED_AST_BASE_NAMES
            and ext_sym not in constants.NEUTRAL_AST_BASE_NAMES
            and ext_root not in constants.SAFE_RESTRICTED_STDLIB_ROOTS
        )
    ):
      failed = True
      continue
    if (
        "." not in ext_sym
        or (
            ext_root in sys.stdlib_module_names
            and ext_root not in constants.RESTRICTED_APPROVED_ROOTS
        )
        or ext_sym in constants.APPROVED_AST_BASE_NAMES
        or ext_sym in constants.NEUTRAL_AST_BASE_NAMES
        or ext_sym.startswith(
            ("abc.", "collections.abc.", "dataclasses.", "typing.")
        )
        or ext_parts[-1] in constants.SAFE_METADATA_ATTRIBUTES
        or ext_parts[-1] == "__version__"
        or ".".join(ext_parts[:-1]) in verified_non_modules
        or isinstance(
            _resolve_dotted_path_in_sys_modules(ext_sym), types.ModuleType
        )
        or _find_module_source_file(ext_sym) is not None
        or _find_module_source_file(ext_sym, compiled=True) is not None
    ):
      continue
    if is_restricted or depth >= constants.MAX_AST_BASE_DEPTH:
      failed = True
      continue

    verdict = classify_approved_root_symbol(
        ext_sym, _depth=depth + 1, _extra_hooks=call_attrs
    )
    if verdict == Classification.UNSAFE:
      return Classification.UNSAFE
    if verdict != Classification.SAFE:
      failed = True
      continue
    verified_non_modules.add(ext_sym)

  return Classification.SUSPICIOUS if failed else Classification.SAFE


def _ast_hook_status(
    func_node: ast.AST,
    file_ctx: tuple[str, str, str, tuple[str, ...]],
    import_map: Mapping[str, str],
    top_funcs: Mapping[str, ast.AST],
    top_classes: Mapping[str, ast.ClassDef],
    class_methods: Mapping[str, ast.AST] | None = None,
    *,
    owner_name: str = "",
    is_restricted: bool = False,
    require_setattr: bool = False,
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
) -> Classification:
  """Checks an AST hook and its local helpers for dangerous references."""
  file_path, root_pkg, module_path, pkg_parts = file_ctx
  walk_nodes = tuple(ast.walk(func_node))
  fn_imports, candidates, failed = _collect_ast_imports(walk_nodes, pkg_parts)
  local_imports = {**import_map, **fn_imports}

  first_arg = ""
  if class_methods is not None and isinstance(
      func_node, (ast.FunctionDef, ast.AsyncFunctionDef)
  ):
    is_static = any(
        _ast_expr_to_dotted_name(dec, local_imports).endswith("staticmethod")
        for dec in func_node.decorator_list
    )
    pos_args = func_node.args.posonlyargs + func_node.args.args
    if not is_static:
      if pos_args:
        first_arg = pos_args[0].arg
      else:
        failed = True

  assigned_self_attrs = {
      node.attr
      for node in walk_nodes
      if first_arg
      and isinstance(node, ast.Attribute)
      and isinstance(node.ctx, ast.Store)
      and isinstance(node.value, ast.Name)
      and node.value.id == first_arg
  }
  load_attrs = {
      node.attr
      for node in walk_nodes
      if isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Store)
  }
  call_attrs = frozenset(load_attrs | {"__call__"})

  names_seen: set[str] = set()
  attrs_seen: set[str] = set()
  helpers: list[tuple[str, str]] = []
  ext_syms: set[str] = set()

  for child in walk_nodes:
    if isinstance(child, ast.Call) and isinstance(child.func, ast.Subscript):
      failed = True
    if isinstance(child, ast.Name):
      names_seen.add(child.id)
      resolved = local_imports.get(child.id, "")
      candidates.extend((child.id, resolved))
      if resolved:
        ext_syms.add(resolved)
      if child.id not in fn_imports:
        if child.id in top_funcs:
          helpers.append(("mod", child.id))
        elif child.id in top_classes and child.id != owner_name:
          if is_restricted or depth >= constants.MAX_AST_BASE_DEPTH:
            failed = True
          else:
            cls_verdict = _inspect_class_via_ast(
                file_path,
                child.id,
                root_pkg,
                module_path,
                depth + 1,
                call_attrs,
            )
            if cls_verdict == Classification.UNSAFE:
              return Classification.UNSAFE
            if cls_verdict != Classification.SAFE:
              failed = True
    elif isinstance(child, ast.Attribute):
      attrs_seen.add(child.attr)
      dotted = _ast_expr_to_dotted_name(child, local_imports)
      candidates.extend((child.attr, dotted))
      if (
          _is_unsafe_class_path(dotted)
          or dotted in constants.SUSPICIOUS_STRINGS
      ):
        failed = True
      root_expr: ast.AST = child
      while isinstance(root_expr, ast.Attribute):
        root_expr = root_expr.value
      if isinstance(root_expr, ast.Name) and root_expr.id in local_imports:
        ext_syms.add(dotted)

      is_super = (
          isinstance(child.value, ast.Call)
          and _ast_expr_to_dotted_name(child.value.func, local_imports)
          == "super"
      )
      is_self = (
          bool(first_arg)
          and isinstance(child.value, ast.Name)
          and child.value.id == first_arg
      )
      is_owner = (
          bool(owner_name)
          and isinstance(child.value, ast.Name)
          and child.value.id == owner_name
          and child.value.id not in fn_imports
      )
      if is_super and not isinstance(child.ctx, ast.Store):
        if child.attr not in constants.UNPICKLE_LIFECYCLE_HOOKS:
          failed = True
      elif (
          (is_self or is_owner)
          and class_methods
          and child.attr in class_methods
      ):
        helpers.append(("cls", child.attr))
      elif is_self and not isinstance(child.ctx, ast.Store):
        allowed_self = (
            constants.UNPICKLE_LIFECYCLE_HOOKS
            | assigned_self_attrs
            | {"__class__", "__dict__"}
        )
        if child.attr not in allowed_self:
          failed = True

  if require_setattr and not (
      "object" in names_seen and "__setattr__" in attrs_seen
  ):
    failed = True
  if any(
      cand and (set(cand.split(".")) & constants.DANGEROUS_CODE_NAMES)
      for cand in candidates
  ):
    failed = True

  ext_verdict = _has_unapproved_ast_externals(
      ext_syms, call_attrs, is_restricted=is_restricted, depth=depth
  )
  if ext_verdict == Classification.UNSAFE:
    return Classification.UNSAFE
  if ext_verdict != Classification.SAFE:
    failed = True

  for kind, helper_name in helpers:
    tag = f"{kind}:{helper_name}"
    if tag in visited:
      continue
    if len(visited) >= constants.MAX_HELPER_CALL_DEPTH:
      failed = True
      continue
    helper_node = (
        top_funcs[helper_name]
        if kind == "mod"
        else (class_methods[helper_name] if class_methods is not None else None)
    )
    if helper_node is None:
      failed = True
      continue
    helper_verdict = _ast_hook_status(
        helper_node,
        file_ctx,
        import_map,
        top_funcs,
        top_classes,
        class_methods,
        owner_name=owner_name,
        is_restricted=is_restricted,
        depth=depth,
        visited=visited | {tag},
    )
    if helper_verdict == Classification.UNSAFE:
      return Classification.UNSAFE
    if helper_verdict != Classification.SAFE:
      failed = True

  return Classification.SUSPICIOUS if failed else Classification.SAFE


def _classify_ast_reexport(
    reexported: str,
    depth: int,
    extra_hooks: frozenset[str] = frozenset(),
) -> Classification:
  """Classifies an imported symbol re-exported at top level of an AST module."""
  reexport_root = reexported.split(".")[0]
  if reexport_root in constants.UNSAFE_ROOT_PACKAGES:
    return Classification.UNSAFE
  if reexport_root not in constants.APPROVED_ROOT_PACKAGES:
    return classify_symbol(reexported)

  re_segs = reexported.split(".")[1:]
  if _is_unsafe_class_path(reexported) or any(
      seg in constants.DANGEROUS_PACKAGE_MEMBERS
      or seg in constants.DANGEROUS_EXEC_MODULES
      for seg in re_segs
  ):
    return Classification.UNSAFE
  if reexported in constants.SUSPICIOUS_STRINGS or any(
      reexported.startswith(f"{s}.") for s in constants.SUSPICIOUS_STRINGS
  ):
    return Classification.SUSPICIOUS

  return (
      classify_approved_root_symbol(
          reexported, _depth=depth + 1, _extra_hooks=extra_hooks
      )
      or Classification.UNKNOWN
  )


def _resolve_ast_bases(
    resolved_bases: Sequence[str],
    file_ctx: tuple[str, str, str, tuple[str, ...]],
    top_classes: Mapping[str, ast.ClassDef],
    *,
    is_restricted: bool,
    is_dataclass: bool,
    saw_unknown: bool,
    depth: int,
    extra_hooks: frozenset[str] = frozenset(),
) -> Classification:
  """Resolves AST base-class classifications into a final class verdict."""
  file_path, root_pkg, module_path, _ = file_ctx
  base_verdicts: list[Classification] = []

  for base_name in resolved_bases:
    if (
        base_name in constants.APPROVED_AST_BASE_NAMES
        or base_name in constants.NEUTRAL_AST_BASE_NAMES
    ):
      base_verdicts.append(Classification.SAFE)
    elif depth >= constants.MAX_AST_BASE_DEPTH:
      base_verdicts.append(Classification.UNKNOWN)
    elif "." not in base_name:
      same_file_verdict = None
      if base_name in top_classes:
        same_file_verdict = _inspect_class_via_ast(
            file_path,
            base_name,
            root_pkg,
            module_path,
            depth + 1,
            extra_hooks,
        )
      base_verdicts.append(same_file_verdict or Classification.UNKNOWN)
    else:
      base_verdicts.append(
          classify_approved_root_symbol(
              base_name, _depth=depth + 1, _extra_hooks=extra_hooks
          )
          or Classification.UNKNOWN
      )

  if Classification.UNSAFE in base_verdicts:
    return Classification.UNSAFE
  if Classification.SUSPICIOUS in base_verdicts:
    return Classification.SUSPICIOUS
  if saw_unknown:
    return Classification.UNKNOWN

  if is_restricted and not is_dataclass:
    active_bases = get_all_active_approved_base_classes()
    if not any(
        base_name in constants.APPROVED_AST_BASE_NAMES
        or (
            isinstance(
                live_base := _resolve_dotted_path_in_sys_modules(base_name),
                type,
            )
            and issubclass(live_base, active_bases)
        )
        for base_name in resolved_bases
    ):
      return Classification.UNKNOWN

  if all(verdict == Classification.SAFE for verdict in base_verdicts):
    return Classification.SAFE
  return Classification.UNKNOWN


def _inspect_ast_class_node(
    node: ast.ClassDef,
    symbol_name: str,
    file_ctx: tuple[str, str, str, tuple[str, ...]],
    import_map: Mapping[str, str],
    top_funcs: Mapping[str, ast.AST],
    top_classes: Mapping[str, ast.ClassDef],
    depth: int,
    extra_hooks: frozenset[str] = frozenset(),
) -> Classification:
  """Classifies an `ast.ClassDef` node by checking its bases and hooks."""
  is_restricted = file_ctx[1] in constants.RESTRICTED_APPROVED_ROOTS
  method_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
  class_methods: dict[str, ast.AST] = {}
  assigned_names: set[str] = set()
  stmt_stack = list(node.body)

  while stmt_stack:
    item = stmt_stack.pop()
    if isinstance(item, ast.ClassDef):
      continue
    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
      method_nodes.append(item)
      class_methods[item.name] = item
      continue
    targets = (
        item.targets
        if isinstance(item, ast.Assign)
        else ([item.target] if isinstance(item, ast.AnnAssign) else [])
    )
    for target in targets:
      if isinstance(target, ast.Name):
        assigned_names.add(target.id)
    for child in ast.iter_child_nodes(item):
      if isinstance(child, ast.stmt):
        stmt_stack.append(child)

  member_names = set(class_methods) | assigned_names
  resolved_bases = [
      _ast_expr_to_dotted_name(base_expr, import_map)
      for base_expr in node.bases
  ]
  for kw in node.keywords:
    if kw.arg == "metaclass":
      meta_name = _ast_expr_to_dotted_name(kw.value, import_map)
      if meta_name not in ("ABCMeta", "abc.ABCMeta", "type", "builtins.type"):
        resolved_bases.append(meta_name)

  for base_name in resolved_bases:
    if _is_unsafe_class_path(base_name) or any(
        seg in constants.DANGEROUS_PACKAGE_MEMBERS
        or seg in constants.DANGEROUS_EXEC_MODULES
        for seg in base_name.split(".")[1:]
    ):
      return Classification.UNSAFE

  saw_unknown = any(not base_name for base_name in resolved_bases)
  resolved_bases = [base for base in resolved_bases if base]
  is_dataclass = any(
      _ast_expr_to_dotted_name(dec, import_map).endswith("dataclass")
      for dec in node.decorator_list
  )

  if is_restricted:
    if {"__reduce__", "__reduce_ex__"} & member_names:
      return Classification.SUSPICIOUS
    if symbol_name.startswith("_"):
      saw_unknown = True
    disallowed = (
        constants.RESTRICTED_DATACLASS_DISALLOWED_HOOKS
        if is_dataclass
        else constants.DANGEROUS_CLASS_LIFECYCLE_HOOKS
    )
    if disallowed & member_names:
      return Classification.SUSPICIOUS

  hooks_to_check = constants.UNPICKLE_LIFECYCLE_HOOKS | extra_hooks
  unknown_only = (
      {"__init__"} | (set() if is_restricted else {"__new__"})
  ) - extra_hooks
  ordered_hooks = sorted(hooks_to_check, key=lambda h: h in unknown_only)
  for hook_name in ordered_hooks:
    fail_cls = (
        Classification.UNKNOWN
        if hook_name in unknown_only
        else Classification.SUSPICIOUS
    )
    if hook_name in assigned_names:
      if fail_cls != Classification.UNKNOWN:
        return fail_cls
      saw_unknown = True
      continue

    need_setattr = (
        is_restricted and is_dataclass and hook_name == "__setstate__"
    )
    for method_node in method_nodes:
      if method_node.name != hook_name:
        continue
      hook_verdict = _ast_hook_status(
          method_node,
          file_ctx,
          import_map,
          top_funcs,
          top_classes,
          class_methods,
          owner_name=symbol_name,
          is_restricted=is_restricted,
          require_setattr=need_setattr,
          depth=depth,
      )
      if hook_verdict == Classification.UNSAFE:
        return Classification.UNSAFE
      if hook_verdict != Classification.SAFE:
        if fail_cls != Classification.UNKNOWN:
          return fail_cls
        saw_unknown = True

  return _resolve_ast_bases(
      resolved_bases,
      file_ctx,
      top_classes,
      is_restricted=is_restricted,
      is_dataclass=is_dataclass,
      saw_unknown=saw_unknown,
      depth=depth,
      extra_hooks=extra_hooks,
  )


@functools.lru_cache(maxsize=512)
def _inspect_class_via_ast(
    file_path: str,
    symbol_name: str,
    root_pkg: str,
    module_path: str = "",
    depth: int = 0,
    extra_hooks: frozenset[str] = frozenset(),
) -> Classification | None:
  """Classifies a class definition by statically parsing its `.py` source file.

  Parses `file_path` with `ast.parse` without importing the module, resolves
  top-level imports, and inspects the target `ast.ClassDef` node's base
  classes, decorators, and lifecycle hook methods.

  Args:
    file_path: Filesystem path to the `.py` module source file.
    symbol_name: Name of the class or function symbol to inspect.
    root_pkg: Top-level root package name (e.g., `"torch"` or `"dataclasses"`).
    module_path: Optional dotted module path used for relative imports.
    depth: Recursion depth for base-class and re-export resolution.
    extra_hooks: Additional method names required safe on helper classes.

  Returns:
    A `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) if the
    symbol is resolved in `file_path`, or None if the file cannot be parsed or
    the symbol is absent.
  """
  try:
    with open(
        file_path, "r", encoding="utf-8", errors="ignore"
    ) as source_file:
      tree = ast.parse(source_file.read(), filename=file_path)
  except (IOError, OSError, SyntaxError, ValueError, TypeError):
    return None

  mod_parts = tuple(module_path.split(".")) if module_path else ()
  pkg_parts = (
      mod_parts
      if os.path.basename(file_path) == "__init__.py"
      else mod_parts[:-1]
  )
  import_map, _, _ = _collect_ast_imports(tree.body, pkg_parts)
  top_classes = {
      stmt.name: stmt for stmt in tree.body if isinstance(stmt, ast.ClassDef)
  }
  top_funcs = {
      stmt.name: stmt
      for stmt in tree.body
      if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
  }
  file_ctx = (file_path, root_pkg, module_path, pkg_parts)

  if symbol_name in top_funcs:
    is_restricted = root_pkg in constants.RESTRICTED_APPROVED_ROOTS
    if is_restricted or not _is_reconstructor_name(symbol_name):
      return Classification.UNKNOWN
    return _ast_hook_status(
        top_funcs[symbol_name],
        file_ctx,
        import_map,
        top_funcs,
        top_classes,
        depth=depth,
    )

  if symbol_name not in top_classes:
    if symbol_name not in import_map:
      return None
    return _classify_ast_reexport(import_map[symbol_name], depth, extra_hooks)

  return _inspect_ast_class_node(
      top_classes[symbol_name],
      symbol_name,
      file_ctx,
      import_map,
      top_funcs,
      top_classes,
      depth,
      extra_hooks,
  )


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
  if root_package in sys.modules:
    return True

  is_installed, _, _ = _find_root_package_spec_info(root_package)
  return is_installed


def _classify_loaded_class_mro(
    target_class: type[Any],
    symbol_name: str,
    root_package: str,
    extra_hooks: frozenset[str] = frozenset(),
) -> Classification:
  """Classifies a live class object by inspecting its module, MRO, and methods.

  Walks `target_class.__mro__` to verify that no ancestor originates from an
  unsafe package or defines dangerous pickle lifecycle hooks, and checks
  whether `target_class` inherits from an approved base class or has safe
  unpickling lifecycle hooks.

  Args:
    target_class: The live `type` object resolved from `sys.modules`.
    symbol_name: Name of the class symbol being classified.
    root_package: Expected top-level root package name from the symbol path.
    extra_hooks: Additional method names required safe on helper classes.

  Returns:
    The `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) for
    `target_class`.
  """
  try:
    approved_bases = get_all_active_approved_base_classes()
    class_module = getattr(target_class, "__module__", "") or ""
    class_root = class_module.split(".")[0] if class_module else ""
    if class_root in constants.UNSAFE_ROOT_PACKAGES:
      return Classification.UNSAFE
    if class_root != root_package and (
        class_root not in constants.APPROVED_ROOT_PACKAGES
        or (
            root_package not in constants.RESTRICTED_APPROVED_ROOTS
            and class_root in constants.RESTRICTED_APPROVED_ROOTS
            and target_class not in approved_bases
        )
    ):
      return Classification.SUSPICIOUS

    non_approved_ancestors: list[type[Any]] = []
    for ancestor in target_class.__mro__:
      if ancestor is object:
        continue

      ancestor_mod = getattr(ancestor, "__module__", "") or ""
      ancestor_qual = getattr(
          ancestor, "__qualname__", getattr(ancestor, "__name__", "")
      )
      if _is_unsafe_class_path(f"{ancestor_mod}.{ancestor_qual}"):
        return Classification.UNSAFE

      if ancestor not in approved_bases:
        non_approved_ancestors.append(ancestor)

    if target_class in approved_bases and not extra_hooks:
      return Classification.SAFE

    is_restricted_root = root_package in constants.RESTRICTED_APPROVED_ROOTS
    is_dataclass_type = dataclasses.is_dataclass(target_class)

    if is_restricted_root and any(
        "__reduce__" in anc.__dict__ or "__reduce_ex__" in anc.__dict__
        for anc in non_approved_ancestors
    ):
      return Classification.SUSPICIOUS

    saw_unknown = is_restricted_root and symbol_name.startswith("_")
    disallowed_hooks: frozenset[str] = frozenset()
    if is_restricted_root:
      disallowed_hooks = constants.DANGEROUS_CLASS_LIFECYCLE_HOOKS
      if is_dataclass_type:
        disallowed_hooks = constants.RESTRICTED_DATACLASS_DISALLOWED_HOOKS

    anc_hooks = constants.UNPICKLE_LIFECYCLE_HOOKS | extra_hooks
    unknown_only = (
        {"__init__"} | (set() if is_restricted_root else {"__new__"})
    ) - extra_hooks
    for ancestor in non_approved_ancestors:
      if disallowed_hooks.intersection(ancestor.__dict__):
        return Classification.SUSPICIOUS

      is_c_ext_ancestor = not bool(
          getattr(ancestor, "__flags__", constants.PY_TPFLAGS_HEAPTYPE)
          & constants.PY_TPFLAGS_HEAPTYPE
      ) or ("__pyx_vtable__" in ancestor.__dict__)

      for hook_name in anc_hooks:
        if hook_name not in ancestor.__dict__:
          continue
        fail_cls = (
            Classification.UNKNOWN
            if hook_name in unknown_only
            else Classification.SUSPICIOUS
        )
        raw_hook = ancestor.__dict__[hook_name]
        unwrapped_hook = inspect.unwrap(
            raw_hook.__func__
            if isinstance(raw_hook, (staticmethod, classmethod))
            else raw_hook
        )
        if (
            is_restricted_root
            and hook_name == "__setstate__"
            and getattr(unwrapped_hook, "__module__", "") == "dataclasses"
        ):
          continue
        if isinstance(unwrapped_hook, types.FunctionType):
          if _callable_has_dangerous_bytecode(
              unwrapped_hook,
              owner_ancestors=non_approved_ancestors,
              is_restricted=is_restricted_root,
              require_setattr=(
                  is_restricted_root
                  and is_dataclass_type
                  and hook_name == "__setstate__"
              ),
          ):
            if fail_cls != Classification.UNKNOWN:
              return fail_cls
            saw_unknown = True
        elif (
            is_restricted_root
            or not is_c_ext_ancestor
            or not _is_compiled_callable(unwrapped_hook)
        ):
          if fail_cls != Classification.UNKNOWN:
            return fail_cls
          saw_unknown = True

    if saw_unknown:
      return Classification.UNKNOWN

    if is_restricted_root and not is_dataclass_type:
      return (
          Classification.SAFE
          if issubclass(target_class, approved_bases)
          else Classification.UNKNOWN
      )

    return Classification.SAFE
  except (TypeError, AttributeError, ValueError, RuntimeError):
    return Classification.UNKNOWN


def classify_approved_root_symbol(
    symbol: str,
    *,
    _depth: int = 0,
    _extra_hooks: frozenset[str] = frozenset(),
) -> Classification | None:
  """Classifies a dotted symbol under an approved root package.

  Inspects a dotted symbol without executing arbitrary module imports by
  checking (1) loaded modules and objects in `sys.modules` (verifying class
  MROs or reconstructor bytecode), (2) static `.py` source files on disk via
  `ast.parse`, (3) compiled C/Cython extension modules on disk, and (4)
  structural naming rules for uninstalled approved roots.

  Args:
    symbol: Fully qualified dotted symbol string (e.g., `'torch.nn.Linear'`).
    _depth: Internal recursion depth for AST base and re-export resolution.
    _extra_hooks: Internal method names required safe on helper classes.

  Returns:
    The `Classification` (`SAFE`, `UNSAFE`, `SUSPICIOUS`, or `UNKNOWN`) if
    the symbol belongs to an unsafe or approved root package, or None if the
    symbol is unqualified, malformed, or belongs to an unlisted root package.
  """
  if not symbol or "." not in symbol:
    return None
  if _depth > constants.MAX_AST_BASE_DEPTH:
    return Classification.UNKNOWN

  symbol_parts = symbol.split(".")
  if not all(part.isidentifier() for part in symbol_parts):
    return None

  root_package = symbol_parts[0]
  if root_package in constants.UNSAFE_ROOT_PACKAGES:
    return Classification.UNSAFE
  if root_package not in constants.APPROVED_ROOT_PACKAGES:
    return None

  if any(is_dunder_or_introspection_attr(seg) for seg in symbol_parts[1:]):
    return Classification.SUSPICIOUS

  module_path = ".".join(symbol_parts[:-1])
  symbol_name = symbol_parts[-1]

  if symbol in constants.ALL_BASE_CLASS_SPECS and not _extra_hooks:
    return Classification.SAFE

  target_module = _resolve_dotted_path_in_sys_modules(module_path)
  if target_module is not None:
    target_object = getattr(target_module, symbol_name, None)
    if target_object is None:
      return Classification.UNKNOWN

    if isinstance(target_object, types.ModuleType):
      module_name = getattr(target_object, "__name__", "") or ""
      module_root = module_name.split(".")[0]
      if (
          module_root in constants.UNSAFE_ROOT_PACKAGES
          or _is_unsafe_class_path(module_name)
      ):
        return Classification.UNSAFE
      if module_root != root_package and (
          module_root not in constants.APPROVED_ROOT_PACKAGES
          or module_root in constants.RESTRICTED_APPROVED_ROOTS
      ):
        return Classification.SUSPICIOUS
      return Classification.SAFE

    if not isinstance(target_object, type):
      return _classify_approved_root_function(
          target_object, symbol_name, module_path, root_package
      )

    return _classify_loaded_class_mro(
        target_object, symbol_name, root_package, _extra_hooks
    )

  if (source_file := _find_module_source_file(module_path)) is not None:
    return (
        _inspect_class_via_ast(
            source_file,
            symbol_name,
            root_package,
            module_path,
            _depth,
            _extra_hooks,
        )
        or Classification.UNKNOWN
    )

  if _find_module_source_file(symbol) is not None or (
      root_package not in constants.RESTRICTED_APPROVED_ROOTS
      and _find_module_source_file(symbol, compiled=True) is not None
  ):
    return Classification.SAFE

  is_pascal_class = symbol_name[:1].isupper() or (
      symbol_name.startswith("_") and symbol_name[1:2].isupper()
  )
  if (
      root_package not in constants.RESTRICTED_APPROVED_ROOTS
      and (is_pascal_class or _is_reconstructor_name(symbol_name))
      and (
          _find_module_source_file(module_path, compiled=True) is not None
          or not _is_installed_root_package(root_package)
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

  symbol_clean = _normalize_corrupy_symbol(symbol.strip())
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

  parts = (
      symbol_clean.split(".")
      if ("." in symbol_clean and " " not in symbol_clean)
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

  if any(symbol_clean.startswith(f"{u}.") for u in constants.UNSAFE_STRINGS):
    return Classification.UNSAFE

  if any(
      symbol_clean.startswith(f"{s}.") for s in constants.SUSPICIOUS_STRINGS
  ) or (parts and parts[-1] in constants.SUSPICIOUS_STRINGS):
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

  if parts and parts[0] in constants.APPROVED_ROOT_PACKAGES:
    if parts[-1] in constants.SAFE_DUNDER_RECONSTRUCTORS or (
        parts[0] == "dataclasses" and parts[-1] == "dataclass"
    ):
      return Classification.SAFE
    return classify_approved_root_symbol(symbol_clean) or Classification.UNKNOWN

  if any(symbol_clean.startswith(f"{s}.") for s in constants.SAFE_STRINGS):
    return Classification.SAFE

  return Classification.UNKNOWN


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
    is_suspicious_override: bool = False,
) -> bool:
  """Parses a `picklemagic` log line against `pattern` and registers symbols.

  Args:
    line: Raw log line emitted by `corrupy.picklemagic`.
    pattern: Compiled regex with named capture groups for symbol extraction.
    register_item: Callback invoked to classify and record extracted symbols.
    is_suspicious_override: Whether `UNKNOWN` class matches should be promoted
      to `SUSPICIOUS`.

  Returns:
    True if `pattern` matched `line`, or False otherwise.
  """
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
    normalized_class = _normalize_corrupy_symbol(class_name)
    is_internal = normalized_class in constants.INTERNAL_FAKE_WARNING_CLASSES
    register_item(
        normalized_class,
        Classification.SUSPICIOUS
        if (is_suspicious_override and not is_internal)
        else None,
    )
    if method_name:
      register_item(
          method_name if is_internal else f"{normalized_class}.{method_name}"
      )

  if attr_name:
    register_item(attr_name)

  if module_name:
    register_item(module_name)

  combined_args = (args or state) + " " + kwargs
  if combined_args.strip():
    combined_args = _strip_binary_bytes_repr(combined_args)
    for group in _COMBINED_ARGS_TOKEN_RE.findall(combined_args):
      for token in group:
        token = token.strip(".")
        if token and not _HEX_TOKEN_PREFIX_RE.match(token):
          register_item(token)

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
  """Parses and categorizes `corrupy.picklemagic` warning log output.

  Args:
    filtered_output: Buffer containing warning lines captured from
      `picklemagic`.

  Returns:
    A 4-tuple of `(safe_results, unsafe_results, suspicious_results,
    unknown_results)` string sets.
  """
  results: dict[Classification, Set[str]] = {
      Classification.SAFE: set(),
      Classification.UNSAFE: set(),
      Classification.SUSPICIOUS: set(),
      Classification.UNKNOWN: set(),
  }

  def register_item(item: str, override: Classification | None = None):
    base_cls = classify_symbol(item) if item else None
    cls = (
        override
        if (override is not None and base_cls == Classification.UNKNOWN)
        else base_cls
    )
    if cls is not None:
      results[cls].add(item)

  lines = filtered_output.getvalue().split("\n")
  for line in lines:
    if not line:
      continue

    clean_line = line.removeprefix("WARNING:picklemagic:")
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
        results[Classification.UNKNOWN].add(full_name)
        continue

    matched = False
    for keyword, pattern, is_override in PICKLEMAGIC_PATTERNS:
      if keyword in line:
        if _parse_and_process_pattern(
            line,
            pattern,
            register_item,
            is_suspicious_override=is_override,
        ):
          matched = True
          break

    if matched:
      continue

  return (
      results[Classification.SAFE],
      results[Classification.UNSAFE],
      results[Classification.SUSPICIOUS],
      results[Classification.UNKNOWN],
  )


_OPCODES_STRIDE_1: frozenset[int] = frozenset({
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
})
_OPCODES_STRIDE_2: frozenset[int] = frozenset({0x80, 0x4B, 0x68, 0x71})
_OPCODES_STRIDE_3: frozenset[int] = frozenset({0x4D})
_OPCODES_STRIDE_5: frozenset[int] = frozenset({0x4A, 0x6A, 0x72})
_OPCODES_STRIDE_9: frozenset[int] = frozenset({0x47, 0x95})


def _build_opcode_strides() -> list[int]:
  """Constructs a 256-element byte stride lookup table for fixed-size opcodes.

  Precomputes fixed byte offset advances for standard pickle opcodes so the
  parser can skip non-string operands in O(1) time without unpacking arguments.

  Returns:
    A 256-element integer list where indices represent opcode bytes and values
    represent the total stride in bytes, or -1 for variable-length opcodes.
  """
  strides = [-1] * 256
  for opcode_byte in _OPCODES_STRIDE_1:
    strides[opcode_byte] = 1
  for opcode_byte in _OPCODES_STRIDE_2:
    strides[opcode_byte] = 2
  for opcode_byte in _OPCODES_STRIDE_3:
    strides[opcode_byte] = 3
  for opcode_byte in _OPCODES_STRIDE_5:
    strides[opcode_byte] = 5
  for opcode_byte in _OPCODES_STRIDE_9:
    strides[opcode_byte] = 9
  return strides


OPCODE_STRIDES = _build_opcode_strides()


def decode_string_operand(
    data: bytes | mmap.mmap,
    start: int,
    length: int,
    encoding: str = "utf-8",
) -> str | None:
  """Decodes a byte slice into a string operand safely.

  Decodes string operands extracted from pickle byte streams while ignoring
  decode errors and filtering out single-character strings.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    start: The starting byte offset of the string payload.
    length: The byte length of the string payload.
    encoding: The character encoding to apply (defaults to utf-8).

  Returns:
    The decoded string operand if length exceeds 1 character, otherwise None.
  """
  try:
    decoded_string = data[start : start + length].decode(
        encoding, errors="ignore"
    )
    return decoded_string if len(decoded_string) > 1 else None
  except (UnicodeDecodeError, ValueError):
    return None


def _read_length_span(
    data: bytes | mmap.mmap,
    pos: int,
    total_length: int,
    header_size: int,
) -> tuple[int, int]:
  """Returns (length, next_pos) for a length-prefixed opcode or raises error.

  Validates that operand lengths do not exceed the bounds of the enclosing
  pickle stream buffer.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    pos: Current byte offset at the start of the opcode.
    total_length: Total byte length of the pickle data buffer.
    header_size: Number of header bytes (1 opcode byte + length prefix bytes).

  Returns:
    A tuple of (payload_length, next_opcode_offset).

  Raises:
    exceptions.UnsafePickleDetectedError: If payload bounds exceed the buffer.
  """
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
  """Returns index of next newline at or after start offset, or raises error.

  Locates the terminating newline delimiter for text-based pickle opcodes.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    start: Byte offset where searching for newline should begin.
    error_offset: Byte offset reported if the stream is truncated before
      newline.

  Returns:
    The integer index of the newline byte in data.

  Raises:
    exceptions.UnsafePickleDetectedError: If no newline is found before end of
    data.
  """
  newline_offset = data.find(b"\n", start)
  if newline_offset == -1:
    raise exceptions.UnsafePickleDetectedError(
        "Parser error during security scan: truncated newline at offset"
        f" {error_offset}"
    )
  return newline_offset


MAX_ABSTRACT_STACK_SIZE = 65536


def _apply_fixed_opcode_stack_effect(
    opcode_byte: int,
    data: bytes | mmap.mmap,
    current_offset: int,
    value_stack: list[Optional[str]],
    mark_stack: list[int],
    memo_table: dict[int, Optional[str]],
) -> None:
  """Updates abstract stack and memo state for a fixed-stride pickle opcode.

  Args:
    opcode_byte: Single-byte integer opcode value.
    data: Raw pickle byte buffer or memory-mapped file.
    current_offset: Byte offset of `opcode_byte` within `data`.
    value_stack: Abstract stack tracking string operands and placeholders.
    mark_stack: Stack of `value_stack` indices pushed by `MARK` (`0x28`).
    memo_table: Mapping from integer memo keys to tracked string operands.

  Returns:
    None.
  """
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

    case 0x64 | 0x69 | 0x6C | 0x6F | 0x74 | 0x91:
      # DICT, INST, LIST, OBJ, TUPLE, FROZENSET
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

    case 0x85 | 0x98:  # TUPLE1, READONLY_BUFFER
      if value_stack:
        value_stack.pop()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case 0x52 | 0x81 | 0x86:  # REDUCE, NEWOBJ, TUPLE2
      for _ in range(2):
        if value_stack:
          value_stack.pop()
      if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
        value_stack.append(None)

    case 0x87 | 0x92:  # TUPLE3, NEWOBJ_EX
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
        | 0x82  # EXT1
        | 0x83  # EXT2
        | 0x84  # EXT4
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
  """Partitions pickle bytes into opcode-aligned chunk slices with seed stacks.

  Scans opcode boundaries so large pickle buffers can be partitioned across
  multiple threads without splitting multi-byte opcodes or losing string operand
  context between boundaries.

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
        break
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
        # 1-byte prefix (SHORT_BINUNICODE) or 4-byte prefix (BINUNICODE)
        case 0x8C | 0x58:
          header_size = 2 if opcode_byte == 0x8C else 5
          try:
            operand_length, next_offset = _read_length_span(
                data, current_offset, effective_length, header_size
            )
          except exceptions.UnsafePickleDetectedError:
            break
          decoded_value = decode_string_operand(
              data, current_offset + header_size, operand_length, "utf-8"
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(decoded_value)
          current_offset = next_offset

        # 1-, 4-, or 8-byte length prefix binary/large payloads to skip safely
        case 0x43 | 0x8A | 0x42 | 0x8B | 0x8D | 0x8E | 0x96:
          header_size = (
              2
              if opcode_byte in (0x43, 0x8A)
              else (5 if opcode_byte in (0x42, 0x8B) else 9)
          )
          try:
            _, current_offset = _read_length_span(
                data, current_offset, effective_length, header_size
            )
          except exceptions.UnsafePickleDetectedError:
            break
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)

        # Newline-terminated opcodes (INT, FLOAT, LONG, STRING, etc.)
        case 0x49 | 0x46 | 0x4C | 0x70 | 0x67 | 0x50 | 0x56 | 0x53:
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
        non_null: list[Optional[str]] = [
            item for item in value_stack if item is not None
        ]
        seed_stacks.append(non_null[-16:])

  chunk_partitions = []
  for chunk_index, chunk_start in enumerate(chunk_starts):
    chunk_end = (
        chunk_starts[chunk_index + 1]
        if chunk_index + 1 < len(chunk_starts)
        else effective_length
    )
    partition = (chunk_start, chunk_end, seed_stacks[chunk_index])
    chunk_partitions.append(
        (*partition, seed_memos[chunk_index]) if include_memo else partition
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

  Traverses pickle opcodes starting from byte offset `start` up to `end`,
  yielding discovered string operands and module references while tracking stack
  state and skipping binary payloads in constant time.

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
        break
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
      # 1-byte, 4-byte, or 8-byte length-prefixed Unicode text strings
      case 0x8C | 0x58 | 0x8D:
        header_size = (
            2 if opcode_byte == 0x8C else (5 if opcode_byte == 0x58 else 9)
        )
        payload_length, current_offset = _read_length_span(
            data, current_offset, limit_offset, header_size
        )
        string_value = decode_string_operand(
            data, current_offset - payload_length, payload_length, "utf-8"
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(string_value)
        if string_value is not None:
          yield constants.OPCODES_INFO_INT.get(opcode_byte), string_value

      # Non-string binary byte buffers and bytearrays to skip safely
      case 0x43 | 0x8A | 0x42 | 0x8B | 0x8E | 0x96:
        header_size = (
            2
            if opcode_byte in (0x43, 0x8A)
            else (5 if opcode_byte in (0x42, 0x8B) else 9)
        )
        _, current_offset = _read_length_span(
            data, current_offset, limit_offset, header_size
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(None)

      # Newline-terminated string literals (Protocol 0 UNICODE / STRING)
      case 0x56 | 0x53:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        encoding = "raw-unicode-escape" if opcode_byte == 0x56 else "latin1"
        string_value = decode_string_operand(
            data,
            current_offset + 1,
            newline_offset - current_offset - 1,
            encoding,
        )
        if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
          value_stack.append(string_value)
        if string_value is not None:
          yield constants.OPCODES_INFO_INT.get(opcode_byte), string_value
        current_offset = newline_offset + 1

      # Two newline-terminated strings for module and attribute names
      case 0x63 | 0x69:
        module_newline = _read_newline(data, current_offset + 1, current_offset)
        name_newline = _read_newline(data, module_newline + 1, current_offset)
        module_name = data[current_offset + 1 : module_newline].decode(
            "utf-8", errors="ignore"
        )
        attribute_name = data[module_newline + 1 : name_newline].decode(
            "utf-8", errors="ignore"
        )
        if opcode_byte == 0x69:
          if mark_stack:
            mark_position = mark_stack.pop()
            del value_stack[mark_position:]
          else:
            value_stack.clear()
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        yield opcode_info, module_name
        yield opcode_info, attribute_name
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
        try:
          memo_key = int(
              bytes(data[current_offset + 1 : newline_offset]).rstrip(b"\r"), 0
          )
          memo_table[memo_key] = value_stack[-1] if value_stack else None
        except ValueError:
          pass
        current_offset = newline_offset + 1

      # Protocol 0 GET (newline-terminated decimal memo index)
      case 0x67:
        newline_offset = _read_newline(data, current_offset + 1, current_offset)
        try:
          memo_key = int(
              bytes(data[current_offset + 1 : newline_offset]).rstrip(b"\r"), 0
          )
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(memo_table.get(memo_key))
        except ValueError:
          if len(value_stack) < MAX_ABSTRACT_STACK_SIZE:
            value_stack.append(None)
        current_offset = newline_offset + 1

      # Newline-terminated non-string numeric and persistent ID arguments
      case 0x49 | 0x46 | 0x4C | 0x50:
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

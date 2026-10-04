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
    Iterator,
    Optional,
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


def create_pattern(strings: FrozenSet[str]) -> re.Pattern[str]:
  """Creates a pattern for matching method calls from a list of strings.

  Args:
    strings: The strings to match.

  Returns:
    A pattern for matching method calls.
  """
  included = "|".join(set(map(re.escape, strings)))
  return re.compile(
      rf"""
        (?<![a-zA-Z0-9_])(?:{included})(?![a-zA-Z0-9_])  # Match the initial library name as a whole word
        (?:\.(?:[a-zA-Z_]+))* # Match zero or more chained attributes
        (?:\.(?:__\w+__|[a-zA-Z_]\w*))* # Match zero or more chained method calls with underscores
        \b
        """,
      re.VERBOSE,
  )


def create_pattern_for_unknowns(strings: FrozenSet[str]) -> re.Pattern[str]:
  """Creates a pattern for matching method calls excluding substrings from the list of strings.

  Args:
    strings: The strings to exclude in matching.

  Returns:
    A pattern string for matching unknown method calls.
  """

  excluded = "|".join(set(map(re.escape, strings)))
  return re.compile(
      rf"""
        \b(?<!\.)
        (?!(?:{excluded})\b)    # Negative lookahead to exclude known strings
        (                       # Capture the unknown method call
            [a-zA-Z_][a-zA-Z0-9_]*        # Match module/class name
            (?:\.[a-zA-Z_][a-zA-Z0-9_]*)* # Match zero or more chained attributes
        )
        \b
        """,
      re.VERBOSE,
  )


safe_pattern = create_pattern(constants.SAFE_STRINGS)
unsafe_pattern = create_pattern(constants.UNSAFE_STRINGS)
suspicious_pattern = create_pattern(constants.SUSPICIOUS_STRINGS)
unknown_pattern = create_pattern_for_unknowns(constants.ALL_STRINGS)

# Precompiled regex patterns for categorize_strings
EXTRACT_UNSAFE_MODULE_REGEX = re.compile(r"warning: (.*?) is unsafe")
ARGS_REGEX = re.compile(
    r"\<class '(.*?)'\>.*?unexpected arguments [({](.*)[)}]"
)

PYTHON_METHOD_PATTERNS = frozenset({
    re.compile(r"(\w+\.\w+\(\))"),  # Method Calls (a.b())
    re.compile(r"(\w+)\("),  # Function Calls (a())
    re.compile(r"[b]?['\"](\w+)['\"]"),  # String Arguments (like 'system')
})


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
        # Fallback to pickle copy
        logging.warning(
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
    return {member for member, _ in inspect.getmembers(imported_module)}

  if (spec := importlib.util.find_spec(module_name)) is None:
    return None
  if (origin := spec.origin) is None:
    return None

  try:
    with open(origin, "r") as f:
      tree = ast.parse(f.read(), filename=origin)
  except (IOError, ValueError, SyntaxError, RecursionError):
    return None

  members = set()
  # This generates the list of methods and classes in the module from
  # the AST tree of the module source file.
  for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
      members.add(node.name)
    elif isinstance(node, ast.ClassDef):
      members.add(node.name)
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


@functools.lru_cache(maxsize=None)
def classify_class_name(class_name: str) -> Classification | None:
  """Classifies a class name based on the safe, unsafe, and suspicious patterns."""
  # An exact list membership is more specific than a pattern match, so honor it
  # first (most dangerous wins). Otherwise a specific unsafe entry like
  # "pydoc.pipepager" is masked by the safe pattern for its module ("pydoc"),
  # while a specific safe entry like "shutil.disk_usage" still beats the unsafe
  # pattern for its module ("shutil"). This matches _classify_item's ordering.
  if class_name in constants.UNSAFE_STRINGS:
    return Classification.UNSAFE
  if class_name in constants.SUSPICIOUS_STRINGS:
    return Classification.SUSPICIOUS
  if class_name in constants.SAFE_STRINGS:
    return Classification.SAFE
  if re.search(safe_pattern, class_name):
    return Classification.SAFE
  if re.search(unsafe_pattern, class_name):
    return Classification.UNSAFE
  if re.search(suspicious_pattern, class_name):
    return Classification.SUSPICIOUS
  if re.search(unknown_pattern, class_name):
    return Classification.UNKNOWN
  return None


def is_unsafe_or_suspicious(class_name: str) -> bool:
  allow_list = config.get_allow_list()
  if any(
      allowed_item.startswith(class_name)
      or class_name.startswith(allowed_item)
      or allowed_item.endswith(f".{class_name}")
      for allowed_item in allow_list
  ):
    return False
  classification = classify_class_name(class_name)
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
    if "." in result:
      base_library = result.split(".", 1)[0]
      base_module = result.split(".", 1)[1]
      if base_library in final_results:
        libraries_to_remove.add(base_library)
      if base_module in final_results:
        modules_to_remove.add(base_module)

  final_results.difference_update(libraries_to_remove)
  final_results.difference_update(modules_to_remove)

  # Remove less specific versions of qualified modules.
  # Eg. Remove requests.api if requests.api.post is present.
  underspecific_qualified_modules_to_remove = set()
  for res in final_results:
    attribute_parts = res.split(".")
    # Check for less specific versions of the current item
    for i in range(1, len(attribute_parts)):
      parent = ".".join(attribute_parts[:i])
      if parent in final_results:
        underspecific_qualified_modules_to_remove.add(parent)

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


def _classify_item(item: str) -> Classification | None:
  """Classifies a single item string into a Classification enum."""
  if not item:
    return None
  if item in constants.UNSAFE_STRINGS:
    return Classification.UNSAFE
  if item in constants.SUSPICIOUS_STRINGS:
    return Classification.SUSPICIOUS
  if item in constants.SAFE_STRINGS:
    return Classification.SAFE
  return classify_class_name(item)


def _parse_and_process_pattern(
    line: str,
    pattern: re.Pattern[str],
    register_item: Callable[..., None],
    is_suspicious_override: bool = False,
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
    register_item(
        class_name,
        Classification.SUSPICIOUS if is_suspicious_override else None,
    )
    if method_name:
      register_item(f"{class_name}.{method_name}")
  if attr_name:
    register_item(attr_name)
  if module_name:
    register_item(module_name)

  combined_args = (args or state) + " " + kwargs
  if combined_args.strip():
    for group in re.findall(
        r"['\"](.*?)['\"]|([a-zA-Z_][a-zA-Z0-9_.]*(?:\(.*?\))?)", combined_args
    ):
      for token in group:
        if token:
          register_item(token)

  return True


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

  def register_item(item: str, override: Classification | None = None):
    cls = override or _classify_item(item)
    if cls is not None:
      results[cls].add(item)

  lines = filtered_output.getvalue().split("\n")
  for line in lines:
    if not line:
      continue

    if "Unsafe module/class invoked:" in line:
      match = re.search(
          r"Unsafe module/class invoked:\s*([a-zA-Z0-9_.]+)", line
      )
      if match:
        full_name = match.group(1)
        results[Classification.UNSAFE].add(full_name)
        if "." in full_name:
          results[Classification.UNSAFE].add(full_name.split(".", 1)[0])
      continue

    if "Unknown module/class imported:" in line:
      match = re.search(
          r"Unknown module/class imported:\s*([a-zA-Z0-9_.]+)", line
      )
      if match:
        results[Classification.UNKNOWN].add(match.group(1))
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

    # Legacy fallback parsing
    if line.lower().startswith("warning"):
      match = re.search(
          r"Unsafe module/class invoked:\s*([a-zA-Z0-9_.]+)", line
      )
      if match:
        full_name = match.group(1)
        results[Classification.UNSAFE].add(full_name)
        if "." in full_name:
          results[Classification.UNSAFE].add(full_name.split(".", 1)[0])
    elif line.lower().startswith("<"):
      class_args_match = ARGS_REGEX.search(line.lower())
      if class_args_match:
        register_item(class_args_match.group(1))
        class_args = class_args_match.group(2)
        for method_pattern in PYTHON_METHOD_PATTERNS:
          for argument_find in method_pattern.findall(class_args):
            register_item(argument_find)

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


_decode_string_operand = decode_string_operand


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


def partition_pickle_chunks(
    data: bytes | mmap.mmap,
    target_chunk_size: int,
    end: int | None = None,
) -> list[tuple[int, int]]:
  """Partitions pickle bytes into opcode-aligned chunk slices.

  Scans opcode boundaries so large pickle buffers can be partitioned across
  multiple threads without splitting multi-byte opcodes or string arguments.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    target_chunk_size: Desired byte size for each worker partition chunk.
    end: Optional upper byte bound limiting the scan range.

  Returns:
    A list of tuples (chunk_start, chunk_end) defining slice ranges.
  """
  effective_length = len(data) if end is None else min(end, len(data))
  chunk_starts = [0]
  current_offset = 0
  strides = OPCODE_STRIDES

  while current_offset < effective_length:
    opcode_byte = data[current_offset]
    stride = strides[opcode_byte]
    if stride > 0:
      if opcode_byte == 0x2E:
        break
      current_offset += stride
    else:
      match opcode_byte:
        # 1-byte length prefix (SHORT_BINUNICODE, SHORT_BINBYTES, etc.)
        case 0x8C | 0x43 | 0x8A:
          current_offset += 2 + data[current_offset + 1]
        # 4-byte length prefix (BINUNICODE, BINBYTES, BINBYTES8_SHORT)
        case 0x58 | 0x42 | 0x8B:
          current_offset += 5 + int.from_bytes(
              data[current_offset + 1 : current_offset + 5], "little"
          )
        # 8-byte length prefix (BINUNICODE8, BINBYTES8, BYTEARRAY8)
        case 0x8D | 0x8E | 0x96:
          current_offset += 9 + int.from_bytes(
              data[current_offset + 1 : current_offset + 9], "little"
          )
        # Newline-terminated opcodes (INT, FLOAT, LONG, STRING, etc.)
        case 0x49 | 0x46 | 0x4C | 0x70 | 0x67 | 0x50 | 0x56 | 0x53:
          if (newline_offset := data.find(b"\n", current_offset + 1)) == -1:
            break
          current_offset = newline_offset + 1
        # Two newline-terminated strings for module and attribute (GLOBAL, INST)
        case 0x63 | 0x69:
          if (first_newline := data.find(b"\n", current_offset + 1)) == -1 or (
              second_newline := data.find(b"\n", first_newline + 1)
          ) == -1:
            break
          current_offset = second_newline + 1
        # Unrecognized or single-byte variable opcode
        case _:
          current_offset += 1

    if (
        current_offset - chunk_starts[-1] >= target_chunk_size
        and current_offset < effective_length
    ):
      chunk_starts.append(current_offset)

  # Returns the chunks and indexes
  return [
      (
          chunk_starts[chunk_index],
          (
              chunk_starts[chunk_index + 1]
              if chunk_index + 1 < len(chunk_starts)
              else effective_length
          ),
      )
      for chunk_index in range(len(chunk_starts))
  ]


def custom_genops_from_bytes(
    data: bytes | mmap.mmap,
    start: int = 0,
    end: int | None = None,
) -> Iterator[tuple[Optional[pickletools.OpcodeInfo], Any | None]]:
  """Generates string-declaring opcodes and arguments from raw pickle bytes.

  Args:
    data: The raw pickle byte buffer or memory-mapped file.
    start: Byte offset to start parsing from.
    end: Optional byte offset upper limit for parsing.

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
        opcode_info = constants.OPCODES_INFO_INT.get(opcode_byte)
        yield opcode_info, module_name
        yield opcode_info, attribute_name
        yield opcode_info, f"{module_name}.{attribute_name}"
        current_offset = name_newline + 1

      # Stack global resolution opcode referencing stack operands
      case 0x93:
        yield constants.OPCODES_INFO_INT.get(opcode_byte), "STACK_GLOBAL"
        current_offset += 1

      # Newline-terminated non-string numeric and memo arguments to skip
      case 0x49 | 0x46 | 0x4C | 0x70 | 0x67 | 0x50:
        current_offset = (
            _read_newline(data, current_offset + 1, current_offset) + 1
        )

      # Unrecognized single-byte opcode
      case _:
        current_offset += 1

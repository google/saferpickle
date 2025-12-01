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

"""Utility functions for safer_pickle."""

import ast
import functools
import importlib
import inspect
import io
import os
import re
import subprocess
import sys
import types
from typing import FrozenSet, Set
import zipfile

from absl import logging

from lib import constants


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


def is_zip_bytes(file_bytes: bytes) -> bool:
  """Checks if the provided bytes represent a zip file.

  Args:
    file_bytes: The bytes to check.

  Returns:
    True if the input is a zip file, False otherwise.
  """
  if not file_bytes:
    return False
  try:
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
      zf.namelist()
    return True
  except zipfile.BadZipFile:
    return False


def extract_zip_contents(file_bytes: bytes) -> list[tuple[str, bytes]]:
  """Extracts the list of files and their contents from a zip file.

  Args:
    file_bytes: The bytes of the zip file.

  Returns:
    A list of tuples, where each tuple contains the filename and its content.
  """
  contents = []
  with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
    for filename in zf.namelist():
      contents.append((filename, zf.read(filename)))
  return contents


def is_pickle_file(
    pickle_bytes: bytes | io.BytesIO, return_num_bytes_read: bool = False
) -> bool | tuple[bool, int]:
  """Checks if the provided bytes represent a valid pickle file.

  This function reads the beginning of the input byte stream, looking for
  valid pickle opcodes. It stops after reading a maximum number of bytes,
  defined by `_MAX_BYTES_TO_CHECK`, to avoid processing very large inputs.
  Do note that this is not foolproof and false positives are possible.

  Args:
      pickle_bytes: The bytes to check.
      return_num_bytes_read: If True, returns a tuple containing a boolean
        indicating if the file is a valid pickle file and the number of bytes
        read. Otherwise, it returns only the boolean.

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
  if isinstance(pickle_bytes, bytes):
    raw_bytes = pickle_bytes
    pickle_bytes = io.BytesIO(pickle_bytes)
  else:
    raw_bytes = pickle_bytes.getvalue()

  pickle_file_is_ascii = pickle_bytes.getvalue().isascii()

  if pickle_file_is_ascii:
    stripped_bytes = raw_bytes.lstrip()
    if stripped_bytes.startswith(
        constants.TEXT_BASED_PREFIXES
    ) or stripped_bytes.startswith(constants.CODE_KEYWORDS):
      if return_num_bytes_read:
        return (False, 0)
      return False

  if raw_bytes.startswith(constants.NON_PICKLE_MAGIC_BYTES):
    if return_num_bytes_read:
      return (False, 0)
    return False

  num_of_bytes_read = 0
  while True:
    charcode = pickle_bytes.read(1)

    num_of_bytes_read += 1
    if num_of_bytes_read > constants.MAX_BYTES_TO_CHECK:
      if return_num_bytes_read:
        return (True, num_of_bytes_read)
      return True

    opcode = constants.OPCODES_INFO.get(charcode.decode("latin-1"))
    if opcode is None:
      if not charcode:  # Indicates exhaustion of the data stream
        if return_num_bytes_read:
          return (True, num_of_bytes_read)
        return True
      continue

    if opcode.arg is None:
      continue
    try:
      _ = opcode.arg.reader(pickle_bytes)
    except (ValueError, TypeError, IndexError):
      if return_num_bytes_read:
        return (False, num_of_bytes_read)
      return False


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

  spec = importlib.util.find_spec(module_name)
  if not spec:
    return None

  if not os.path.exists(spec.origin):
    return None

  with open(spec.origin, "r") as f:
    try:
      tree = ast.parse(f.read(), filename=spec.origin)
    except (ValueError, SyntaxError):
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
  sys.executable = None
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
  py_interpreter_candidate = sys.argv[0]

  # If sys.executable is not set, we patch it with the interpreter path that
  # was passed to the subprocess. If the path is not valid, we patch it with an
  # empty string to indicate that it's invalid.
  if not sys.executable:
    valid_py_interpreter_path = get_interpreter_path_to_patch()

    for interpreter_path in [
        py_interpreter_candidate,
        valid_py_interpreter_path,
    ]:
      if (
          interpreter_path and os.path.exists(interpreter_path)
      ) and is_sys_executable_to_path_set(interpreter_path):
        return True

  logging.warning("Warning: sys.executable is not set to a valid interpreter.")
  return False

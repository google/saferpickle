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

"""Pickle hook to detect malicious content in pickle files."""

import concurrent.futures
import contextlib
import dataclasses
import functools
import importlib
import io
import logging as std_logging
import lzma
import math
from multiprocessing import shared_memory
import os
import pickle
import pickletools
import re
import sys
import tarfile
import tempfile
import threading
from typing import Any, BinaryIO, Callable, Dict, IO, Iterator, Optional, Set, Tuple
import zipfile

from absl import logging
from third_party.corrupy import picklemagic
from lib import config
from lib import constants
from lib import exceptions
from lib import utils

import multiprocessing

IllegalArgumentCombinationError = exceptions.IllegalArgumentCombinationError
StrictCheckError = exceptions.StrictCheckError
UnsafePickleDetectedError = exceptions.UnsafePickleDetectedError
MaxRecursionDepthExceededError = exceptions.MaxRecursionDepthExceededError


# Global flag for debug mode
DEBUG_MODE = False


IS_COLAB_ENABLED = "google.colab" in sys.modules


Classification = utils.Classification


@dataclasses.dataclass
class ScanResults:
  """Results from a pickle security scan."""

  safe_results: Set[str] = dataclasses.field(default_factory=set)
  unsafe_results: Set[str] = dataclasses.field(default_factory=set)
  suspicious_results: Set[str] = dataclasses.field(default_factory=set)
  unknown_results: Set[str] = dataclasses.field(default_factory=set)
  is_denylisted: bool = False


def _custom_genops(
    pickle_bytes: bytes,
) -> Iterator[tuple[pickletools.OpcodeInfo, Any | None]]:
  """Generates string-declaring opcodes and their arguments from pickle data.

  Args:
    pickle_bytes: The pickle data to generate opcodes from.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """

  if isinstance(pickle_bytes, bytes):
    pickle_file = io.BytesIO(pickle_bytes)
  else:
    pickle_file = pickle_bytes

  while True:
    charcode = pickle_file.read(1)
    if not charcode:  # Indicates exhaustion of the data stream
      break

    try:
      opcode = constants.OPCODES_INFO_INT.get(charcode[0])
    except IndexError:
      continue  # Skip invalid opcode bytes

    if opcode is None:
      # We skip processing unknown opcodes
      continue

    opcode_argument = None
    if opcode.arg is not None:
      try:
        opcode_argument = opcode.arg.reader(pickle_file)
      except (
          ValueError,
          IndexError,
          AttributeError,
          EOFError,
          TypeError,
          ImportError,
          pickle.UnpicklingError,
      ):
        # Continue if we can't read the argument
        continue

    # We only yield opcodes that declare strings and have arguments
    should_yield = False
    for relevant_opcode_substr in constants.OPCODE_SUBSTRS_THAT_DECLARE_STRINGS:
      if relevant_opcode_substr in opcode.name:
        should_yield = True
        break

    if (
        should_yield
        and opcode_argument is not None  # Exclude opcodes without arguments
    ):
      # This is to be careful while processing opcode arguments. This was
      # borrowed from what works in the chunked version.
      if isinstance(opcode_argument, (str, bytes)) and len(opcode_argument) > 1:
        yield opcode, opcode_argument
      elif isinstance(opcode_argument, tuple):
        yield opcode, opcode_argument

    if charcode == b".":
      break


def _custom_chunked_genops(
    pickle_file: IO[bytes],
    chunk_range: Tuple[int, int],
) -> Iterator[tuple[pickletools.OpcodeInfo, Any | None]]:
  """Generates string-declaring opcodes and arguments from a chunk.

  This function reads a specific byte range (chunk) of the pickle bytecode
  and yields opcodes that are known to declare strings, along with their
  arguments. It's designed to be used in parallel for large pickle files.

  Args:
    pickle_file: The pickle data stream to generate opcodes from.
    chunk_range: A tuple (start, end) defining the byte range to process.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """
  pickle_file.seek(chunk_range[0])

  while True:
    current_file_position = pickle_file.tell()
    if not (chunk_range[0] <= current_file_position < chunk_range[1]):
      break

    charcode = pickle_file.read(1)
    if not charcode:  # Indicates exhaustion of the data stream
      break

    try:
      opcode = constants.OPCODES_INFO_INT.get(charcode[0])
    except IndexError:
      continue  # Skip invalid opcode bytes

    if opcode is None:
      # We skip processing unknown opcodes
      if not charcode:
        break
      continue

    opcode_argument = None
    if opcode.arg is not None:
      pos_before_arg_read = pickle_file.tell()
      try:
        opcode_argument = opcode.arg.reader(pickle_file)
        new_pos = pickle_file.tell()

        # Ensure we don't read past the chunk boundary accidentally
        if new_pos > chunk_range[1]:
          pickle_file.seek(pos_before_arg_read)
          continue

      except (
          ValueError,
          IndexError,
          AttributeError,
          EOFError,
          TypeError,
          ImportError,
          pickle.UnpicklingError,
      ):
        # Continue if we can't read the argument within the chunk
        pickle_file.seek(pos_before_arg_read)
        continue

    # We only yield opcodes that declare strings and have arguments
    should_yield = False
    for relevant_opcode_substr in constants.OPCODE_SUBSTRS_THAT_DECLARE_STRINGS:
      if relevant_opcode_substr in opcode.name:
        should_yield = True
        break

    if (
        should_yield
        and opcode_argument is not None  # Exclude opcodes without arguments
    ):
      # Filter to ensure the argument is string-like if needed
      if isinstance(opcode_argument, (str, bytes)) and len(opcode_argument) > 1:
        yield opcode, opcode_argument
      elif isinstance(
          opcode_argument, tuple
      ):  # Sometimes these arguments are memoized tuples
        yield opcode, opcode_argument

    if charcode == b".":
      break


def _process_chunk_for_generate_ops(
    pickle_data_source: str | bytes,
    chunk_range: Tuple[int, int],
    is_shared_memory: bool = False,
    abort_event: Optional[Any] = None,
) -> Set[str]:
  """Helper function to process a chunk of pickle data."""
  chunked_operands = set()
  try:
    if is_shared_memory:
      shm = shared_memory.SharedMemory(name=pickle_data_source)
      try:
        # Use BytesIO on the memoryview for compatibility with
        # _custom_chunked_genops
        data_view = shm.buf
        with io.BytesIO(data_view) as f:
          for _, operand in _custom_chunked_genops(f, chunk_range):
            if abort_event and abort_event.is_set():
              break
            if operand is None:
              continue
            operand_str = str(operand)
            chunked_operands.add(operand_str)
            if abort_event:
              op_lower = operand_str.lower()
              if (
                  utils.classify_class_name(operand_str)
                  in (Classification.UNSAFE, Classification.SUSPICIOUS)
                  or any(u in op_lower for u in constants.UNSAFE_STRINGS)
                  or any(s in op_lower for s in constants.SUSPICIOUS_STRINGS)
              ):
                abort_event.set()
                break
      finally:
        shm.close()
    else:
      with open(pickle_data_source, "rb") as f:
        f.seek(chunk_range[0])
        chunk_data = f.read(chunk_range[1] - chunk_range[0])
        with io.BytesIO(chunk_data) as memory_f:
          for _, operand in _custom_chunked_genops(
              memory_f, (0, len(chunk_data))
          ):
            if abort_event and abort_event.is_set():
              break
            if operand is None:
              continue
            operand_str = str(operand)
            chunked_operands.add(operand_str)
            if abort_event:
              op_lower = operand_str.lower()
              if (
                  utils.classify_class_name(operand_str)
                  in (Classification.UNSAFE, Classification.SUSPICIOUS)
                  or any(u in op_lower for u in constants.UNSAFE_STRINGS)
                  or any(s in op_lower for s in constants.SUSPICIOUS_STRINGS)
              ):
                abort_event.set()
                break
  except StopIteration:
    pass
  return chunked_operands


def generate_ops_from_file(
    pickle_file_path: str,
    shm_name: Optional[str] = None,
    pickle_length: Optional[int] = None,
    fail_fast: bool = False,
) -> Set[str]:
  """Returns opcodes that declare strings from a path or shared memory.

  Args:
    pickle_file_path: The path to the pickle file.
    shm_name: Optional name of the shared memory block.
    pickle_length: Optional length of the pickle data.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    genops_output: The operands associated with the opcodes that declare
    strings.
  """
  filtered_operands = set()
  num_workers = utils.get_optimal_workers(pickle_length)

  if (
      pickle_length < constants.MIN_SIZE_FOR_CHUNKING
      or not utils.is_sys_executable_patched()
  ):
    if shm_name:
      shm = shared_memory.SharedMemory(name=shm_name)
      pickle_bytes = bytes(shm.buf[:pickle_length])
    else:
      with open(pickle_file_path, "rb") as f:
        pickle_bytes = f.read()
    try:
      for _, operand in _custom_genops(pickle_bytes):
        if operand is None:
          continue
        operand_str = str(operand)
        filtered_operands.add(operand_str)
        if fail_fast:
          op_lower = operand_str.lower()
          if (
              utils.classify_class_name(operand_str)
              in (Classification.UNSAFE, Classification.SUSPICIOUS)
              or any(u in op_lower for u in constants.UNSAFE_STRINGS)
              or any(s in op_lower for s in constants.SUSPICIOUS_STRINGS)
          ):
            break
    except StopIteration:
      pass
    return filtered_operands
  else:
    # Divide into constants.MAX_NUM_CHUNKS for larger files
    chunk_size = math.ceil(pickle_length / num_workers)
    ranges = []
    for chunk_index in range(num_workers):
      chunk_start_size = chunk_index * chunk_size
      # Extend the chunk end by CHUNK_OVERLAP, but don't exceed pickle_length
      chunk_end = min(
          chunk_start_size + chunk_size + constants.CHUNK_OVERLAP, pickle_length
      )
      if chunk_start_size < pickle_length:
        ranges.append((chunk_start_size, chunk_end))
      if chunk_end == pickle_length:
        break  # Last chunk reaches the end

    ctx = multiprocessing.get_context("spawn")
    manager = ctx.Manager() if fail_fast else None
    abort_event = manager.Event() if manager else None

    try:
      with concurrent.futures.ProcessPoolExecutor(
          max_workers=num_workers, mp_context=ctx
      ) as executor:
        future_to_range_tuple = {
            executor.submit(
                _process_chunk_for_generate_ops,
                shm_name if shm_name else pickle_file_path,
                range_tuple,
                is_shared_memory=bool(shm_name),
                abort_event=abort_event,
            ): range_tuple
            for range_tuple in ranges
        }
        for future in concurrent.futures.as_completed(future_to_range_tuple):
          try:
            chunk_results = future.result()
            filtered_operands.update(chunk_results)
            if fail_fast:
              has_blocked_operand = False
              for op in chunk_results:
                op_lower = op.lower()
                if (
                    utils.classify_class_name(op)
                    in (Classification.UNSAFE, Classification.SUSPICIOUS)
                    or any(u in op_lower for u in constants.UNSAFE_STRINGS)
                    or any(s in op_lower for s in constants.SUSPICIOUS_STRINGS)
                ):
                  has_blocked_operand = True
                  break
              if has_blocked_operand:
                if abort_event:
                  abort_event.set()
                for f in future_to_range_tuple:
                  f.cancel()
                break
          except (
              EOFError,
              ValueError,
              IndexError,
              TypeError,
          ) as exc:
            logging.exception(
                "Error processing chunk %s: %s",
                future_to_range_tuple[future],
                exc,
            )
    finally:
      if manager:
        manager.shutdown()

    return filtered_operands


def generate_ops(
    pickle_bytes: bytes | IO[bytes], fail_fast: bool = False
) -> Set[str]:
  """Returns string-declaring opcodes.

  Args:
    pickle_bytes: The pickle bytecode or stream to yield opcode information for.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    genops_output: The operands associated with the opcodes that declare
    strings.
  """

  filtered_operands = set()
  original_pos = None
  if not isinstance(pickle_bytes, bytes):
    original_pos = pickle_bytes.tell()

  try:
    try:
      for _, operand in _custom_genops(pickle_bytes):
        if operand is None:
          continue
        operand_str = str(operand)
        filtered_operands.add(operand_str)
        if fail_fast:
          op_lower = operand_str.lower()
          if (
              utils.classify_class_name(operand_str)
              in (Classification.UNSAFE, Classification.SUSPICIOUS)
              or any(u in op_lower for u in constants.UNSAFE_STRINGS)
              or any(s in op_lower for s in constants.SUSPICIOUS_STRINGS)
          ):
            break
    except StopIteration:
      pass
    return filtered_operands
  finally:
    if original_pos is not None:
      pickle_bytes.seek(original_pos)


def get_class_instantiations(
    pickle_bytes: bytes | BinaryIO,
) -> tuple[io.StringIO, bool, bool]:
  """Gets the class instantiations from a pickle file/stream.

  Args:
    pickle_bytes: The pickle bytecode or stream to disassemble.

  Returns:
    A tuple containing:
      - picklemagic_output: Suspicious function calls from picklemagic.
      - was_unsafe_build_blocked: A boolean indicating if a dangerous
        state assignment was blocked by the custom load_build hook.
      - has_scan_error: A boolean indicating if the sandbox unpickler raised
        an exception.
  """
  picklemagic_output = io.StringIO()
  unpickler = None
  has_scan_error = False

  # Configure temporary log handler to capture picklemagic logs safely
  handler = std_logging.StreamHandler(picklemagic_output)
  handler.setFormatter(std_logging.Formatter("%(message)s"))
  logger = std_logging.getLogger("corrupy.picklemagic")
  logger.addHandler(handler)
  original_level = logger.level
  logger.setLevel(std_logging.WARNING)
  original_propagate = logger.propagate
  logger.propagate = False

  # Handle stream seek-back if necessary
  original_pos = None
  if isinstance(pickle_bytes, bytes):
    pickle_stream = io.BytesIO(pickle_bytes)
  else:
    original_pos = pickle_bytes.tell()
    pickle_stream = pickle_bytes

  try:
    try:
      factory = picklemagic.FakeClassFactory([], picklemagic.FakeWarning)

      # Instead of using safe_loads, we do this to get the
      # has_blocked_unsafe_build_instr boolean properly.
      unpickler = picklemagic.SafeUnpickler(
          pickle_stream,
          class_factory=factory,
          safe_modules=constants.SAFE_STRINGS,
          unsafe_modules=constants.UNSAFE_STRINGS,
      )
      factory.default.unpickler = unpickler

      # Monkey-patch load_build so that we don't miss
      # BUILD instructions due to differing Pickle implementations.
      original_load_build = unpickler.load_build

      def fixed_load_build(*unused_args):
        return original_load_build()

      unpickler.load_build = fixed_load_build
      unpickler.dispatch[pickle.BUILD[0]] = unpickler.load_build

      unpickler.load()

    except (
        ValueError,
        AttributeError,
        TypeError,
        picklemagic.FakeUnpicklingError,
        pickle.UnpicklingError,
        IndexError,
        EOFError,
        KeyError,
    ) as e:
      logging.warning("Sandbox unpickling failed: %s", e)
      has_scan_error = True
  finally:
    logger.removeHandler(handler)
    logger.setLevel(original_level)
    logger.propagate = original_propagate
    if original_pos is not None:
      pickle_bytes.seek(original_pos)

  is_build_instr_blocked = False
  if unpickler:
    is_build_instr_blocked = getattr(
        unpickler, "has_blocked_unsafe_build_instr", False
    )
  return picklemagic_output, is_build_instr_blocked, has_scan_error


def _parse_unsafe_module_class(line: str, unsafe_results: Set[str]):
  """Parses 'Unsafe module/class invoked' logs.

  Args:
    line: The log line to parse.
    unsafe_results: A set to add any found unsafe modules/classes to.
  """
  match = re.search(
      r"Unsafe module/class invoked: ([a-zA-Z0-9_.]+)\.([a-zA-Z0-9_]+)", line
  )
  if match:
    module, name = match.groups()
    unsafe_results.add(f"{module}.{name}")
    unsafe_results.add(module)
  else:
    module_match = re.search(
        r"Unsafe module/class invoked: ([a-zA-Z0-9_]+)", line
    )
    if module_match:
      module = module_match.group(1)
      unsafe_results.add(module)


def _parse_unknown_import(line: str, unknown_results: Set[str]):
  """Parses 'Unknown module/class imported' logs.

  Args:
    line: The log line to parse.
    unknown_results: A set to add any found unknown modules/classes to.
  """
  match = re.search(r"Unknown module/class imported: ([a-zA-Z0-9_.]+)", line)
  if match:
    unknown_results.add(match.group(1))


def _classify_item(
    item: str,
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    safe_results: Set[str],
    unknown_results: Set[str],
):
  """Classifies a single item string.

  Args:
    item: The string item to classify.
    unsafe_results: A set to add unsafe items to.
    suspicious_results: A set to add suspicious items to.
    safe_results: A set to add safe items to.
    unknown_results: A set to add unknown items to.
  """
  if not item:
    return

  if item in constants.UNSAFE_STRINGS:
    unsafe_results.add(item)
    return
  if item in constants.SUSPICIOUS_STRINGS:
    suspicious_results.add(item)
    return
  if item in constants.SAFE_STRINGS:
    safe_results.add(item)
    return

  # Fallback to classification based on name patterns
  classification = utils.classify_class_name(item)
  if classification == Classification.SAFE:
    safe_results.add(item)
  elif classification == Classification.UNSAFE:
    unsafe_results.add(item)
  elif classification == Classification.SUSPICIOUS:
    suspicious_results.add(item)
  else:
    unknown_results.add(item)


def _scan_args_kwargs(
    args_str: str,
    kwargs_str: str,
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    safe_results: Set[str],
    unknown_results: Set[str],
):
  """Scans arguments and keyword arguments for unsafe strings.

  Args:
    args_str: A string representation of positional arguments.
    kwargs_str: A string representation of keyword arguments.
    unsafe_results: A set to add any found unsafe strings to.
    suspicious_results: A set to add any found suspicious strings to.
    safe_results: A set to add any found safe strings to.
    unknown_results: A set to add any found unknown strings to.
  """
  combined = args_str + " " + kwargs_str

  # Extract string literals, identifiers, and potential method calls
  elements = re.findall(
      r"['\"](.*?)['\"]|([a-zA-Z_][a-zA-Z0-9_.]*(?:\(.*?\))?)", combined
  )

  for group in elements:
    for item in group:
      if item:
        _classify_item(
            item,
            unsafe_results,
            suspicious_results,
            safe_results,
            unknown_results,
        )


def _process_classified_match(
    items_to_classify: list[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    safe_results: Set[str],
    unknown_results: Set[str],
    suspicious_items: list[str] | None = None,
    args: str = "",
    kwargs: str = "",
):
  """Classifies items, adds suspicious items, and scans arguments.

  Args:
    items_to_classify: A list of strings to classify.
    unsafe_results: A set to add any found unsafe strings to.
    suspicious_results: A set to add any found suspicious strings to.
    safe_results: A set to add any found safe strings to.
    unknown_results: A set to add any found unknown strings to.
    suspicious_items: Optional list of strings to add to suspicious results.
    args: Optional string representation of positional arguments.
    kwargs: Optional string representation of keyword arguments.
  """
  for item in items_to_classify:
    _classify_item(
        item,
        unsafe_results,
        suspicious_results,
        safe_results,
        unknown_results,
    )
  if suspicious_items:
    for item in suspicious_items:
      suspicious_results.add(item)
  if args or kwargs:
    _scan_args_kwargs(
        args,
        kwargs,
        unsafe_results,
        suspicious_results,
        safe_results,
        unknown_results,
    )


def _parse_and_process_pattern(
    line: str,
    pattern: re.Pattern[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    safe_results: Set[str],
    unknown_results: Set[str],
    is_suspicious_override: bool = False,
) -> bool:
  """Parses a log line using a named group regex and processes the matches.

  Expected named groups in the pattern:
  - class_name: The name of the class or function involved.
  - method_name: The name of the method called.
  - attr_name: The attribute being accessed.
  - module_name: The module being accessed.
  - args: Positional arguments string.
  - kwargs: Keyword arguments string.
  - state: State string (treated as args).

  Args:
    line: The log line to parse.
    pattern: Regex pattern with named groups.
    unsafe_results: A set to add unsafe items to.
    suspicious_results: A set to add suspicious items to.
    safe_results: A set to add safe items to.
    unknown_results: A set to add unknown items to.
    is_suspicious_override: If True, adds the class_name to suspicious items.

  Returns:
    True if the pattern matched, False otherwise.
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

  items_to_classify = []
  suspicious_items = []

  if class_name:
    items_to_classify.append(class_name)
  if class_name and method_name:
    items_to_classify.append(f"{class_name}.{method_name}")
  if attr_name:
    items_to_classify.append(attr_name)
  if module_name:
    items_to_classify.append(module_name)

  if is_suspicious_override and class_name:
    suspicious_items.append(class_name)

  _process_classified_match(
      items_to_classify,
      unsafe_results,
      suspicious_results,
      safe_results,
      unknown_results,
      suspicious_items=suspicious_items if suspicious_items else None,
      args=args or state,
      kwargs=kwargs,
  )
  return True


def _categorize_picklemagic(
    filtered_output: io.StringIO,
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
  """Helper to parse and categorize picklemagic output."""
  safe_results: Set[str] = set()
  unsafe_results: Set[str] = set()
  suspicious_results: Set[str] = set()
  unknown_results: Set[str] = set()

  lines = filtered_output.getvalue().split("\n")
  for line in lines:
    if not line:
      continue

    if "Unsafe module/class invoked:" in line:
      _parse_unsafe_module_class(line, unsafe_results)
      continue
    if "Unknown module/class imported:" in line:
      _parse_unknown_import(line, unknown_results)
      continue

    matched_pattern = False
    for keyword, pattern, is_override in utils.PICKLEMAGIC_PATTERNS:
      if keyword in line:
        if _parse_and_process_pattern(
            line,
            pattern,
            unsafe_results,
            suspicious_results,
            safe_results,
            unknown_results,
            is_suspicious_override=is_override,
        ):
          matched_pattern = True
          break

    if matched_pattern:
      continue

    # Legacy parsing (in case of raw prints or legacy format)
    if line.lower().startswith("warning"):
      _parse_unsafe_module_class(line, unsafe_results)
    elif line.lower().startswith("<"):
      class_args_match = utils.ARGS_REGEX.search(line.lower())
      if class_args_match:
        class_name = class_args_match.group(1)
        _classify_item(
            class_name,
            unsafe_results,
            suspicious_results,
            safe_results,
            unknown_results,
        )
        class_args = class_args_match.group(2)
        for method_pattern in utils.PYTHON_METHOD_PATTERNS:
          argument_finds = method_pattern.findall(class_args)
          for argument_find in argument_finds:
            _classify_item(
                argument_find,
                unsafe_results,
                suspicious_results,
                safe_results,
                unknown_results,
            )

  return safe_results, unsafe_results, suspicious_results, unknown_results


def _categorize_genops(
    filtered_output: Set[str],
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
  """Helper to categorize genops output."""
  safe_results: Set[str] = set()
  unsafe_results: Set[str] = set()
  suspicious_results: Set[str] = set()
  unknown_results: Set[str] = set()

  for line in filtered_output:
    line_in_lowercase = line.lower()
    unsafe_match = any(
        unsafe_string in line_in_lowercase
        for unsafe_string in constants.UNSAFE_STRINGS
    ) and re.findall(utils.unsafe_pattern, line_in_lowercase)
    safe_match = any(
        safe_string in line_in_lowercase
        for safe_string in constants.SAFE_STRINGS
    ) and re.findall(utils.safe_pattern, line_in_lowercase)
    suspicious_match = any(
        suspicious_string in line_in_lowercase
        for suspicious_string in constants.SUSPICIOUS_STRINGS
    ) and re.findall(utils.suspicious_pattern, line_in_lowercase)

    if unsafe_match:
      for match in unsafe_match:
        unsafe_results.add(match)
    elif safe_match:
      for match in safe_match:
        safe_results.add(match)
    elif suspicious_match:
      for match in suspicious_match:
        suspicious_results.add(match)
    else:
      # Only check for unknown if no other categories matched
      unknown_match = re.findall(utils.unknown_pattern, line_in_lowercase)
      if unknown_match:
        for match in unknown_match:
          unknown_results.add(match)

  return safe_results, unsafe_results, suspicious_results, unknown_results


def _reclassify_with_resolution(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> ScanResults:
  """Helper to resolve modules and re-classify results."""
  allow_list = config.get_allow_list()
  deny_list = config.get_deny_list()

  # Combine results for `resolve_library_modules_from_results` call.
  all_results = safe_results.union(
      unsafe_results, suspicious_results, unknown_results
  )
  resolved_results = utils.resolve_library_modules_from_results(all_results)

  # Re-categorize the resolved results
  new_safe_results = set()
  new_unsafe_results = set()
  new_suspicious_results = set()
  new_unknown_results = set()
  is_denylisted = False

  for result in resolved_results:
    if any(result.startswith(denied_item) for denied_item in deny_list):
      new_unsafe_results.add(result)
      is_denylisted = True
      continue

    if any(result.startswith(allowed_item) for allowed_item in allow_list):
      new_safe_results.add(result)
      continue

    if result == "builtins":
      new_unknown_results.add(result)
      continue

    # Classify the resolved result
    classification = utils.classify_class_name(result)

    if classification == Classification.SAFE:
      new_safe_results.add(result)
    elif classification == Classification.UNSAFE:
      new_unsafe_results.add(result)
    elif classification == Classification.SUSPICIOUS:
      new_suspicious_results.add(result)
    elif classification == Classification.UNKNOWN:
      # Fallback: Check against original categories if
      # classify_class_name returns UNKNOWN.
      if result in unsafe_results:
        new_unsafe_results.add(result)
      elif result in suspicious_results:
        new_suspicious_results.add(result)
      elif result in safe_results:
        new_safe_results.add(result)
      else:
        new_unknown_results.add(result)

  return ScanResults(
      safe_results=new_safe_results,
      unsafe_results=new_unsafe_results,
      suspicious_results=new_suspicious_results,
      unknown_results=new_unknown_results,
      is_denylisted=is_denylisted,
  )


def categorize_strings(
    filtered_output: Set[str] | io.StringIO,
    use_picklemagic: bool = False,
) -> ScanResults:
  """Counts strings from filtered output and categorizes them."""
  if use_picklemagic and isinstance(filtered_output, io.StringIO):
    safe, unsafe, suspicious, unknown = _categorize_picklemagic(filtered_output)
  else:
    safe, unsafe, suspicious, unknown = _categorize_genops(filtered_output)
  return _reclassify_with_resolution(safe, unsafe, suspicious, unknown)


def strict_security_scan(pickle_bytes: bytes | BinaryIO) -> bool:
  """Strict security scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.

  Returns:
    True if the pickle file is dangerous, False otherwise.
  """

  original_pos = None
  if not isinstance(pickle_bytes, bytes):
    original_pos = pickle_bytes.tell()

  try:
    unsafe_and_suspicious_strings = constants.UNSAFE_STRINGS.union(
        constants.SUSPICIOUS_STRINGS
    )
    for _, operand in _custom_genops(pickle_bytes):
      if operand is None:
        continue
      stmt = str(operand)
      for pattern in unsafe_and_suspicious_strings:
        if re.search(pattern, stmt):
          return True

    # Seek back the stream before running picklemagic
    if original_pos is not None and hasattr(pickle_bytes, "seek"):
      try:
        pickle_bytes.seek(original_pos)
      except (OSError, AttributeError, io.UnsupportedOperation):
        logging.debug("Failed to seek back stream before picklemagic scan.")

    # The below handles catching cases of unknown imports and state attacks.
    instantiations_output, was_unsafe_build_blocked, has_scan_error = (
        get_class_instantiations(pickle_bytes)
    )

    if was_unsafe_build_blocked or has_scan_error:
      return True

    instantiations = instantiations_output.getvalue().split("\n")
    for instantiation in instantiations:
      if re.search(utils.unknown_pattern, instantiation):
        return True
      # This is a noisy but necessary check for a small number of cases where
      # a library is not explicitly imported but is used in a class instantiation
      # in a suspicious manner.
      if re.search(utils.suspicious_pattern, instantiation):
        return True
  finally:
    if original_pos is not None and hasattr(pickle_bytes, "seek"):
      try:
        pickle_bytes.seek(original_pos)
      except (OSError, AttributeError, io.UnsupportedOperation):
        logging.debug("Failed to reset file pointer after strict scan.")

  return False


def is_unsafe(
    number_of_safe_results: int,
    number_of_unsafe_results: int,
    number_of_suspicious_results: int,
) -> bool:
  """Conditional check for safeness.

  Args:
    number_of_safe_results: Number of safe results from the security scan.
    number_of_unsafe_results: Number of unsafe results from the security scan.
    number_of_suspicious_results: Number of suspicious results from the security
      scan.

  Returns:
    True if the pickle file is dangerous, False otherwise.
  """
  if number_of_unsafe_results == 0 and number_of_suspicious_results == 0:
    return False

  # We halve the weight of suspicious results to lower false positives
  # caused by greedy matches of unknown method-like strings (Ex. "google.com")
  if (
      number_of_suspicious_results + number_of_unsafe_results
      >= number_of_safe_results
  ):
    return True

  sum_of_unsafe_and_suspicious_results = (
      number_of_unsafe_results + 0.5 * number_of_suspicious_results
  )

  unsafe = (sum_of_unsafe_and_suspicious_results > number_of_safe_results) or (
      number_of_safe_results == 0 and sum_of_unsafe_and_suspicious_results >= 1
  )

  return unsafe


def picklemagic_scan(
    pickle_bytes: bytes,
) -> ScanResults:
  """Picklemagic scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    A ScanResults object.
  """
  picklemagic_output, was_unsafe_build_blocked, has_scan_error = (
      get_class_instantiations(pickle_bytes)
  )

  results = categorize_strings(picklemagic_output, use_picklemagic=True)

  if was_unsafe_build_blocked:
    # Temporary addition to increase number of suspicious results given the
    # current scoring implementation. This will be removed in the future.
    results.suspicious_results.add("unsafe_state_assignment")
  if has_scan_error:
    results.unsafe_results.add("sandbox_unpickling_error")

  return results


def genops_scan(
    pickle_bytes: bytes,
    pickle_file_path: Optional[str] = None,
    shm_name: Optional[str] = None,
    fail_fast: bool = False,
) -> ScanResults:
  """Genops scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    shm_name: Optional name of the shared memory block.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    A ScanResults object.
  """
  if shm_name:
    genops_output = generate_ops_from_file(
        "",
        shm_name=shm_name,
        pickle_length=len(pickle_bytes),
        fail_fast=fail_fast,
    )
  elif pickle_file_path:
    genops_output = generate_ops_from_file(
        pickle_file_path, pickle_length=len(pickle_bytes), fail_fast=fail_fast
    )
  else:
    genops_output = generate_ops(pickle_bytes, fail_fast=fail_fast)
  results = categorize_strings(genops_output)
  return results


def score_results(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> Tuple[int, int, int, int]:
  """Count the results from the security scan.

  Args:
    safe_results: List of safe strings.
    unsafe_results: List of unsafe strings.
    suspicious_results: List of suspicious strings.
    unknown_results: List of unknown strings.

  Returns:
    A tuple of safe, unsafe, suspicious, and unknown scores.
  """

  number_of_safe_results = len(safe_results)
  number_of_unsafe_results = len(unsafe_results)
  number_of_suspicious_results = len(suspicious_results)
  number_of_unknown_results = len(unknown_results)

  safe_score = math.log(number_of_safe_results + 1) * 2
  unsafe_score = math.log(number_of_unsafe_results + 1) * 4
  suspicious_score = math.log(number_of_suspicious_results + 1) * 3
  unknown_score = math.log(number_of_unknown_results + 1) * 1

  return (
      round(safe_score),
      round(unsafe_score),
      round(suspicious_score),
      round(unknown_score),
  )


def apply_approach(
    scan_approach: Callable[..., ScanResults],
    pickle_bytes: bytes,
    pickle_file_path: Optional[str] = None,
    shm_name: Optional[str] = None,
    fail_fast: bool = False,
) -> Dict[str, int]:
  """Applies the given scan approach to the data.

  Args:
    scan_approach: The scan approach to apply to the data.
    pickle_bytes: The data to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    shm_name: Optional name of the shared memory block.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    A dictionary of the resulting scores.
  """
  if scan_approach is genops_scan:
    results = scan_approach(
        pickle_bytes,
        pickle_file_path=pickle_file_path,
        shm_name=shm_name,
        fail_fast=fail_fast,
    )
  else:
    results = scan_approach(pickle_bytes)

  if DEBUG_MODE:
    logging.info("Scan approach: %s", scan_approach.__name__)
    logging.info("  Safe results: %s", results.safe_results)
    logging.info("  Unsafe results: %s", results.unsafe_results)
    logging.info("  Suspicious results: %s", results.suspicious_results)
    logging.info("  Unknown results: %s\n", results.unknown_results)

  (
      number_of_safe_results,
      number_of_unsafe_results,
      number_of_suspicious_results,
      number_of_unknown_results,
  ) = score_results(
      results.safe_results,
      results.unsafe_results,
      results.suspicious_results,
      results.unknown_results,
  )
  scores = {
      "unsafe": number_of_unsafe_results,
      "suspicious": number_of_suspicious_results,
      "unknown": number_of_unknown_results,
  }
  if results.is_denylisted or is_unsafe(
      number_of_safe_results,
      number_of_unsafe_results,
      number_of_suspicious_results,
  ):
    return scores

  scores["unsafe"] = 0
  scores["suspicious"] = 0
  return scores


def security_scan(
    pickle_bytes: bytes | IO[bytes],
    force_scan: bool = False,
    recursion_depth: int = 0,
    fail_fast: bool = False,
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    recursion_depth: Current recursion depth for nested archives.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    results.
  """
  if recursion_depth > 10:
    raise MaxRecursionDepthExceededError("Max recursion depth of 10 exceeded.")
  if recursion_depth > 3:
    logging.warning("Suspiciously deep recursion depth of %d", recursion_depth)

  original_pos = None
  if not isinstance(pickle_bytes, bytes):
    original_pos = pickle_bytes.tell()

  try:
    is_archive = False
    if not isinstance(pickle_bytes, bytes):
      # Peek first 262 bytes to identify archive streams
      current_pos = pickle_bytes.tell()
      header = pickle_bytes.read(262)
      pickle_bytes.seek(current_pos)
      if header.startswith(
          (b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x1f\x8b")
      ) or (len(header) >= 262 and header[257:262] == b"ustar"):
        is_archive = True

    if is_archive:
      # Temporarily read non-seekable or seekable archive stream fully to bytes (pre-utils-streaming fallback)
      archive_bytes = pickle_bytes.read()
      return _extract_and_scan_archive(
          archive_bytes,
          "zip"
          if archive_bytes.startswith(b"PK\x03\x04")
          else "bz2"
          if archive_bytes.startswith(b"BZh")
          else "lzma"
          if archive_bytes.startswith(b"\xfd7zXZ\x00")
          else "gzip"
          if archive_bytes.startswith(b"\x1f\x8b")
          else "tar",
          recursion_depth,
          force_scan,
          fail_fast=fail_fast,
      )

    # Check for compression signatures if input was raw bytes
    if isinstance(pickle_bytes, bytes):
      if utils.is_zip_bytes(pickle_bytes):
        return _extract_and_scan_archive(
            pickle_bytes,
            "zip",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
        )
      elif utils.is_bz2_bytes(pickle_bytes):
        return _extract_and_scan_archive(
            pickle_bytes,
            "bz2",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
        )
      elif utils.is_lzma_bytes(pickle_bytes):
        return _extract_and_scan_archive(
            pickle_bytes,
            "lzma",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
        )
      elif utils.is_gzip_bytes(pickle_bytes):
        return _extract_and_scan_archive(
            pickle_bytes,
            "gzip",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
        )
      elif utils.is_tar_bytes(pickle_bytes):
        return _extract_and_scan_archive(
            pickle_bytes,
            "tar",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
        )

    return _security_scan_internal(
        pickle_bytes, force_scan, fail_fast=fail_fast
    )
  finally:
    if original_pos is not None:
      pickle_bytes.seek(original_pos)


def _merge_scores(total: Dict[str, int], new: Dict[str, int]):
  total["unsafe"] += new.get("unsafe", 0)
  total["suspicious"] += new.get("suspicious", 0)
  total["unknown"] += new.get("unknown", 0)


def _extract_and_scan_archive(
    data: bytes | IO[bytes],
    archive_type: str,
    recursion_depth: int,
    force_scan: bool = False,
    fail_fast: bool = False,
) -> Dict[str, int]:
  """Extracts and scans contents of an archive."""
  if not isinstance(data, bytes):
    data = data.read()

  all_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}

  try:
    if archive_type == "zip":
      with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
          if ".." in name or name.startswith("/"):
            # Zip slip detection
            logging.warning("Zip slip detected: %s", name)
            return {
                "unsafe": constants.HIGH_SEVERITY_ZIPSLIP,
                "suspicious": 0,
                "unknown": 0,
            }  # Return early

          with zf.open(name) as f:
            content = f.read()
            scores = security_scan(
                content,
                force_scan=force_scan,
                recursion_depth=recursion_depth + 1,
                fail_fast=fail_fast,
            )
            _merge_scores(all_scores, scores)

    elif archive_type == "bz2":
      content = utils.extract_bz2_contents(data)
      scores = security_scan(
          content,
          force_scan=force_scan,
          recursion_depth=recursion_depth + 1,
          fail_fast=fail_fast,
      )
      _merge_scores(all_scores, scores)

    elif archive_type == "lzma":
      content = utils.extract_lzma_contents(data)
      scores = security_scan(
          content,
          force_scan=force_scan,
          recursion_depth=recursion_depth + 1,
          fail_fast=fail_fast,
      )
      _merge_scores(all_scores, scores)

    elif archive_type == "gzip":
      content = utils.extract_gzip_contents(data)
      scores = security_scan(
          content,
          force_scan=force_scan,
          recursion_depth=recursion_depth + 1,
          fail_fast=fail_fast,
      )
      _merge_scores(all_scores, scores)

    elif archive_type == "tar":
      for name, content in utils.extract_tar_contents(data):
        if ".." in name or name.startswith("/"):
          logging.warning("Tar slip detected: %s", name)
          return {
              "unsafe": constants.HIGH_SEVERITY_ZIPSLIP,
              "suspicious": 0,
              "unknown": 0,
          }  # Return early
        scores = security_scan(
            content,
            force_scan=force_scan,
            recursion_depth=recursion_depth + 1,
            fail_fast=fail_fast,
        )
        _merge_scores(all_scores, scores)

    else:
      logging.warning("Unsupported archive type: %s", archive_type)
      return {
          "unsafe": 0,
          "suspicious": 0,
          "unknown": constants.HIGH_SEVERITY_ZIPSLIP,
      }

  except MaxRecursionDepthExceededError:
    raise
  except (
      zipfile.BadZipFile,
      tarfile.TarError,
      lzma.LZMAError,
      OSError,
      EOFError,
      ValueError,
  ) as e:
    logging.exception("Error processing %s archive: %s", archive_type, e)
    # Block file if extraction fails to prevent security bypass
    return {
        "unsafe": constants.HIGH_SEVERITY_ZIPSLIP,
        "suspicious": 0,
        "unknown": 0,
    }

  return all_scores


def _security_scan_internal(
    pickle_bytes: bytes | IO[bytes],
    force_scan: bool = False,
    fail_fast: bool = False,
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    finds.
  """
  is_stream = isinstance(pickle_bytes, io.IOBase)

  # Get pickle length safely without loading all into memory
  if is_stream:
    try:
      current_pos = pickle_bytes.tell()
      pickle_bytes.seek(0, io.SEEK_END)
      pickle_length = pickle_bytes.tell()
      pickle_bytes.seek(current_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      # Read only on unsupported seek fallback
      data = pickle_bytes.read()
      pickle_bytes = io.BytesIO(data)
      pickle_length = len(data)
      is_stream = True
  else:
    pickle_length = len(pickle_bytes)

  is_pickle = False
  if is_stream:
    try:
      current_pos = pickle_bytes.tell()
      header_bytes = pickle_bytes.read(1024)
      pickle_bytes.seek(current_pos)
      is_pickle = utils.is_pickle_file(header_bytes)
    except Exception:
      is_pickle = False
  else:
    is_pickle = utils.is_pickle_file(pickle_bytes)

  if not is_pickle and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  pickle_file_path = None
  shm = None
  shm_name = None

  if pickle_length >= constants.MIN_SIZE_FOR_CHUNKING:
    try:
      shm = shared_memory.SharedMemory(create=True, size=pickle_length)
      shm_name = shm.name

      # Copy to shared memory in 1MB chunks
      if is_stream:
        offset = 0
        current_pos = pickle_bytes.tell()
        pickle_bytes.seek(0)
        try:
          while True:
            chunk = pickle_bytes.read(1024 * 1024)
            if not chunk:
              break
            shm.buf[offset : offset + len(chunk)] = chunk
            offset += len(chunk)
        finally:
          pickle_bytes.seek(current_pos)
      else:
        shm.buf[:pickle_length] = pickle_bytes
    except OSError:
      # Fallback to tempfile with chunked buffering
      with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        pickle_file_path = temp_file.name
        if is_stream:
          current_pos = pickle_bytes.tell()
          pickle_bytes.seek(0)
          try:
            while True:
              chunk = pickle_bytes.read(1024 * 1024)
              if not chunk:
                break
              temp_file.write(chunk)
          finally:
            pickle_bytes.seek(current_pos)
        else:
          temp_file.write(pickle_bytes)

  original_stream_pos = None
  if is_stream:
    try:
      original_stream_pos = pickle_bytes.tell()
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass

  try:
    final_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}
    for scan_approach in [picklemagic_scan, genops_scan]:
      scores = apply_approach(
          scan_approach,
          pickle_bytes,
          pickle_file_path,
          shm_name,
          fail_fast=fail_fast,
      )
      # Restore stream pointer after each scan approach to prevent EOF errors
      if (
          is_stream
          and original_stream_pos is not None
          and hasattr(pickle_bytes, "seek")
      ):
        try:
          pickle_bytes.seek(original_stream_pos)
        except (OSError, AttributeError, io.UnsupportedOperation):
          logging.debug("Failed to restore stream pointer inside scan loop.")

      if scores["unsafe"] > 0 or scores["suspicious"] > 0:
        return scores
      final_scores["unknown"] += scores["unknown"]
    return final_scores
  finally:
    # Ensure stream is seeked back before exiting so load_func gets a clean stream
    if (
        is_stream
        and original_stream_pos is not None
        and hasattr(pickle_bytes, "seek")
    ):
      try:
        pickle_bytes.seek(original_stream_pos)
      except (OSError, AttributeError, io.UnsupportedOperation):
        logging.debug("Failed to restore stream pointer before exiting scan.")

    if shm:
      shm.close()
      shm.unlink()
    if pickle_file_path:
      os.remove(pickle_file_path)


_ORIG_METHODS_BEFORE_HOOKING = {}
_HOOKING_LOCK = threading.Lock()


def _report_or_raise(
    classification: Classification, report_only: bool, log_info=False
):
  """Reports or raises an error based on classification and report_only flag."""

  if report_only:
    logging_function = logging.info if log_info else logging.error
    logging_function(
        constants.ERROR_STRING.substitute(classification=classification.value)
    )
    return
  raise UnsafePickleDetectedError(
      constants.ERROR_STRING.substitute(classification=classification.value)
  )


def _is_ipc_caller() -> bool:
  """Checks if the caller of the load is multiprocessing or concurrent.futures."""
  try:
    frame = sys._getframe()
    f = frame
    files = []
    while f:
      files.append(f.f_code.co_filename)
      f = f.f_back
    print(f"ST_FILES: {files}")

    f1 = frame.f_back
    f2 = f1.f_back if f1 else None
    f3 = f2.f_back if f2 else None
    if f3:
      f3_file = f3.f_code.co_filename
      if "multiprocessing" in f3_file or "concurrent/futures" in f3_file:
        return True
      f4 = f3.f_back
      if f4:
        f4_file = f4.f_code.co_filename
        if "multiprocessing" in f4_file or "concurrent/futures" in f4_file:
          return True
  except Exception:  # pylint: disable=broad-except
    pass
  return False


def _scan_ipc_pickle(pickle_source: bytes | io.IOBase) -> bool:
  """Returns True if the pickle tries to load anything outside the strict sandbox."""
  original_pos = None
  if not isinstance(pickle_source, bytes):
    try:
      original_pos = pickle_source.tell()
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass

  try:
    if isinstance(pickle_source, bytes):
      pickle_bytes = pickle_source
    else:
      try:
        pickle_source.seek(0)
        pickle_bytes = pickle_source.read()
      finally:
        if original_pos is not None:
          try:
            pickle_source.seek(original_pos)
          except (OSError, AttributeError, io.UnsupportedOperation):
            pass

    # Parse opcodes using _custom_genops
    for _, operand in _custom_genops(pickle_bytes):
      if operand is None:
        continue

      if isinstance(operand, tuple):
        check_list = [str(x) for x in operand]
      else:
        check_list = [str(operand)]

      for name in check_list:
        name_lower = name.lower()
        if name_lower in (
            "os",
            "posix",
            "nt",
            "sys",
            "subprocess",
            "shutil",
            "builtins",
            "__builtin__",
        ):
          if name_lower not in ("builtins", "__builtin__"):
            return True

        if "." in name:
          base_module = name.split(".", 1)[0]
          if (
              base_module
              not in (
                  "builtins",
                  "__builtin__",
                  "collections",
                  "multiprocessing",
                  "concurrent",
                  "copyreg",
              )
              and "safer_pickle" not in name_lower
              and "saferpickle" not in name_lower
          ):
            return True
  except Exception:  # pylint: disable=broad-except
    return True  # Fail secure if parsing fails
  return False


def _scan_and_load(
    pickle_file_or_bytes: io.IOBase | bytes,
    allow_unsafe: bool,
    strict_check: bool,
    report_only: bool,
    force_scan: bool,
    hooked_mod_name: str,
    is_load: bool,
    log_info: bool,
    *args: Any,
    **kwargs: Any,
):
  """Internal helper to scan and load pickle data."""

  if is_load:
    if not isinstance(pickle_file_or_bytes, io.IOBase):
      raise TypeError("pickle_file_or_bytes must be IOBase when is_load=True")

    pickle_file = pickle_file_or_bytes

    # Dynamically handle non-seekable streams
    try:
      is_seekable = pickle_file.seekable()
    except (AttributeError, ValueError):
      is_seekable = False

    if not is_seekable:
      # Fallback: read non-seekable stream into a seekable BytesIO
      # We only read it fully when seek is not supported
      data_bytes = pickle_file.read()
      pickle_file = io.BytesIO(data_bytes)

    scan_source = pickle_file
  else:
    if not isinstance(pickle_file_or_bytes, bytes):
      raise TypeError("pickle_file_or_bytes must be bytes when is_load=False")
    data_bytes = pickle_file_or_bytes
    scan_source = data_bytes
    pickle_file = None

  loader_mod = COPIED_MODS_MAP.get(hooked_mod_name)
  if not loader_mod:
    loader_mod = pickle_copy

  if is_load:
    load_func = loader_mod.load
    load_args = (pickle_file,)
  else:
    load_func = loader_mod.loads
    load_args = (data_bytes,)

  if _is_ipc_caller():
    if _scan_ipc_pickle(scan_source):
      raise UnsafePickleDetectedError(
          "Unsanctioned object inside internal IPC pickle channel."
      )
    # If the IPC check passes, bypass standard scan and load directly
    return load_func(*load_args, *args, **kwargs)

  if strict_check and allow_unsafe:
    error_string_illegal_combination = (
        "Strict scanning and allow_unsafe cannot be used together."
    )
    if report_only:
      logging.error(error_string_illegal_combination)
      return
    raise IllegalArgumentCombinationError(error_string_illegal_combination)
  elif allow_unsafe:
    if report_only:
      logging.info("Loading pickle file with allow_unsafe set to True.")
  elif strict_check:
    if strict_security_scan(scan_source):
      error_string_strict_check = "Pickle file failed strict security check."
      if report_only:
        logging.error(error_string_strict_check)
        return
      raise StrictCheckError(error_string_strict_check)
  else:
    # Default scanning routines
    scan_scores = security_scan(scan_source, force_scan=force_scan)
    number_of_unsafe_results = scan_scores["unsafe"]
    number_of_suspicious_results = scan_scores["suspicious"]
    number_of_unknown_results = scan_scores["unknown"]

    if number_of_suspicious_results == 0 and number_of_unsafe_results == 0:
      if report_only:
        logging.info("Loading safe pickle file")
        if number_of_unknown_results > 0:
          logging.warning(
              "SaferPickle: File contains %d unknown items that were ignored.",
              number_of_unknown_results,
          )
    elif number_of_unsafe_results > number_of_suspicious_results:
      _report_or_raise(Classification.UNSAFE, report_only, log_info)
    else:
      _report_or_raise(Classification.SUSPICIOUS, report_only, log_info)

  # Load the pickle if report_only is True and no exceptions were raised earlier
  try:
    return load_func(*load_args, *args, **kwargs)
  except (
      AttributeError,
      pickle.UnpicklingError,
      ModuleNotFoundError,
      EOFError,
      ImportError,
  ) as exc:
    logging.debug(
        "Safe pickle failed to load due to environmental constraints: %s",
        exc,
        exc_info=True,
    )
    raise


def hook_pickle(
    force_report_only: bool = False,
    log_info: bool = False,
    config_path: Optional[str] = None,
) -> None:
  """This implements the hooking of pickle-like libraries."""
  config.set_config_path(config_path)

  def custom_loads(
      pickle_bytes: bytes,
      allow_unsafe: bool = False,
      strict_check: bool = False,
      report_only: bool = False,
      force_scan: bool = False,
      hooked_mod_name: str = "",
      *args: Any,
      **kwargs: Any,
  ) -> Any:
    """Custom loads function for pickle to security scan before loading pickle files.

    Args:
      pickle_bytes: The pickle file bytes to load.
      allow_unsafe: If True, allow unsafe pickle files to be loaded.
      strict_check: If True, perform a strict security check on the pickle file.
      report_only: If True, only report errors and do not raise them.
      force_scan: If True, force scan even if the file is not a pickle file.
      hooked_mod_name: The name of the hooked module that called this function.
      *args: Additional arguments to pass to pickle.loads.
      **kwargs: Additional keyword arguments to pass to pickle.loads.

    Returns:
      None if we are in report_only mode and the pickle file is unsafe.
      Result of loader_mod.loads if pickle file is safe.

    Raises:
      IllegalArgumentCombinationError: If both allow_unsafe and strict_check are
      set to True.
      StrictCheckError: If the pickle file fails the strict security check.
      UnsafePickleDetectedError: If the pickle file is unsafe.

    Logs:
      If report_only is True, logs the above raised exceptions and unknown
      results.
      Logs if an absent class is encountered. We return even if benign.
    """
    if force_report_only:
      report_only = True
    return _scan_and_load(
        pickle_bytes,
        allow_unsafe,
        strict_check,
        report_only,
        force_scan,
        hooked_mod_name,
        False,
        log_info,
        *args,
        **kwargs,
    )

  def custom_load(
      pickle_file: io.IOBase,
      allow_unsafe: bool = False,
      strict_check: bool = False,
      report_only: bool = False,
      force_scan: bool = False,
      hooked_mod_name: str = "",
      *args: Any,
      **kwargs: Any,
  ) -> Any:
    """Custom load function for pickle to security scan before loading pickle files.

    Args:
      pickle_file: The file-like object to load from.
      allow_unsafe: If True, allow unsafe pickle files to be loaded.
      strict_check: If True, perform a strict security check on the pickle file.
      report_only: If True, only report errors and do not raise them.
      force_scan: If True, force scan even if the file is not a pickle file.
      hooked_mod_name: The name of the hooked module that called this function.
      *args: Additional arguments to pass to pickle.load.
      **kwargs: Additional keyword arguments to pass to pickle.load.

    Returns:
      None if we are in report_only mode and the pickle file is unsafe.
      result of loader_mod.load if pickle file is safe.

    Raises:
      IllegalArgumentCombinationError: If both allow_unsafe and strict_check are
      set to True.
      StrictCheckError: If the pickle file fails the strict security check.
      UnsafePickleDetectedError: If the pickle file is unsafe.

    Logs:
      If report_only is True, logs the above raised exceptions and unknown
      results.
      Logs if an absent class is encountered. We return even if benign.
    """
    if force_report_only:
      report_only = True
    return _scan_and_load(
        pickle_file,
        allow_unsafe,
        strict_check,
        report_only,
        force_scan,
        hooked_mod_name,
        True,
        log_info,
        *args,
        **kwargs,
    )

  # The main hooking routine
  hookable_mods: Set[str] = set([
      "_pickle",
      "joblib",
      "cloudpickle",
      "torch",
      "pickle",
      "dill",
  ])

  for hookable_mod in hookable_mods:
    if sys.modules.get(hookable_mod):
      module = sys.modules[hookable_mod]
    else:
      logging.debug("%s DOES NOT exist in sys.modules", hookable_mod)
      logging.debug("Importing %s now", hookable_mod)
      try:
        # Imports are necessary for hooking to work
        module = importlib.import_module(hookable_mod)
      except (ImportError, ModuleNotFoundError):
        logging.debug("Failed to import %s", hookable_mod)
        continue

    with _HOOKING_LOCK:
      if hookable_mod not in _ORIG_METHODS_BEFORE_HOOKING:
        _ORIG_METHODS_BEFORE_HOOKING[hookable_mod] = {}

      methods_to_patch = {
          "load": functools.partial(custom_load, hooked_mod_name=hookable_mod),
          "_load": functools.partial(custom_load, hooked_mod_name=hookable_mod),
          "loads": functools.partial(
              custom_loads, hooked_mod_name=hookable_mod
          ),
          "_loads": functools.partial(
              custom_loads, hooked_mod_name=hookable_mod
          ),
      }
      for method_name, custom_func in methods_to_patch.items():
        if hasattr(module, method_name):
          if method_name not in _ORIG_METHODS_BEFORE_HOOKING[hookable_mod]:
            _ORIG_METHODS_BEFORE_HOOKING[hookable_mod][method_name] = getattr(
                module, method_name
            )
          setattr(module, method_name, custom_func)


@contextlib.contextmanager
def hook_pickle_libs(
    report_only: bool = True,
    log_info: bool = False,
    config_path: Optional[str] = None,
) -> Iterator[None]:
  """Context manager that hooks pickle on entry and unhooks on exit.

  Args:
      report_only: If True, hooks will only log errors instead of raising them.
      log_info: If True, use logging.info instead of logging.error for
        reporting.
      config_path: Optional path to a JSON config file for the allow-list.
  """
  hook_pickle(
      force_report_only=report_only, log_info=log_info, config_path=config_path
  )
  try:
    yield
  finally:
    unhook_pickle()


def unhook_pickle() -> None:
  """Unhooks the pickle-like libraries."""
  with _HOOKING_LOCK:
    for module_name, methods in _ORIG_METHODS_BEFORE_HOOKING.items():
      try:
        module = importlib.import_module(module_name)
        for method_name, original_method in methods.items():
          if hasattr(module, method_name):
            setattr(module, method_name, original_method)
      except (ImportError, ModuleNotFoundError):
        logging.debug("Failed to import %s for unhooking", module_name)
        continue
    # Empty stored methods to avoid re-unhooking on a second unhook call
    _ORIG_METHODS_BEFORE_HOOKING.clear()


# To avoid creating __pycache__ files
sys.dont_write_bytecode: bool = True

# Makes copies for the libraries we wish to hook to avoid recursion conflicts
pickle_copy = utils.copy_module("_pickle", "pickle_copy")
dill_copy = utils.copy_module("dill", "dill_copy")
joblib_copy = utils.copy_module("joblib", "joblib_copy")
cloudpickle_copy = utils.copy_module("cloudpickle", "cloudpickle_copy")
torch_copy = utils.copy_module("torch", "torch_copy")

# This must succeed, otherwise we cannot continue with any hooking
if pickle_copy is None:
  sys.exit(1)

# This is a map of modules to their copies, if the copy fails, we fall back to
# the pickle copy.
COPIED_MODS_MAP = {
    "pickle": pickle_copy,
    "_pickle": pickle_copy,
    "dill": dill_copy if dill_copy else pickle_copy,
    "joblib": joblib_copy if joblib_copy else pickle_copy,
    "cloudpickle": cloudpickle_copy if cloudpickle_copy else pickle_copy,
    "torch": torch_copy if torch_copy else pickle_copy,
}

REQUIRED_COPIES = frozenset(["pickle", "_pickle"])

for mod_name, mod_copy in COPIED_MODS_MAP.items():
  if mod_copy is None:
    if mod_name in REQUIRED_COPIES:
      sys.exit(1)
    else:
      logging.warning(
          "%s could not be imported, functionality may be limited.", mod_name
      )


def load(
    pickle_file: Any,
    allow_unsafe: bool = False,
    strict_check: bool = False,
    report_only: bool = False,
    force_scan: bool = False,
    log_info: bool = False,
    *args: Any,
    **kwargs: Any,
) -> Any:
  """Custom load function to security scan before loading pickle files.

  This function can be used as a replacement for pickle.load or torch.load,
  providing security scan features.

  Args:
    pickle_file: The pickle file to load.
    allow_unsafe: If True, allow unsafe pickle files to be loaded.
    strict_check: If True, perform a strict security check on the pickle file.
    report_only: If True, only report errors and do not raise them.
    force_scan: If True, force scan even if the file is not a pickle file.
    log_info: If True, use logging.info instead of logging.error for reporting.
    *args: Additional arguments to pass to torch.load.
    **kwargs: Additional keyword arguments to pass to torch.load.

  Returns:
    The unpickled object or None if the pickle file is unsafe and report_only is
    True.

  Raises:
    UnsafePickleDetectedError: If the pickle file is unsafe.
  """
  return _scan_and_load(
      pickle_file,
      allow_unsafe,
      strict_check,
      report_only,
      force_scan,
      "torch",
      True,
      log_info,
      *args,
      **kwargs,
  )


class Unpickler(pickle.Unpickler):
  """Custom unpickler class to security scan before unpickling."""

  def __init__(
      self,
      file: Any,
      allow_unsafe: bool = False,
      strict_check: bool = False,
      report_only: bool = False,
      force_scan: bool = False,
      log_info: bool = False,
      *args: Any,
      **kwargs: Any,
  ):
    super().__init__(file, *args, **kwargs)
    self.file = file
    self.args = args
    self.kwargs = kwargs
    self._allow_unsafe = allow_unsafe
    self._strict_check = strict_check
    self._report_only = report_only
    self._force_scan = force_scan
    self._log_info = log_info

  def load(self) -> Any:
    """Security scan before loading pickle files."""
    return _scan_and_load(
        self.file,
        self._allow_unsafe,
        self._strict_check,
        self._report_only,
        self._force_scan,
        "pickle",
        True,
        self._log_info,
        *self.args,
        **self.kwargs,
    )


if __name__ == "__main__":
  if IS_COLAB_ENABLED:
    hook_pickle()

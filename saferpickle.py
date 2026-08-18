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
import struct
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


DEFAULT_FAIL_FAST = True


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
      if charcode in constants.LENGTH_PREFIXED_OPCODES:
        try:
          match charcode:
            case c if c in constants.OPCODES_4BYTE_LEN:
              length = int.from_bytes(pickle_file.read(4), byteorder="little")
            case c if c in constants.OPCODES_8BYTE_LEN:
              length = int.from_bytes(pickle_file.read(8), byteorder="little")
            case c if c in constants.OPCODES_1BYTE_LEN:
              length = int.from_bytes(pickle_file.read(1), byteorder="little")
            case _:
              length = 0
          pickle_file.seek(length, os.SEEK_CUR)
        except (AttributeError, io.UnsupportedOperation, OSError):
          try:
            opcode_argument = opcode.arg.reader(pickle_file)
          except (ValueError, pickle.UnpicklingError) as e:
            raise UnsafePickleDetectedError(
                f"Parser error during security scan: {e}"
            ) from e
          except (
              IndexError,
              AttributeError,
              EOFError,
              TypeError,
              ImportError,
          ):
            continue
      else:
        try:
          opcode_argument = opcode.arg.reader(pickle_file)
        except (ValueError, pickle.UnpicklingError) as e:
          raise UnsafePickleDetectedError(
              f"Parser error during security scan: {e}"
          ) from e
        except (
            IndexError,
            AttributeError,
            EOFError,
            TypeError,
            ImportError,
        ):
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

      except (ValueError, pickle.UnpicklingError) as e:
        raise UnsafePickleDetectedError(
            f"Parser error during security scan: {e}"
        ) from e
      except (
          IndexError,
          AttributeError,
          EOFError,
          TypeError,
          ImportError,
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
      shm = shared_memory.SharedMemory(name=pickle_data_source)  # pyrefly: ignore[bad-argument-type]
      try:
        # Use BytesIO on the memoryview for compatibility with
        # _custom_chunked_genops
        data_view = shm.buf
        with io.BytesIO(data_view) as f:  # pyrefly: ignore[bad-argument-type]
          for _, operand in _custom_chunked_genops(f, chunk_range):
            if abort_event and abort_event.is_set():
              break
            if operand is None:
              continue
            operand_str = str(operand)
            chunked_operands.add(operand_str)
            if abort_event:
              if utils.is_unsafe_or_suspicious(operand_str):
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
              if utils.is_unsafe_or_suspicious(operand_str):
                abort_event.set()
                break
  except StopIteration:
    pass
  return chunked_operands


def generate_ops_from_file(
    pickle_file_path: str,
    shm_name: Optional[str] = None,
    pickle_length: Optional[int] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
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
  num_workers = utils.get_optimal_workers(pickle_length)  # pyrefly: ignore[bad-argument-type]

  if (
      pickle_length < constants.MIN_SIZE_FOR_CHUNKING  # pyrefly: ignore[unsupported-operation]
      or not utils.is_sys_executable_patched()
  ):
    if shm_name:
      shm = shared_memory.SharedMemory(name=shm_name)
      pickle_bytes = bytes(shm.buf[:pickle_length])  # pyrefly: ignore[unsupported-operation]
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
          if utils.is_unsafe_or_suspicious(operand_str):
            break
    except StopIteration:
      pass
    return filtered_operands
  else:
    # Divide into constants.MAX_NUM_CHUNKS for larger files
    chunk_size = math.ceil(pickle_length / num_workers)  # pyrefly: ignore[unsupported-operation]
    ranges = []
    for chunk_index in range(num_workers):
      chunk_start_size = chunk_index * chunk_size
      # Extend the chunk end by CHUNK_OVERLAP, but don't exceed pickle_length
      chunk_end = min(  # pyrefly: ignore[bad-specialization]
          chunk_start_size + chunk_size + constants.CHUNK_OVERLAP, pickle_length
      )
      if chunk_start_size < pickle_length:  # pyrefly: ignore[unsupported-operation]
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
                if utils.is_unsafe_or_suspicious(op):
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
    pickle_bytes: bytes | IO[bytes],
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
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
      for _, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
        if operand is None:
          continue
        operand_str = str(operand)
        filtered_operands.add(operand_str)
        if fail_fast:
          if utils.is_unsafe_or_suspicious(operand_str):
            break
    except StopIteration:
      pass
    return filtered_operands
  finally:
    if original_pos is not None:
      pickle_bytes.seek(original_pos)  # pyrefly: ignore[missing-attribute]


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
        struct.error,
    ) as e:
      logging.warning("Sandbox unpickling failed: %s", e)
      has_scan_error = True
  finally:
    logger.removeHandler(handler)
    logger.setLevel(original_level)
    logger.propagate = original_propagate
    if original_pos is not None:
      pickle_bytes.seek(original_pos)  # pyrefly: ignore[missing-attribute]

  was_unsafe_build_blocked = False
  if unpickler:
    was_unsafe_build_blocked = getattr(
        unpickler, "has_blocked_unsafe_build_instr", False
    )

  return picklemagic_output, was_unsafe_build_blocked, has_scan_error


def categorize_strings(
    filtered_output: Set[str] | io.StringIO,
    use_picklemagic: bool = False,
) -> ScanResults:
  """Counts strings from filtered output and categorizes them."""
  if use_picklemagic and isinstance(filtered_output, io.StringIO):
    safe, unsafe, suspicious, unknown = utils.categorize_picklemagic(
        filtered_output
    )
  else:
    safe, unsafe, suspicious, unknown = _categorize_genops(filtered_output)  # pyrefly: ignore[bad-argument-type]
  return _reclassify_with_resolution(safe, unsafe, suspicious, unknown)


def _categorize_genops(
    filtered_output: Set[str],
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
  """Helper to categorize genops output."""
  safe_results: Set[str] = set()
  unsafe_results: Set[str] = set()
  suspicious_results: Set[str] = set()
  unknown_results: Set[str] = set()

  for line in filtered_output:
    # Match against the operand as-is. Python module and attribute names are
    # case-sensitive and the string lists / patterns are case-sensitive too, so
    # lowercasing here hides the mixed-case unsafe names (VirtualAlloc,
    # CreateThread, RtlMoveMemory, WaitForSingleObject, Crypto, ...) that a
    # global can carry.
    unsafe_match = any(
        unsafe_string in line
        for unsafe_string in constants.UNSAFE_STRINGS
    ) and re.findall(utils.unsafe_pattern, line)
    safe_match = any(
        safe_string in line
        for safe_string in constants.SAFE_STRINGS
    ) and re.findall(utils.safe_pattern, line)
    suspicious_match = any(
        suspicious_string in line
        for suspicious_string in constants.SUSPICIOUS_STRINGS
    ) and re.findall(utils.suspicious_pattern, line)

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
      unknown_match = re.findall(utils.unknown_pattern, line)
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

    if classification == utils.Classification.SAFE:
      new_safe_results.add(result)
    elif classification == utils.Classification.UNSAFE:
      new_unsafe_results.add(result)
    elif classification == utils.Classification.SUSPICIOUS:
      new_suspicious_results.add(result)
    elif classification == utils.Classification.UNKNOWN:
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
    for _, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
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
      # a library is not explicitly imported but is used in a
      # class instantiation in a suspicious manner.
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
    # Temporary addition to increase suspicious results count given the
    # current scoring implementation. This will be removed in the future.
    results.suspicious_results.add("unsafe_state_assignment")
  if has_scan_error:
    results.suspicious_results.add("sandbox_unpickling_error")

  return results


def genops_scan(
    pickle_bytes: bytes | IO[bytes],
    pickle_file_path: Optional[str] = None,
    shm_name: Optional[str] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> ScanResults:
  """Genops scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    shm_name: Optional name of the shared memory block.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data.

  Returns:
    A ScanResults object.
  """
  resolved_pickle_length = (
      pickle_length if pickle_length is not None else len(pickle_bytes)  # pyrefly: ignore[bad-argument-type]
  )
  if shm_name:
    genops_output = generate_ops_from_file(
        "",
        shm_name=shm_name,
        pickle_length=resolved_pickle_length,
        fail_fast=fail_fast,
    )
  elif pickle_file_path:
    genops_output = generate_ops_from_file(
        pickle_file_path,
        pickle_length=resolved_pickle_length,
        fail_fast=fail_fast,
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
    pickle_bytes: bytes | IO[bytes],
    pickle_file_path: Optional[str] = None,
    shm_name: Optional[str] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> Dict[str, int]:
  """Applies the given scan approach to the data.

  Args:
    scan_approach: The scan approach to apply to the data.
    pickle_bytes: The data to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    shm_name: Optional name of the shared memory block.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data.

  Returns:
    A dictionary of the resulting scores.
  """
  if scan_approach is genops_scan:
    results = scan_approach(
        pickle_bytes,
        pickle_file_path=pickle_file_path,
        shm_name=shm_name,
        fail_fast=fail_fast,
        pickle_length=pickle_length,
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
  should_fail_fast = fail_fast and (
      number_of_unsafe_results > 0 and number_of_suspicious_results == 0
  )
  if (
      results.is_denylisted
      or should_fail_fast
      or is_unsafe(
          number_of_safe_results,
          number_of_unsafe_results,
          number_of_suspicious_results,
      )
  ):
    return scores

  scores["unsafe"] = 0
  scores["suspicious"] = 0
  return scores


def security_scan(
    pickle_bytes: bytes | IO[bytes],
    force_scan: bool = False,
    recursion_depth: int = 0,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    recursion_depth: Current recursion depth for nested archives.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    check_magic_bytes: Whether to perform magic byte checks.

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
      # Temporarily archive streams fully to bytes
      archive_bytes = pickle_bytes.read()  # pyrefly: ignore[missing-attribute]
      if archive_bytes.startswith(b"PK\x03\x04"):
        archive_type = "zip"
      elif archive_bytes.startswith(b"BZh"):
        archive_type = "bz2"
      elif archive_bytes.startswith(b"\xfd7zXZ\x00"):
        archive_type = "lzma"
      elif archive_bytes.startswith(b"\x1f\x8b"):
        archive_type = "gzip"
      else:
        archive_type = "tar"
      return _extract_and_scan_archive(
          archive_bytes,
          archive_type,
          recursion_depth,
          force_scan,
          fail_fast=fail_fast,
          check_magic_bytes=check_magic_bytes,
      )

    # Check for compression signatures if input was raw bytes
    if isinstance(pickle_bytes, bytes):
      if pickle_bytes.startswith(b"PK\x03\x04"):
        return _extract_and_scan_archive(
            pickle_bytes,
            "zip",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
            check_magic_bytes=check_magic_bytes,
        )
      elif pickle_bytes.startswith(b"BZh"):
        return _extract_and_scan_archive(
            pickle_bytes,
            "bz2",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
            check_magic_bytes=check_magic_bytes,
        )
      elif pickle_bytes.startswith(b"\xfd7zXZ\x00"):
        return _extract_and_scan_archive(
            pickle_bytes,
            "lzma",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
            check_magic_bytes=check_magic_bytes,
        )
      elif pickle_bytes.startswith(b"\x1f\x8b"):
        return _extract_and_scan_archive(
            pickle_bytes,
            "gzip",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
            check_magic_bytes=check_magic_bytes,
        )
      elif len(pickle_bytes) >= 262 and pickle_bytes[257:262] == b"ustar":
        return _extract_and_scan_archive(
            pickle_bytes,
            "tar",
            recursion_depth,
            force_scan,
            fail_fast=fail_fast,
            check_magic_bytes=check_magic_bytes,
        )

    return _security_scan_internal(
        pickle_bytes,
        force_scan,
        fail_fast=fail_fast,
        check_magic_bytes=check_magic_bytes,
    )
  finally:
    if original_pos is not None:
      pickle_bytes.seek(original_pos)  # pyrefly: ignore[missing-attribute]


def _merge_scores(total: Dict[str, int], new: Dict[str, int]):
  total["unsafe"] += new.get("unsafe", 0)
  total["suspicious"] += new.get("suspicious", 0)
  total["unknown"] += new.get("unknown", 0)


def _extract_and_scan_archive(
    data: bytes | IO[bytes],
    archive_type: str,
    recursion_depth: int,
    force_scan: bool = False,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
) -> Dict[str, int]:
  """Extracts and scans contents of an archive."""
  if not isinstance(data, bytes):
    data = data.read()

  all_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}

  try:
    if archive_type == "zip":
      try:
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
                  check_magic_bytes=check_magic_bytes,
              )
              _merge_scores(all_scores, scores)
      except zipfile.BadZipFile as e:
        logging.warning("Error processing zip archive: %s", e)
        return {
            "unsafe": constants.HIGH_SEVERITY_ZIPSLIP,
            "suspicious": 0,
            "unknown": 0,
        }

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
            check_magic_bytes=check_magic_bytes,
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
    logging.warning("Error processing %s archive: %s", archive_type, e)
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
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    check_magic_bytes: Whether to perform magic byte checks.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    finds.
  """
  # Normalize to seekable stream and get length
  if isinstance(pickle_bytes, bytes):
    stream = io.BytesIO(pickle_bytes)
    pickle_length = len(pickle_bytes)
  else:
    stream = pickle_bytes
    try:
      is_seekable = stream.seekable()
    except (AttributeError, ValueError):
      is_seekable = False

    if not is_seekable:
      data = stream.read()
      stream = io.BytesIO(data)
      pickle_length = len(data)
    else:
      current_pos = stream.tell()
      stream.seek(0, io.SEEK_END)
      pickle_length = stream.tell()
      stream.seek(current_pos)

  # Check if pickle (always stream now)
  try:
    is_pickle = utils.is_pickle_file(
        stream, check_magic_bytes=check_magic_bytes
    )
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    is_pickle = False

  if not is_pickle and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  # Find actual start of valid pickle payload if it has leading garbage
  start_offset = 0
  try:
    current_pos = stream.tell()
    stream.seek(0)
    header_bytes = stream.read(1024)
    stream.seek(current_pos)
    is_archive = header_bytes.startswith(
        (b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x1f\x8b")
    ) or (len(header_bytes) >= 262 and header_bytes[257:262] == b"ustar")
    if not is_archive:
      start_offset = utils.find_pickle_start_offset(stream)
    else:
      start_offset = 0

    if start_offset > 0:
      stream.seek(start_offset)
      pickle_length -= start_offset
    else:
      stream.seek(current_pos)
  except (OSError, AttributeError, io.UnsupportedOperation):
    pass

  pickle_file_path = None
  shm = None
  shm_name = None

  if pickle_length >= constants.MIN_SIZE_FOR_CHUNKING:
    try:
      shm = shared_memory.SharedMemory(create=True, size=pickle_length)
      shm_name = shm.name

      # Fast path for BytesIO, chunked fallback for other streams
      if isinstance(stream, io.BytesIO):
        shm.buf[:pickle_length] = stream.getbuffer()[  # pyrefly: ignore[unsupported-operation]
            start_offset : start_offset + pickle_length
        ]
      else:
        offset = 0
        current_pos = stream.tell()
        stream.seek(start_offset)
        try:
          while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
              break
            shm.buf[offset : offset + len(chunk)] = chunk  # pyrefly: ignore[unsupported-operation]
            offset += len(chunk)
        finally:
          stream.seek(current_pos)
    except OSError:
      # Fallback to tempfile with chunked buffering
      with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        pickle_file_path = temp_file.name
        if isinstance(stream, io.BytesIO):
          temp_file.write(
              stream.getbuffer()[start_offset : start_offset + pickle_length]
          )
        else:
          current_pos = stream.tell()
          stream.seek(start_offset)
          try:
            while True:
              chunk = stream.read(1024 * 1024)
              if not chunk:
                break
              temp_file.write(chunk)
          finally:
            stream.seek(current_pos)

  original_stream_pos = None
  try:
    original_stream_pos = stream.tell()
  except (OSError, AttributeError, io.UnsupportedOperation):
    pass

  try:
    final_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}
    for scan_approach in [picklemagic_scan, genops_scan]:
      scores = apply_approach(
          scan_approach,
          stream,
          pickle_file_path,
          shm_name,
          fail_fast=fail_fast,
          pickle_length=pickle_length,
      )
      # Restore stream pointer after each scan approach to prevent EOF errors
      if original_stream_pos is not None and hasattr(stream, "seek"):
        try:
          stream.seek(original_stream_pos)
        except (OSError, AttributeError, io.UnsupportedOperation):
          logging.debug("Failed to restore stream pointer inside scan loop.")

      if scores["unsafe"] > 0 or scores["suspicious"] > 0:
        return scores
      final_scores["unknown"] += scores["unknown"]
    return final_scores
  finally:
    # Ensure stream is seeked back before exiting so load_func gets
    # a clean stream
    if original_stream_pos is not None and hasattr(stream, "seek"):
      try:
        stream.seek(original_stream_pos)
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
    classification: utils.Classification, report_only: bool, log_info=False
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


def _scan_and_load(
    pickle_file_or_bytes: io.IOBase | bytes,
    allow_unsafe: bool,
    strict_check: bool,
    report_only: bool,
    force_scan: bool,
    hooked_mod_name: str,
    is_load: bool,
    log_info: bool,
    check_magic_bytes: bool = True,
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

    try:
      current_pos = pickle_file.tell()
      pickle_file.seek(0)
      header_bytes = pickle_file.read(1024)
      is_archive = header_bytes.startswith(
          (b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x1f\x8b")
      ) or (len(header_bytes) >= 262 and header_bytes[257:262] == b"ustar")
      if not is_archive:
        start_offset = utils.find_pickle_start_offset(header_bytes)
      else:
        start_offset = 0

      if start_offset > 0:
        pickle_file.seek(start_offset)
      else:
        pickle_file.seek(current_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass

    scan_source = pickle_file
  else:
    if not isinstance(pickle_file_or_bytes, bytes):
      raise TypeError("pickle_file_or_bytes must be bytes when is_load=False")
    data_bytes = pickle_file_or_bytes
    is_archive = data_bytes.startswith(
        (b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x1f\x8b")
    ) or (len(data_bytes) >= 262 and data_bytes[257:262] == b"ustar")
    if not is_archive:
      start_offset = utils.find_pickle_start_offset(data_bytes)
    else:
      start_offset = 0

    if start_offset > 0:
      data_bytes = data_bytes[start_offset:]
    scan_source = data_bytes
    pickle_file = None

  loader_mod = utils.get_copied_module(hooked_mod_name or "_pickle")

  if is_load:
    load_func = loader_mod.load  # pyrefly: ignore[missing-attribute]
    load_args = (pickle_file,)
  else:
    load_func = loader_mod.loads  # pyrefly: ignore[missing-attribute]
    load_args = (data_bytes,)  # pyrefly: ignore[unbound-name]

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
    if strict_security_scan(scan_source):  # pyrefly: ignore[bad-argument-type]
      error_string_strict_check = "Pickle file failed strict security check."
      if report_only:
        logging.error(error_string_strict_check)
        return
      raise StrictCheckError(error_string_strict_check)
  else:
    # Default scanning routines
    scan_scores = security_scan(
        scan_source, force_scan=force_scan, check_magic_bytes=check_magic_bytes  # pyrefly: ignore[bad-argument-type]
    )
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
      _report_or_raise(utils.Classification.UNSAFE, report_only, log_info)
    else:
      _report_or_raise(utils.Classification.SUSPICIOUS, report_only, log_info)

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
      check_magic_bytes: bool = True,
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
      check_magic_bytes: Whether to perform magic byte checks to fast path
        reject files.
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
        check_magic_bytes,
        *args,
        **kwargs,
    )

  def custom_load(
      pickle_file: Any,
      allow_unsafe: bool = False,
      strict_check: bool = False,
      report_only: bool = False,
      force_scan: bool = False,
      hooked_mod_name: str = "",
      check_magic_bytes: bool = True,
      *args: Any,
      **kwargs: Any,
  ) -> Any:
    """Custom load function for pickle to security scan before loading pickle files.

    Args:
      pickle_file: The pickle file to load.
      allow_unsafe: If True, allow unsafe pickle files to be loaded.
      strict_check: If True, perform a strict security check on the pickle file.
      report_only: If True, only report errors and do not raise them.
      force_scan: If True, force scan even if the file is not a pickle file.
      hooked_mod_name: The name of the hooked module that called this function.
      check_magic_bytes: Whether to perform magic byte checks to fast path
        reject files.
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
        check_magic_bytes,
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

    # Force copy before patching to ensure we copy the unhooked version
    _ = utils.get_copied_module(hookable_mod)

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


def load(
    pickle_file: Any,
    allow_unsafe: bool = False,
    strict_check: bool = False,
    report_only: bool = False,
    force_scan: bool = False,
    log_info: bool = False,
    check_magic_bytes: bool = True,
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
    check_magic_bytes: Whether to perform magic byte checks to fast path reject
      files.
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
      check_magic_bytes,
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
      check_magic_bytes: bool = True,
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
    self._check_magic_bytes = check_magic_bytes

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
        self._check_magic_bytes,
        *self.args,
        **self.kwargs,
    )


if __name__ == "__main__":
  if IS_COLAB_ENABLED:
    hook_pickle()

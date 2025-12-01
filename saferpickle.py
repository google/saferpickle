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
import enum
import functools
import importlib
import io
import math
import pickle
import pickletools
import re
import sys
import threading
from typing import Any, Callable, Dict, Iterator, Optional, Set, Tuple

from absl import logging
from third_party.corrupy import picklemagic

import multiprocessing
from lib import config
from lib import constants
from lib import utils


class IllegalArgumentCombinationError(Exception):
  """Custom exception for using allow_unsafe and strict_check together."""

  def __init__(self, m: str) -> None:
    self.message = m

  def __str__(self) -> str:
    return self.message


class StrictCheckError(Exception):
  """Custom exception for strict check failures."""

  def __init__(self, m: str) -> None:
    self.message = m

  def __str__(self) -> str:
    return self.message


class UnsafePickleDetectedError(Exception):
  """Custom exception for unsafe pickle files."""

  def __init__(self, m: str) -> None:
    self.message = m

  def __str__(self) -> str:
    return self.message


# Global flag for debug mode
DEBUG_MODE = False


IS_COLAB_ENABLED = "google.colab" in sys.modules


@enum.unique
class Classification(enum.Enum):
  """Classification of a class name."""

  SAFE = "SAFE"
  UNSAFE = "UNSAFE"
  SUSPICIOUS = "SUSPICIOUS"
  UNKNOWN = "UNKNOWN"


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
      except Exception:  # pylint: disable=broad-except
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
    pickle_bytes: bytes,
    chunk_range: Tuple[int, int],
) -> Iterator[tuple[pickletools.OpcodeInfo, Any | None]]:
  """Generates string-declaring opcodes and arguments from a chunk of pickle data.

  This function reads a specific byte range (chunk) of the pickle bytecode
  and yields opcodes that are known to declare strings, along with their
  arguments. It's designed to be used in parallel for large pickle files.

  Args:
    pickle_bytes: The pickle data to generate opcodes from.
    chunk_range: A tuple (start, end) defining the byte range to process.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """

  if isinstance(pickle_bytes, bytes):
    pickle_file = io.BytesIO(pickle_bytes)
  else:
    pickle_file = pickle_bytes

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

      except Exception:  # pylint: disable=broad-except
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


def get_optimal_workers(file_size: int) -> int:
  """Calculates the optimal number of workers based on the file size using tiers.

  Args:
    file_size: The size of the file in bytes.

  Returns:
    The optimal number of workers to use.
  """
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


def _process_chunk_for_generate_ops(
    pickle_bytes: bytes, chunk_range: Tuple[int, int]
) -> Set[str]:
  """Helper function for generate_ops to process a chunk of pickle data."""
  chunked_operands = set()
  try:
    for _, operand in _custom_chunked_genops(pickle_bytes, chunk_range):
      if operand is None:
        continue
      chunked_operands.add(str(operand))
  except StopIteration:
    pass
  return chunked_operands


def generate_ops(pickle_bytes: bytes) -> Set[str]:
  """Returns opcodes that declare strings from a pickle file.

  Args:
    pickle_bytes: The pickle bytecode to yield opcode information for.

  Returns:
    genops_output: The operands associated with the opcodes that declare
    strings.
  """

  filtered_operands = set()
  pickle_length = len(pickle_bytes)
  num_workers = get_optimal_workers(pickle_length)

  # If sys.executable does not have a value or is not a valid
  # Python interpreter, we don't use multiprocessing.
  if (
      pickle_length < constants.MIN_SIZE_FOR_CHUNKING
      or not utils.is_sys_executable_patched()
  ):
    # Use the original non-chunked version for smaller files
    try:
      for _, operand in _custom_genops(pickle_bytes):
        if operand is None:
          continue
        filtered_operands.add(str(operand))
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
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=num_workers, mp_context=ctx
    ) as executor:
      future_to_range_tuple = {
          executor.submit(
              _process_chunk_for_generate_ops, pickle_bytes, range_tuple
          ): range_tuple
          for range_tuple in ranges
      }
      for future in concurrent.futures.as_completed(future_to_range_tuple):
        try:
          filtered_operands.update(future.result())
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

    return filtered_operands


def get_class_instantiations(pickle_bytes: bytes) -> tuple[io.StringIO, bool]:
  """Gets the class instantiations from a pickle file.

  Args:
    pickle_bytes: The pickle bytecode to disassemble.

  Returns:
    A tuple containing:
      - picklemagic_output: Suspicious function calls from picklemagic.
      - was_unsafe_build_blocked: A boolean indicating if a dangerous
        state assignment was blocked by the custom load_build hook.
  """
  picklemagic_output = io.StringIO()
  unpickler = None

  with contextlib.redirect_stdout(picklemagic_output):
    try:
      factory = picklemagic.FakeClassFactory([], picklemagic.FakeWarning)

      # Instead of using safe_loads, we do this to get the
      # has_blocked_unsafe_build_instr boolean properly.
      unpickler = picklemagic.SafeUnpickler(
          io.BytesIO(pickle_bytes),
          class_factory=factory,
          safe_modules=constants.SAFE_STRINGS,
          unsafe_modules=constants.UNSAFE_STRINGS,
      )
      factory.default.unpickler = unpickler
      unpickler.load()

    # These errors are expected and should not be raised.
    # Even if errors are encountered, we still get the class instantiations
    # before errors occur.
    except (
        ValueError,
        AttributeError,
        TypeError,
        picklemagic.FakeUnpicklingError,
        pickle.UnpicklingError,
        IndexError,
        EOFError,
        KeyError,
    ):
      pass

  is_build_instr_blocked = getattr(
      unpickler, "has_blocked_unsafe_build_instr", False
  )
  return picklemagic_output, is_build_instr_blocked


@functools.lru_cache(maxsize=None)
def classify_class_name(class_name: str) -> Classification | None:
  """Classifies a class name based on the safe, unsafe, and suspicious patterns."""
  if re.search(utils.safe_pattern, class_name):
    return Classification.SAFE
  if re.search(utils.unsafe_pattern, class_name):
    return Classification.UNSAFE
  if re.search(utils.suspicious_pattern, class_name):
    return Classification.SUSPICIOUS
  if re.search(utils.unknown_pattern, class_name):
    return Classification.UNKNOWN
  return None


def categorize_strings(
    filtered_output: Set[str] | io.StringIO,
    use_picklemagic: bool = False,
) -> ScanResults:
  """Counts the relevant strings from the filtered output and categorizes them.

  Args:
    filtered_output: The series of statements filtered by string declarations.
    use_picklemagic: If True, the filtered output is from picklemagic, otherwise
      it is from genops or disassembly.

  Returns:
    A ScanResults object.
  """

  unsafe_results: Set[str] = set()
  safe_results: Set[str] = set()
  suspicious_results: Set[str] = set()
  unknown_results: Set[str] = set()
  allow_list = config.get_allow_list()
  deny_list = config.get_deny_list()

  if use_picklemagic and isinstance(filtered_output, io.StringIO):
    filtered_output = filtered_output.getvalue().split("\n")
    for picklemagic_warning in filtered_output:
      if not picklemagic_warning:
        continue

      picklemagic_warning_lower = picklemagic_warning.lower()

      # Printable warning sourced from every suspicious invocation of
      # find_class()
      if picklemagic_warning_lower.startswith("warning"):
        unsafe_module_match = utils.EXTRACT_UNSAFE_MODULE_REGEX.search(
            picklemagic_warning_lower
        )
        if unsafe_module_match:
          unsafe_results.add(unsafe_module_match.group(1))

      # Printable warning for suspicious class instantiations
      if picklemagic_warning_lower.startswith("<"):
        class_args_match = utils.ARGS_REGEX.search(picklemagic_warning_lower)

        if not class_args_match:
          continue

        class_name = class_args_match.group(1)
        class_name_classification = classify_class_name(class_name)

        match class_name_classification:
          case Classification.SAFE:
            safe_results.add(class_name)
          case Classification.UNSAFE:
            unsafe_results.add(class_name)
          case Classification.SUSPICIOUS:
            suspicious_results.add(class_name)
          case Classification.UNKNOWN:
            unknown_results.add(class_name)

        class_args = class_args_match.group(2)

        for method_pattern in utils.PYTHON_METHOD_PATTERNS:
          argument_finds = method_pattern.findall(class_args)
          if not argument_finds:
            continue
          for argument_find in argument_finds:
            found_match = False
            for unsafe_string in constants.UNSAFE_STRINGS:
              if unsafe_string in argument_find:
                unsafe_results.add(argument_find)
                found_match = True
            for safe_string in constants.SAFE_STRINGS:
              if safe_string in argument_find:
                safe_results.add(argument_find)
                found_match = True
            for suspicious_string in constants.SUSPICIOUS_STRINGS:
              if suspicious_string in argument_find:
                suspicious_results.add(argument_find)
                found_match = True

            if not found_match and re.search(
                utils.unknown_pattern, argument_find
            ):
              unknown_results.add(argument_find)

  else:
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
    classification = classify_class_name(result)

    if classification == Classification.SAFE:
      new_safe_results.add(result)
    elif classification == Classification.UNSAFE:
      new_unsafe_results.add(result)
    elif classification == Classification.SUSPICIOUS:
      new_suspicious_results.add(result)
    elif classification == Classification.UNKNOWN:
      new_unknown_results.add(result)
    else:
      # Fallback: Check against original categories if
      # classify_class_name returns None.
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


def strict_security_scan(pickle_bytes: bytes) -> bool:
  """Strict security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    True if the pickle file is dangerous, False otherwise.
  """

  for stmt in generate_ops(pickle_bytes):
    for unsafe_string in constants.UNSAFE_STRINGS.union(
        constants.SUSPICIOUS_STRINGS
    ):
      if re.search(unsafe_string, stmt):
        return True

  # The below handles catching cases of unknown imports and state attacks.
  instantiations_output, was_unsafe_build_blocked = get_class_instantiations(
      pickle_bytes
  )

  if was_unsafe_build_blocked:
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
  """Picklemagic scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    A ScanResults object.
  """
  picklemagic_output, was_unsafe_build_blocked = get_class_instantiations(
      pickle_bytes
  )

  results = categorize_strings(picklemagic_output, use_picklemagic=True)

  if was_unsafe_build_blocked:
    # Temporary addition to increase number of suspicious results given the
    # current scoring implementation. This will be removed in the future.
    results.suspicious_results.add("unsafe_state_assignment")

  return results


def genops_scan(
    pickle_bytes: bytes,
) -> ScanResults:
  """Genops scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    A ScanResults object.
  """
  genops_output = generate_ops(pickle_bytes)
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
    scan_approach: Callable[[bytes], ScanResults],
    pickle_bytes: bytes,
) -> Dict[str, int]:
  """Applies the given scan approach to the data.

  Args:
    scan_approach: The scan approach to apply to the data.
    pickle_bytes: The data to scan.

  Returns:
    A dictionary of the resulting scores.
  """
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


@functools.lru_cache(maxsize=None)
def security_scan(
    pickle_bytes: bytes, force_scan: bool = False
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    force_scan: If True, force scan even if the file is not a pickle file.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    finds.
  """

  if utils.is_zip_bytes(pickle_bytes):
    total_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}
    unzipped_files = utils.extract_zip_contents(pickle_bytes)
    for unzipped_file in unzipped_files:
      filename, file_bytes = unzipped_file

      if (
          not utils.is_pickle_file(file_bytes) or not file_bytes
      ) and not force_scan:
        if DEBUG_MODE:
          print(f"Skipping non-pickle file: {filename}")
        continue

      if DEBUG_MODE:
        print(f"Scanning unzipped pickle file: {filename}")

      inner_scores = security_scan(file_bytes)

      if inner_scores["unsafe"] > 0 or inner_scores["suspicious"] > 0:
        return inner_scores  # Fail fast for zips

      # Accumulate scores from safe files
      total_scores["unknown"] += inner_scores["unknown"]
    return total_scores

  if not utils.is_pickle_file(pickle_bytes) and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  final_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}
  # Fastest to slowest scan (tiered approach)
  for scan_approach in [picklemagic_scan, genops_scan]:
    scores = apply_approach(scan_approach, pickle_bytes)
    if scores["unsafe"] > 0 or scores["suspicious"] > 0:
      return scores
    final_scores["unknown"] += scores["unknown"]

  return final_scores


_thread_local_storage_for_hooking = threading.local()


def _report_or_raise(
    classification: Classification, report_only: bool, log_info=False
):
  """Reports or raises an error based on classification and report_only flag."""

  # This attempts to catch external exceptions raised by libraries
  # using SaferPickle and re-raise them to maintain the original failures for
  # unit tests.
  exc_info = sys.exc_info()
  external_exception_caught = (
      exc_info[0] is not None and exc_info[1] is not None
  )

  if report_only:
    logging_function = logging.info if log_info else logging.error
    logging_function(
        constants.ERROR_STRING.substitute(classification=classification.value)
    )
    if external_exception_caught:
      # Re-raise the exception that was active when _report_or_raise was called.
      if exc_info[2] is not None:
        raise exc_info[1].with_traceback(exc_info[2])
      raise exc_info[1]
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
    *args: Any,
    **kwargs: Any,
):
  """Internal helper to scan and load pickle data."""

  if is_load:
    if not isinstance(pickle_file_or_bytes, io.IOBase):
      raise TypeError("pickle_file_or_bytes must be IOBase when is_load=True")
    pickle_file = pickle_file_or_bytes
    data_bytes = pickle_file.read()
    if hasattr(pickle_file, "seek"):
      pickle_file.seek(0)
    else:
      pickle_file = io.BytesIO(data_bytes)
  else:
    if not isinstance(pickle_file_or_bytes, bytes):
      raise TypeError("pickle_file_or_bytes must be bytes when is_load=False")
    data_bytes = pickle_file_or_bytes
    pickle_file = None

  loader_mod = COPIED_MODS_MAP.get(hooked_mod_name)
  if not loader_mod:
    loader_mod = pickle_copy

  if strict_check and allow_unsafe:
    error_string_illegal_combination = (
        "Strict scanning and allow_unsafe cannot be used together."
    )
    if report_only:
      logging.error(error_string_illegal_combination)
      return
    raise IllegalArgumentCombinationError(error_string_illegal_combination)

  if is_load:
    load_func = loader_mod.load
    load_args = (pickle_file,)
  else:
    load_func = loader_mod.loads
    load_args = (data_bytes,)

  if allow_unsafe:
    if report_only:
      logging.info("Loading pickle file with allow_unsafe set to True.")
    try:
      return load_func(*load_args, *args, **kwargs)
    except AttributeError as exc:
      logging.info("Could not load an absent class: %s", exc)
      return

  if strict_check:
    if strict_security_scan(data_bytes):
      error_string_strict_check = "Pickle file failed strict security check."
      if report_only:
        logging.error(error_string_strict_check)
        return
      raise StrictCheckError(error_string_strict_check)
    try:
      return load_func(*load_args, *args, **kwargs)
    except (AttributeError, pickle.UnpicklingError) as exc:
      if "persistent load" in str(exc):
        logging.info("Persistent load error: %s", exc)
        return
      elif "Can't get attribute" in str(exc):
        logging.exception(
            "Could not load an absent class: %s", exc, exc_info=True
        )
        raise UnsafePickleDetectedError(
            constants.ERROR_STRING.substitute(
                classification=Classification.SUSPICIOUS.value
            )
        ) from exc
      elif "underflow" in str(exc):
        raise
      logging.exception("Unknown error: %s", exc, exc_info=True)
      return

  # If we get here, we are not in strict check or allow_unsafe mode.
  # We perform non-strict scanning as usual with force_scan if needed.
  scan_scores = security_scan(data_bytes, force_scan=force_scan)
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
    try:
      return load_func(*load_args, *args, **kwargs)
    except (AttributeError, pickle.UnpicklingError) as exc:
      if "persistent load" in str(exc):
        logging.info("Persistent load error: %s", exc)
        return
      elif "Can't get attribute" in str(exc):
        logging.exception(
            "Could not load an absent class: %s", exc, exc_info=True
        )
        raise UnsafePickleDetectedError(
            constants.ERROR_STRING.substitute(
                classification=Classification.SUSPICIOUS.value
            )
        ) from exc
      elif "underflow" in str(exc):
        raise
      logging.exception("Unknown error: %s", exc, exc_info=True)
      return

  elif number_of_unsafe_results > number_of_suspicious_results:
    _report_or_raise(Classification.UNSAFE, report_only, log_info)
    return
  else:
    _report_or_raise(Classification.SUSPICIOUS, report_only, log_info)
    return


def hook_pickle(
    force_report_only: bool = False,
    log_info: bool = False,
    config_path: Optional[str] = None,
) -> None:
  """This implements the hooking of pickle-like libraries."""
  config.set_config_path(config_path)
  if not hasattr(
      _thread_local_storage_for_hooking, "orig_methods_before_hooking"
  ):
    _thread_local_storage_for_hooking.orig_methods_before_hooking = {}

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

    if (
        hookable_mod
        not in _thread_local_storage_for_hooking.orig_methods_before_hooking
    ):
      _thread_local_storage_for_hooking.orig_methods_before_hooking[
          hookable_mod
      ] = {}

    methods_to_patch = {
        "load": functools.partial(custom_load, hooked_mod_name=hookable_mod),
        "_load": functools.partial(custom_load, hooked_mod_name=hookable_mod),
        "loads": functools.partial(custom_loads, hooked_mod_name=hookable_mod),
        "_loads": functools.partial(custom_loads, hooked_mod_name=hookable_mod),
    }
    for method_name, custom_func in methods_to_patch.items():
      if hasattr(module, method_name):
        if (
            method_name
            not in _thread_local_storage_for_hooking.orig_methods_before_hooking[
                hookable_mod
            ]
        ):
          _thread_local_storage_for_hooking.orig_methods_before_hooking[
              hookable_mod
          ][method_name] = getattr(module, method_name)
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
  if not hasattr(
      _thread_local_storage_for_hooking, "orig_methods_before_hooking"
  ):
    return
  for (
      module_name,
      methods,
  ) in _thread_local_storage_for_hooking.orig_methods_before_hooking.items():
    try:
      module = importlib.import_module(module_name)
      for method_name, original_method in methods.items():
        if hasattr(module, method_name):
          setattr(module, method_name, original_method)
    except (ImportError, ModuleNotFoundError):
      logging.debug("Failed to import %s for unhooking", module_name)
      continue
  # Empty stored methods to avoid re-unhooking on a second unhook call
  # items() would be empty after clearing the dictionary
  _thread_local_storage_for_hooking.orig_methods_before_hooking.clear()


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

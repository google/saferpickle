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
import math
import mmap
import pickle
import pickletools
import re
import struct
import sys
import threading
import types
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    IO,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from absl import logging
from third_party.corrupy import picklemagic
from lib import config
from lib import constants
from lib import exceptions
from lib import utils

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


def _get_stream_pos(stream: Any) -> Optional[int]:
  """Safely retrieves the current byte offset of a stream if supported.

  Attempts to call `stream.tell()` and catches unsupported stream or OS errors
  so non-seekable streams return `None` instead of raising.

  Args:
    stream: A file-like stream object.

  Returns:
    The current integer byte position of `stream`, or None if unavailable.
  """
  try:
    return stream.tell()
  except (OSError, AttributeError, io.UnsupportedOperation):
    return None


def _resolve_pickle_length(
    pickle_bytes: Any,
    pickle_length: Optional[int],
) -> int:
  """Resolves the remaining byte length of a pickle buffer or stream.

  Computes the exact remaining byte count for in-memory buffers (`bytes`,
  `bytearray`, `memoryview`, `mmap.mmap`, `io.BytesIO`) and seekable streams
  while preserving stream position, returning `0` for non-seekable streams.

  Args:
    pickle_bytes: In-memory byte buffer or binary stream to inspect.
    pickle_length: Explicit byte length override, if already known.

  Returns:
    The non-negative byte length, or `0` if `pickle_bytes` is non-seekable.
  """
  if pickle_length is not None:
    return pickle_length

  if isinstance(pickle_bytes, (bytes, bytearray, memoryview, mmap.mmap)):
    return len(pickle_bytes)

  if isinstance(pickle_bytes, io.BytesIO):
    return max(0, len(pickle_bytes.getbuffer()) - pickle_bytes.tell())

  seekable_fn = getattr(pickle_bytes, "seekable", None)
  if callable(seekable_fn):
    try:
      if not seekable_fn():
        return 0
    except (OSError, AttributeError, io.UnsupportedOperation):
      return 0

  cur_pos = _get_stream_pos(pickle_bytes)
  if cur_pos is None:
    return 0

  try:
    end_pos = pickle_bytes.seek(0, io.SEEK_END)
    pickle_bytes.seek(cur_pos)
  except (OSError, AttributeError, io.UnsupportedOperation):
    try:
      pickle_bytes.seek(cur_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass
    return 0

  return max(0, end_pos - cur_pos)


def _safe_seek(stream: Any, position: Optional[int]) -> None:
  """Restores `stream` to `position` if seekable."""
  if position is None or not hasattr(stream, "seek"):
    return
  try:
    stream.seek(position)
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    logging.debug("Failed to seek stream back to position %s.", position)


def _custom_genops(
    pickle_bytes: bytes | BinaryIO,
) -> Iterator[tuple[Optional[pickletools.OpcodeInfo], Any | None]]:
  """Generates string-declaring opcodes and their arguments from pickle data.

  Args:
    pickle_bytes: The pickle data to generate opcodes from.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """
  match pickle_bytes:
    case bytes() | mmap.mmap():
      yield from utils.custom_genops_from_bytes(pickle_bytes)
      return

    case bytearray() | memoryview():
      yield from utils.custom_genops_from_bytes(bytes(pickle_bytes))
      return

    case io.BytesIO():
      yield from utils.custom_genops_from_bytes(
          pickle_bytes.getvalue(), start=pickle_bytes.tell()
      )
      return

  start_position = _get_stream_pos(pickle_bytes)
  try:
    data_bytes = pickle_bytes.read(-1)
  finally:
    _safe_seek(pickle_bytes, start_position)
  yield from utils.custom_genops_from_bytes(data_bytes)


def _scan_byte_slice(
    data: bytes | mmap.mmap,
    start: int,
    end: int,
    seed_stack: Sequence[Optional[str]] = (),
    fail_fast: bool = False,
    abort_event: Optional[threading.Event] = None,
    seed_memo: Optional[Mapping[int, Optional[str]]] = None,
) -> Set[str]:
  """Worker function to scan a byte slice of pickle bytecode.

  Scans an opcode-aligned byte slice concurrently in a worker thread and
  extracts all string-declaring operands

  Args:
    data: The raw pickle byte buffer or mmapped file slice.
    start: Byte offset where the chunk starts.
    end: Byte offset where the chunk ends.
    seed_stack: Initial string operands to populate the stack context.
    fail_fast: Whether to abort scanning immediately upon detecting an unsafe or
      suspicious operand.
    abort_event: Optional threading event used to signal other workers to stop.
    seed_memo: Initial memo table mapping memo keys to string operands.

  Returns:
    A set of string operands discovered within the byte slice.
  """
  discovered_operands = set()
  for chunk_index, (_, operand) in enumerate(
      utils.custom_genops_from_bytes(
          data,
          start=start,
          end=end,
          seed_stack=seed_stack,
          seed_memo=seed_memo,
      )
  ):
    if (
        abort_event is not None
        and (chunk_index & 0xFF == 0)
        and abort_event.is_set()
    ):
      break
    if operand is not None:
      operand_string = str(operand)
      discovered_operands.add(operand_string)
      if fail_fast and utils.is_unsafe_for_fail_fast(operand_string):
        if abort_event is not None:
          abort_event.set()
        break
  return discovered_operands


def generate_ops_from_file(
    pickle_file_path: str,
    pickle_length: Optional[int] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    data_buffer: Optional[bytes | mmap.mmap] = None,
) -> Set[str]:
  """Returns opcodes that declare strings from a path or in-memory buffer.

  Reads pickle bytecode and partitions large payloads for parallel
  scanning using threads.

  Args:
    pickle_file_path: The filesystem path to the pickle file.
    pickle_length: Optional length of the pickle data in bytes.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    data_buffer: Optional in-memory bytes or mmap buffer for zero-copy scanning.

  Returns:
    The operands associated with opcodes declaring strings.
  """
  if data_buffer is not None:
    pickle_bytes = data_buffer
  else:
    with open(pickle_file_path, "rb") as file_handle:
      pickle_bytes = (
          file_handle.read(pickle_length)
          if pickle_length is not None
          else file_handle.read()
      )

  effective_length = (
      min(pickle_length, len(pickle_bytes))
      if pickle_length is not None
      else len(pickle_bytes)
  )
  num_workers = utils.get_optimal_workers(effective_length)

  if (
      effective_length < constants.MIN_SIZE_FOR_CHUNKING
      or num_workers <= 1
      or not utils.is_sys_executable_patched()
  ):
    all_operands = set()
    for _, operand in utils.custom_genops_from_bytes(
        pickle_bytes, end=effective_length
    ):
      if operand is not None:
        operand_string = str(operand)
        all_operands.add(operand_string)
        if fail_fast and utils.is_unsafe_for_fail_fast(operand_string):
          break
    return all_operands

  target_chunk_size = max(
      constants.MIN_SIZE_FOR_CHUNKING, effective_length // num_workers
  )
  chunk_ranges = utils.partition_pickle_chunks(
      pickle_bytes,
      target_chunk_size,
      end=effective_length,
      include_memo=True,
  )

  all_operands = set()
  abort_event = threading.Event() if fail_fast else None

  with concurrent.futures.ThreadPoolExecutor(
      max_workers=len(chunk_ranges)
  ) as executor:
    futures = [
        executor.submit(
            _scan_byte_slice,
            pickle_bytes,
            start_offset,
            end_offset,
            seed_stack,
            bool(fail_fast),
            abort_event,
            seed_memo,
        )
        for start_offset, end_offset, seed_stack, seed_memo in chunk_ranges
    ]
    for future in concurrent.futures.as_completed(futures):
      chunk_results = future.result()
      all_operands.update(chunk_results)
      if fail_fast and any(
          utils.is_unsafe_for_fail_fast(item) for item in chunk_results
      ):
        if abort_event:
          abort_event.set()
        for running_future in futures:
          running_future.cancel()
        break

  return all_operands


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
  original_pos = (
      None
      if isinstance(pickle_bytes, (bytes, bytearray, memoryview, mmap.mmap))
      else _get_stream_pos(pickle_bytes)
  )

  try:
    try:
      for _, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
        if operand is None:
          continue
        operand_str = str(operand)
        filtered_operands.add(operand_str)
        if fail_fast and utils.is_unsafe_for_fail_fast(operand_str):
          break
    except StopIteration:
      pass
    return filtered_operands
  finally:
    if original_pos is not None:
      try:
        pickle_bytes.seek(original_pos)  # pyrefly: ignore[missing-attribute]
      except (OSError, AttributeError, io.UnsupportedOperation):
        pass


class SaferUnpickler(picklemagic.SafeUnpickler):
  """Subclass of SafeUnpickler to optimize state checking during BUILD.

  Overrides and refines object state verification to prevent bypasses from
  injecting malicious state or invoking dangerous reduction callbacks on
  untrusted classes.
  """

  def __init__(self, file: Any, *args: Any, **kwargs: Any) -> None:
    """Initializes `SaferUnpickler` with CRLF normalization and byte loaders.

    Wraps `self._file_readline` to normalize trailing CRLF sequences to LF for
    Protocol 0 opcodes and registers fast dispatch handlers for binary byte
    opcodes (`BINBYTES`, `BINSTRING`, `BINBYTES8`, `BYTEARRAY8`).

    Args:
      file: Binary file-like stream containing pickle bytecode.
      *args: Additional positional arguments forwarded to `SafeUnpickler`.
      **kwargs: Additional keyword arguments forwarded to `SafeUnpickler`.

    Returns:
      None.
    """
    super().__init__(file, *args, **kwargs)
    self._raw_stream = file

    original_file_readline = self._file_readline

    def _normalized_readline() -> bytes:
      """Reads a single line from the stream and normalizes CRLF to LF.

      Calls the underlying unpickler's `_file_readline` and strips any carriage
      return immediately preceding the terminating newline.

      Returns:
        The line bytes with a trailing CRLF normalized to LF.
      """
      line = original_file_readline()
      return line[:-2] + b"\n" if line.endswith(b"\r\n") else line

    self._file_readline = _normalized_readline

    self.dispatch = self.dispatch.copy()
    self.dispatch[pickle.BINBYTES[0]] = self._load_binbytes_fast
    self.dispatch[pickle.BINBYTES8[0]] = self._load_binbytes8_fast
    self.dispatch[pickle.BYTEARRAY8[0]] = self._load_bytearray8_fast

  def _skip_or_read_bytes(
      self, length: int, as_bytearray: bool = False
  ) -> None:
    """Reads small byte payloads or skips payloads larger than 4096 bytes.

    Reads and pushes the exact payload onto the unpickler stack when
    `length <= 4096`, or advances the stream and pushes an empty `bytes` or
    `bytearray` placeholder when `length > 4096`.

    Args:
      length: Number of bytes in the opcode payload.
      as_bytearray: Whether to push a `bytearray` instead of `bytes` onto the
        unpickler stack.

    Returns:
      None.

    Raises:
      pickle.UnpicklingError: If `length` is negative.
      EOFError: If the stream is truncated before `length` bytes.
    """
    if length < 0:
      raise pickle.UnpicklingError("BINBYTES/BYTEARRAY count < 0")

    unframer = getattr(self, "_unframer", None)
    current_frame = getattr(unframer, "current_frame", None)
    if (
        length > 4096
        and current_frame is None
        and hasattr(self._raw_stream, "seek")
        and hasattr(self._raw_stream, "tell")
    ):
      cur_pos = self._raw_stream.tell()
      self._raw_stream.seek(0, io.SEEK_END)
      end_pos = self._raw_stream.tell()
      if cur_pos + length > end_pos:
        self._raw_stream.seek(end_pos)
        raise EOFError("Truncated binary payload in pickle stream")

      self._raw_stream.seek(cur_pos + length)
      self.append(bytearray() if as_bytearray else b"")
      return

    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")

    self.append(bytearray(data) if as_bytearray else data)

  def _load_binbytes_fast(self, *unused_args: Any) -> None:
    """Dispatches `BINBYTES` using a 4-byte unsigned little-endian length.

    Reads the 4-byte length prefix from the stream and delegates payload
    handling to `_skip_or_read_bytes`.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    self._skip_or_read_bytes(struct.unpack("<I", self.read(4))[0])

  def _load_binbytes8_fast(self, *unused_args: Any) -> None:
    """Dispatches `BINBYTES8` using an 8-byte unsigned little-endian length.

    Reads the 8-byte length prefix from the stream and delegates payload
    handling to `_skip_or_read_bytes`.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    self._skip_or_read_bytes(struct.unpack("<Q", self.read(8))[0])

  def _load_bytearray8_fast(self, *unused_args: Any) -> None:
    """Dispatches `BYTEARRAY8` using an 8-byte unsigned little-endian length.

    Reads the 8-byte length prefix from the stream and delegates payload
    handling to `_skip_or_read_bytes` with `as_bytearray=True`.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    self._skip_or_read_bytes(
        struct.unpack("<Q", self.read(8))[0], as_bytearray=True
    )

  def load_build(self, *unused_args: Any) -> None:
    """Validates and applies the `BUILD` opcode within the unpickler sandbox.

    Blocks `BUILD` instructions that configure real objects with `FakeClass`
    state, updates dictionary-backed objects lacking `__dict__` or
    `__setstate__` directly, and delegates remaining cases to `SafeUnpickler`.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    if len(self.stack) >= 2:
      state = self.stack[-1]
      inst = self.stack[-2]
      if self._state_contains_fake_class(state, only_suspicious=True):
        self.has_blocked_unsafe_build_instr = True
        self.stack.pop()
        return

      if (
          isinstance(inst, dict)
          and not isinstance(inst, picklemagic.FakeClass)
          and getattr(inst, "__setstate__", None) is None
          and getattr(inst, "__dict__", None) is None
      ):
        self.stack.pop()
        if state is None:
          return
        if self._state_contains_fake_class(state):
          self.has_blocked_unsafe_build_instr = True
          return

        is_two_tuple = isinstance(state, tuple) and len(state) == 2
        dict_state = state[0] if is_two_tuple else state
        slots_state = state[1] if is_two_tuple else None
        if isinstance(dict_state, dict):
          inst.update(dict_state)
        if isinstance(slots_state, dict):
          for slot_key, slot_val in slots_state.items():
            try:
              setattr(inst, slot_key, slot_val)
            except Exception:  # pylint: disable=broad-exception-caught
              pass
        return

    super().load_build(*unused_args)

  def load_reduce(self, *unused_args: Any) -> None:
    """Executes the `REDUCE` opcode safely within the `picklemagic` sandbox.

    Flags `REDUCE` instructions whose argument tuple contains `UNSAFE`,
    `SUSPICIOUS`, or deny-listed `FakeClass` objects while allowing `UNKNOWN`
    sandbox placeholders, and replaces failed reductions with a
    `picklemagic.failed_reduce` placeholder.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    stack = self.stack
    args = stack.pop()
    func = stack[-1]

    if self._state_contains_fake_class(args, only_suspicious=True):
      self.has_blocked_unsafe_build_instr = True

    try:
      stack[-1] = func(*args)
    except Exception as e:  # pylint: disable=broad-exception-caught
      std_logging.getLogger("corrupy.picklemagic").warning(
          "Failed to reduce %s with %s: %s", func, args, e
      )
      stack[-1] = self.class_factory("failed_reduce", "picklemagic")()

  def _state_contains_fake_class(  # pyrefly: ignore[bad-override]
      self,
      object_to_inspect: Any,
      visited_object_ids: Optional[Set[int]] = None,
      only_suspicious: bool = False,
      inspection_depth: int = 0,
  ) -> bool:
    """Recursively inspects an object to detect FakeClass instances or types.

    Traverses containers, `__dict__` attributes, and `__slots__` while tracking
    visited object IDs to prevent infinite recursion on cyclic object graphs.

    Args:
      object_to_inspect: The candidate object, container, or state dictionary.
      visited_object_ids: Set of memory addresses visited to prevent infinite
        cycles in self-referential structures.
      only_suspicious: If True, only flags `FakeClass` symbols classified as
        `UNSAFE`, `SUSPICIOUS`, deny-listed, or `picklemagic` error placeholders
        rather than `UNKNOWN` symbols.
      inspection_depth: Current recursion depth within the inspected object
        graph.

    Returns:
      True if the object contains a matching FakeClass instance or type, or
      False otherwise.
    """
    if inspection_depth > 64:
      return True

    # Primitive immutable types cannot harbor custom objects so we quickly
    # return
    if isinstance(
        object_to_inspect,
        (
            int,
            float,
            str,
            bytes,
            bool,
            type(None),
            complex,
            memoryview,
            bytearray,
            range,
        ),
    ):
      return False

    # Skip heavy numerical array buffers from standard scientific libraries.
    object_type = type(object_to_inspect)
    if object_type.__module__ in (
        "numpy",
        "torch",
    ) and object_type.__name__ in (
        "ndarray",
        "Tensor",
    ):
      return False

    # Initialize cycle detection set on top-level call.
    if visited_object_ids is None:
      visited_object_ids = set()

    current_object_id = id(object_to_inspect)
    if current_object_id in visited_object_ids:
      return False
    visited_object_ids.add(current_object_id)

    # Check if target object is an unapproved sandbox FakeClass or
    # FakeClassType.
    if isinstance(
        object_to_inspect, (picklemagic.FakeClass, picklemagic.FakeClassType)
    ) or (
        isinstance(object_to_inspect, type)
        and issubclass(object_to_inspect, picklemagic.FakeClass)
    ):
      if isinstance(object_to_inspect, picklemagic.FakeClass):
        module_name = object_to_inspect.__class__.__module__
        attribute_name = object_to_inspect.__class__.__name__
      else:
        module_name = getattr(object_to_inspect, "__module__", "")
        attribute_name = getattr(object_to_inspect, "__name__", "")

      full_symbol_name = (
          f"{module_name}.{attribute_name}"
          if module_name and attribute_name
          else (module_name or attribute_name)
      )
      if (
          not full_symbol_name
          or module_name == "picklemagic"
          or utils.matches_symbol_prefix_list(
              full_symbol_name, config.get_deny_list()
          )
      ):
        return True

      if is_self_protected := utils.is_self_protected_symbol(full_symbol_name):
        return True

      if not is_self_protected and not utils.matches_symbol_prefix_list(
          full_symbol_name, config.get_allow_list()
      ):
        cls_verdict = utils.classify_symbol(full_symbol_name)
        if only_suspicious:
          if cls_verdict in (
              utils.Classification.UNSAFE,
              utils.Classification.SUSPICIOUS,
          ):
            return True
        elif cls_verdict != utils.Classification.SAFE:
          return True

    if isinstance(object_to_inspect, (list, tuple, set, frozenset)):
      return any(
          self._state_contains_fake_class(
              element,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          )
          for element in object_to_inspect
      )

    if isinstance(object_to_inspect, dict):
      return any(
          self._state_contains_fake_class(
              dict_key,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          )
          or self._state_contains_fake_class(
              dict_value,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          )
          for dict_key, dict_value in object_to_inspect.items()
      )

    instance_attributes = getattr(object_to_inspect, "__dict__", None)
    if isinstance(instance_attributes, dict):
      if self._state_contains_fake_class(
          instance_attributes,
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      ):
        return True

    slot_names = getattr(type(object_to_inspect), "__slots__", None)
    if isinstance(slot_names, str):
      slot_names = (slot_names,)
    if isinstance(slot_names, (list, tuple, set, frozenset)):
      for slot_name in slot_names:
        if isinstance(slot_name, str) and hasattr(object_to_inspect, slot_name):
          slot_value = getattr(object_to_inspect, slot_name)
          if self._state_contains_fake_class(
              slot_value,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          ):
            return True

    return False


def get_class_instantiations(
    pickle_bytes: bytes | IO[bytes],
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
      unpickler = SaferUnpickler(
          pickle_stream,
          class_factory=factory,
          safe_modules=(),
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
  """Categorizes extracted operands or `picklemagic` logs into `ScanResults`.

  Args:
    filtered_output: Set of `genops` operands or `StringIO` `picklemagic` logs.
    use_picklemagic: Whether `filtered_output` contains `picklemagic` log text.

  Returns:
    A `ScanResults` instance with resolved and categorized symbol sets.
  """
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
  """Classifies a set of `genops` string operands by safety category.

  Args:
    filtered_output: Set of raw string operands extracted from pickle opcodes.

  Returns:
    A 4-tuple of `(safe_results, unsafe_results, suspicious_results,
    unknown_results)` string sets.
  """
  results: dict[utils.Classification, Set[str]] = {
      cls: set() for cls in utils.Classification
  }
  for line in filtered_output:
    results[utils.classify_symbol(line)].add(line)

  return (
      results[utils.Classification.SAFE],
      results[utils.Classification.UNSAFE],
      results[utils.Classification.SUSPICIOUS],
      results[utils.Classification.UNKNOWN],
  )


def _reclassify_with_resolution(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> ScanResults:
  """Resolves module-member pairs and re-classifies results against config lists.

  Args:
    safe_results: Initially classified safe symbols.
    unsafe_results: Initially classified unsafe symbols.
    suspicious_results: Initially classified suspicious symbols.
    unknown_results: Initially classified unknown symbols.

  Returns:
    A `ScanResults` instance after module resolution and allow/deny list checks.
  """
  allow_list = config.get_allow_list()
  deny_list = config.get_deny_list()

  # Only resolve qualified symbols (e.g. 'pkg.mod') to avoid plain words.
  candidate_results = safe_results.union(unsafe_results, suspicious_results)
  resolvable_unknowns = {
      unknown_symbol
      for unknown_symbol in unknown_results
      if "." in unknown_symbol
      or utils.classify_symbol(unknown_symbol) != utils.Classification.UNKNOWN
  }
  all_candidates = candidate_results.union(resolvable_unknowns)

  resolved_results = utils.resolve_library_modules_from_results(all_candidates)
  resolved_results.update(unknown_results - resolvable_unknowns)

  # Re-categorize the resolved results
  new_safe_results = set()
  new_unsafe_results = set()
  new_suspicious_results = set()
  new_unknown_results = set()
  is_denylisted = False

  for result in resolved_results:
    if utils.matches_symbol_prefix_list(result, deny_list):
      new_unsafe_results.add(result)
      is_denylisted = True
      continue

    if not utils.is_self_protected_symbol(
        result
    ) and utils.matches_symbol_prefix_list(result, allow_list):
      new_safe_results.add(result)
      continue

    if result == "builtins":
      new_unknown_results.add(result)
      continue

    # Classify the resolved result
    classification = utils.classify_symbol(result)

    if classification == utils.Classification.SAFE:
      new_safe_results.add(result)
    elif classification == utils.Classification.UNSAFE:
      new_unsafe_results.add(result)
    elif classification == utils.Classification.SUSPICIOUS:
      new_suspicious_results.add(result)
    elif classification == utils.Classification.UNKNOWN:
      # Fallback: Check against original categories if
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


def _strict_security_scan_stream(pickle_bytes: bytes | IO[bytes]) -> bool:
  """Runs a strict genops and picklemagic security check on a single stream.

  Args:
    pickle_bytes: Unwrapped pickle byte buffer or binary stream to scan.

  Returns:
    True if any non-safe symbol, dangerous literal, or sandbox error is
    detected, or False if the stream passes strict verification.
  """
  original_pos = _get_stream_pos(pickle_bytes)

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

    _safe_seek(pickle_bytes, original_pos)

    instantiations_output, was_unsafe_build_blocked, has_scan_error = (
        get_class_instantiations(pickle_bytes)
    )

    if was_unsafe_build_blocked or has_scan_error:
      return True

    _, unsafe_items, suspicious_items, unknown_items = (
        utils.categorize_picklemagic(instantiations_output)
    )
    if unsafe_items or suspicious_items or unknown_items:
      return True
  finally:
    _safe_seek(pickle_bytes, original_pos)

  return False


def is_unsafe(
    unused_number_of_safe_results: int,
    number_of_unsafe_results: int,
    number_of_suspicious_results: int,
) -> bool:
  """Conditional check for safeness.

  Args:
    unused_number_of_safe_results: Number of safe results from the security
      scan.
    number_of_unsafe_results: Number of unsafe results from the security scan.
    number_of_suspicious_results: Number of suspicious results from the security
      scan.

  Returns:
    True if the pickle file is dangerous, False otherwise.
  """
  return number_of_unsafe_results > 0 or number_of_suspicious_results > 0


_STREAM_ARCHIVE_EXTRACTORS = types.MappingProxyType({
    "bz2": utils.extract_bz2_contents,
    "lzma": utils.extract_lzma_contents,
    "gzip": utils.extract_gzip_contents,
})


def _iter_archive_entries(
    data: bytes,
    archive_type: str,
) -> Iterator[tuple[str | None, IO[bytes]]]:
  """Yields `(entry_name, content_stream)` pairs from a supported archive."""
  if archive_type == "zip":
    yield from utils.extract_zip_contents(data)
  elif archive_type in _STREAM_ARCHIVE_EXTRACTORS:
    yield None, _STREAM_ARCHIVE_EXTRACTORS[archive_type](data)
  elif archive_type == "tar":
    yield from utils.extract_tar_contents(data)
  else:
    raise ValueError(f"Unsupported archive type: {archive_type}")


class _UnsafeArchivePathError(Exception):
  """Raised internally when an archive member contains path traversal."""


def _iter_scannable_archive_children(
    archive_bytes: bytes,
    archive_type: str,
    budget: list[int],
    *,
    force_scan: bool = False,
    check_magic_bytes: bool = True,
    advance_to_pickle: bool = False,
) -> Iterator[tuple[bytes, bool]]:
  """Yields `(entry_bytes, child_force_scan)` for scannable archive members."""
  for entry_name, content_stream in _iter_archive_entries(
      archive_bytes, archive_type
  ):
    if entry_name is not None and utils.is_unsafe_archive_path(entry_name):
      raise _UnsafeArchivePathError(entry_name)

    if entry_name is not None:
      is_named_pickle = entry_name.lower().endswith(
          constants.PICKLE_MEMBER_EXTENSIONS
      )
      if (
          not is_named_pickle
          and not force_scan
          and utils.detect_archive_type(content_stream) is None
          and not utils.is_pickle_file(
              content_stream,
              check_magic_bytes=check_magic_bytes,
          )
      ):
        continue

      entry_bytes = utils.read_bounded(content_stream, remaining_budget=budget)
      child_force_scan = force_scan
      if is_named_pickle and utils.detect_archive_type(entry_bytes) is None:
        child_force_scan = True
      yield entry_bytes, child_force_scan
      continue

    entry_bytes = utils.read_bounded(content_stream, remaining_budget=budget)
    if (
        not force_scan
        and utils.detect_archive_type(entry_bytes) is None
        and not utils.is_pickle_file(
            entry_bytes,
            check_magic_bytes=check_magic_bytes,
        )
        and not (
            advance_to_pickle
            and utils.find_pickle_start_offset(entry_bytes) > 0
        )
    ):
      continue

    yield entry_bytes, force_scan


def _scan_payload_tree(
    data: bytes | IO[bytes],
    on_leaf: Callable[[bytes | IO[bytes], bool, bool], bool],
    on_error: Callable[[str], bool],
    *,
    force_scan: bool = False,
    check_magic_bytes: bool = True,
    advance_to_pickle: bool = False,
    recursion_depth: int = 0,
    remaining_budget: Optional[list[int]] = None,
) -> bool:
  """Recursively walks archives, polyglots, and `.npy` files to leaf payloads.

  Args:
    data: Raw byte buffer or binary stream to inspect.
    on_leaf: Callback `(payload, leaf_force_scan, leaf_check_magic_bytes)`
      invoked on each non-archive leaf payload; returns True to stop early.
    on_error: Callback `(error_tag)` invoked on archive traversal or extraction
      failure; returns True to stop early.
    force_scan: Whether to scan entries even when `is_pickle_file` is False.
    check_magic_bytes: Whether to enable magic-byte fast rejection.
    advance_to_pickle: Whether to advance leaves past leading non-pickle bytes.
    recursion_depth: Current archive nesting depth (`0` at top-level caller).
    remaining_budget: Shared mutable single-item byte budget `[bytes_left]`.

  Returns:
    True if `on_leaf` or `on_error` requested early termination, or False
    otherwise.

  Raises:
    MaxRecursionDepthExceededError: If `recursion_depth` exceeds
      `constants.MAX_ARCHIVE_RECURSION_DEPTH`.
  """
  max_depth = constants.MAX_ARCHIVE_RECURSION_DEPTH
  if recursion_depth > max_depth:
    raise MaxRecursionDepthExceededError(
        f"Max recursion depth of {max_depth} exceeded."
    )

  normalized_data = utils.ensure_seekable_stream(data)
  original_pos = _get_stream_pos(normalized_data)

  try:
    archive_type = utils.detect_archive_type(normalized_data)
    if archive_type is not None:
      archive_bytes = (
          normalized_data
          if isinstance(normalized_data, (bytes, mmap.mmap))
          else normalized_data.read()
      )
      if isinstance(archive_bytes, mmap.mmap):
        archive_bytes = bytes(archive_bytes)
      budget = (
          remaining_budget
          if remaining_budget is not None
          else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
      )
      try:
        for entry_bytes, child_force_scan in _iter_scannable_archive_children(
            archive_bytes,
            archive_type,
            budget,
            force_scan=force_scan,
            check_magic_bytes=check_magic_bytes,
            advance_to_pickle=advance_to_pickle,
        ):
          if _scan_payload_tree(
              entry_bytes,
              on_leaf,
              on_error,
              force_scan=child_force_scan,
              check_magic_bytes=check_magic_bytes,
              advance_to_pickle=advance_to_pickle,
              recursion_depth=recursion_depth + 1,
              remaining_budget=budget,
          ):
            return True
      except _UnsafeArchivePathError as slip_err:
        logging.warning(
            "%s slip detected: %s",
            archive_type.capitalize(),
            slip_err,
        )
        return on_error(f"{archive_type}_slip_detected")
      except MaxRecursionDepthExceededError:
        raise
      except utils.ARCHIVE_EXTRACTION_ERRORS as exc:
        logging.warning("Error processing %s archive: %s", archive_type, exc)
        return on_error("archive_extraction_error")

      is_non_prefix_zip = archive_type == "zip" and not utils.is_zip_bytes(
          archive_bytes, allow_trailing_eocd=False
      )
      if (archive_type == "tar" or is_non_prefix_zip) and utils.is_pickle_file(
          archive_bytes, check_magic_bytes=False
      ):
        return on_leaf(archive_bytes, True, False)
      return False

    if utils.peek_bytes(normalized_data, 6) == b"\x93NUMPY":
      offset = utils.find_pickle_start_offset(normalized_data)
      if offset <= 0:
        return False
      if isinstance(normalized_data, (bytes, mmap.mmap)):
        return on_leaf(normalized_data[offset:], True, False)
      normalized_data.seek((original_pos or 0) + offset)
      return on_leaf(normalized_data, True, False)

    leaf_data = normalized_data
    if advance_to_pickle or (
        force_scan
        and not utils.is_pickle_file(
            normalized_data, check_magic_bytes=check_magic_bytes
        )
    ):
      offset = utils.find_pickle_start_offset(normalized_data)
      if offset > 0:
        if isinstance(normalized_data, (bytes, mmap.mmap)):
          leaf_data = normalized_data[offset:]
        else:
          normalized_data.seek((original_pos or 0) + offset)

    return on_leaf(leaf_data, force_scan, check_magic_bytes)
  finally:
    _safe_seek(normalized_data, original_pos)


def strict_security_scan(
    pickle_bytes: bytes | BinaryIO,
    recursion_depth: int = 0,
    *,
    _remaining_budget: Optional[list[int]] = None,
) -> bool:
  """Strict security scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    recursion_depth: Current archive recursion depth.
    _remaining_budget: Internal cumulative decompression byte budget tracker.

  Returns:
    True if the pickle file is dangerous, False otherwise.
  """

  def _strict_leaf(
      leaf_data: bytes | IO[bytes],
      unused_force_scan: bool,
      unused_check_magic: bool,
  ) -> bool:
    return _strict_security_scan_stream(leaf_data)

  def _strict_error(unused_error_tag: str) -> bool:
    return True

  return _scan_payload_tree(
      pickle_bytes,
      _strict_leaf,
      _strict_error,
      advance_to_pickle=True,
      recursion_depth=recursion_depth,
      remaining_budget=_remaining_budget,
  )


def _merge_scan_results(target: ScanResults, source: ScanResults) -> None:
  """Merges findings from `source` into `target` in place."""
  target.safe_results.update(source.safe_results)
  target.unsafe_results.update(source.unsafe_results)
  target.suspicious_results.update(source.suspicious_results)
  target.unknown_results.update(source.unknown_results)
  target.is_denylisted = target.is_denylisted or source.is_denylisted


def _scan_bytes_generic(
    data: bytes | IO[bytes],
    scan_func: Callable[[bytes | IO[bytes]], ScanResults],
    recursion_depth: int = 0,
    *,
    force_scan: bool = False,
    check_magic_bytes: bool = True,
    remaining_budget: Optional[list[int]] = None,
) -> ScanResults:
  """Scans `data` recursively via `_scan_payload_tree` and merges `ScanResults`.

  Args:
    data: Raw bytes or binary stream to scan.
    scan_func: Single-payload scan callable returning `ScanResults`.
    recursion_depth: Current archive recursion depth.
    force_scan: Whether to scan archive entries when `is_pickle_file` is False.
    check_magic_bytes: Whether to enable magic-byte fast rejection.
    remaining_budget: Optional shared decompression byte budget tracker.

  Returns:
    The combined `ScanResults` produced by scanning `data`.

  Raises:
    MaxRecursionDepthExceededError: If `recursion_depth` exceeds the limit.
  """
  combined = ScanResults()

  def _handle_leaf(
      leaf_data: bytes | IO[bytes],
      unused_force_scan: bool,
      unused_check_magic: bool,
  ) -> bool:
    _merge_scan_results(combined, scan_func(leaf_data))
    return False

  def _handle_error(error_tag: str) -> bool:
    combined.unsafe_results.add(error_tag)
    return True

  _scan_payload_tree(
      data,
      _handle_leaf,
      _handle_error,
      force_scan=force_scan,
      check_magic_bytes=check_magic_bytes,
      recursion_depth=recursion_depth,
      remaining_budget=remaining_budget,
  )
  return combined


def _picklemagic_scan_internal(
    pickle_bytes: bytes | IO[bytes],
) -> ScanResults:
  """Picklemagic scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    A ScanResults object.
  """
  picklemagic_output, was_unsafe_build_blocked, has_scan_error = (
      get_class_instantiations(pickle_bytes)  # pyrefly: ignore[bad-argument-type]
  )
  results = categorize_strings(picklemagic_output, use_picklemagic=True)
  if was_unsafe_build_blocked:
    results.suspicious_results.add("unsafe_state_assignment")
  if has_scan_error:
    results.suspicious_results.add("sandbox_unpickling_error")

  return results


def picklemagic_scan(
    pickle_bytes: bytes | IO[bytes],
    *,
    check_magic_bytes: bool = True,
) -> ScanResults:
  """Picklemagic scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    check_magic_bytes: Whether to enable magic-byte fast rejection in archives.

  Returns:
    A ScanResults object.
  """
  return _scan_bytes_generic(
      pickle_bytes,
      _picklemagic_scan_internal,
      check_magic_bytes=check_magic_bytes,
  )


def _genops_scan_internal(
    pickle_bytes: bytes | IO[bytes],
    pickle_file_path: Optional[str] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> ScanResults:
  """Runs the internal opcode-disassembly (`genops`) scan on a single payload.

  Selects between multi-worker chunked scanning (`generate_ops_from_file`)
  for file paths or buffers at least `MIN_SIZE_FOR_CHUNKING` bytes and
  single-pass in-memory scanning (`generate_ops`), then categorizes
  discovered operands.

  Args:
    pickle_bytes: Pickle byte buffer or binary stream to scan.
    pickle_file_path: Optional filesystem path for direct file/mmap chunking.
    fail_fast: Whether to stop scanning immediately upon finding an unsafe or
      suspicious operand.
    pickle_length: Optional byte length of the pickle payload.

  Returns:
    A `ScanResults` object containing categorized safe, unsafe, suspicious,
    and unknown symbols.
  """
  if pickle_file_path:
    genops_output = generate_ops_from_file(
        pickle_file_path,
        pickle_length=pickle_length,
        fail_fast=fail_fast,
    )
    return categorize_strings(genops_output)

  resolved_pickle_length = _resolve_pickle_length(pickle_bytes, pickle_length)
  if resolved_pickle_length >= constants.MIN_SIZE_FOR_CHUNKING:
    if isinstance(pickle_bytes, (bytes, mmap.mmap)):
      data_buffer = pickle_bytes
    elif isinstance(pickle_bytes, (bytearray, memoryview)):
      data_buffer = bytes(pickle_bytes)
    elif isinstance(pickle_bytes, io.BytesIO):
      cur_pos = pickle_bytes.tell()
      full_bytes = pickle_bytes.getvalue()
      data_buffer = full_bytes if cur_pos == 0 else full_bytes[cur_pos:]
    else:
      cur_pos = _get_stream_pos(pickle_bytes)
      try:
        data_buffer = pickle_bytes.read()
      finally:
        if cur_pos is not None:
          try:
            pickle_bytes.seek(cur_pos)
          except (OSError, AttributeError, io.UnsupportedOperation):
            pass

    genops_output = generate_ops_from_file(
        "",
        pickle_length=resolved_pickle_length,
        fail_fast=fail_fast,
        data_buffer=data_buffer,
    )
  else:
    genops_output = generate_ops(pickle_bytes, fail_fast=fail_fast)

  results = categorize_strings(genops_output)
  return results


def genops_scan(
    pickle_bytes: bytes | IO[bytes],
    pickle_file_path: Optional[str] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
    *,
    check_magic_bytes: bool = True,
) -> ScanResults:
  """Genops scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data in bytes.
    check_magic_bytes: Whether to enable magic-byte fast rejection in archives.

  Returns:
    A ScanResults object.
  """
  if (
      utils.detect_archive_type(pickle_bytes) is not None
      or utils.peek_bytes(pickle_bytes, 6) == b"\x93NUMPY"
  ):
    scan_slice = functools.partial(_genops_scan_internal, fail_fast=fail_fast)
    return _scan_bytes_generic(
        pickle_bytes,
        scan_slice,
        check_magic_bytes=check_magic_bytes,
    )
  return _genops_scan_internal(
      pickle_bytes,
      pickle_file_path=pickle_file_path,
      fail_fast=fail_fast,
      pickle_length=pickle_length,
  )


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

  result_scores = (
      round(safe_score),
      round(unsafe_score),
      round(suspicious_score),
      round(unknown_score),
  )
  return result_scores


def apply_approach(
    scan_approach: Callable[..., ScanResults],
    pickle_bytes: bytes | IO[bytes],
    pickle_file_path: Optional[str] = None,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> Dict[str, int]:
  """Applies the given scan approach to the data.

  Args:
    scan_approach: The scan approach to apply to the data.
    pickle_bytes: The data to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data.

  Returns:
    A dictionary of the resulting scores.
  """
  if scan_approach in (genops_scan, _genops_scan_internal):
    results = scan_approach(
        pickle_bytes,
        pickle_file_path=pickle_file_path,
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
      _,
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
          len(results.safe_results),
          len(results.unsafe_results),
          len(results.suspicious_results),
      )
  ):
    return scores

  scores["unsafe"] = 0
  scores["suspicious"] = 0
  return scores


def _merge_scores(total: Dict[str, int], new: Dict[str, int]) -> None:
  """Adds `unsafe`, `suspicious`, and `unknown` counts from `new` into `total`."""
  total["unsafe"] += new.get("unsafe", 0)
  total["suspicious"] += new.get("suspicious", 0)
  total["unknown"] += new.get("unknown", 0)


def security_scan(
    pickle_bytes: bytes | IO[bytes],
    force_scan: bool = False,
    recursion_depth: int = 0,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
    *,
    _remaining_budget: Optional[list[int]] = None,
) -> Dict[str, int]:
  """Security scan to detect malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    recursion_depth: Current recursion depth for nested archives.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    check_magic_bytes: Whether to perform magic byte checks.
    _remaining_budget: Internal cumulative decompression byte budget tracker.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    results.
  """
  all_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}

  def _score_leaf(
      leaf_data: bytes | IO[bytes],
      leaf_force_scan: bool,
      leaf_check_magic: bool,
  ) -> bool:
    scores = _security_scan_internal(
        leaf_data,
        force_scan=leaf_force_scan,
        fail_fast=fail_fast,
        check_magic_bytes=leaf_check_magic,
    )
    _merge_scores(all_scores, scores)
    return False

  def _score_error(unused_error_tag: str) -> bool:
    all_scores["unsafe"] = constants.HIGH_SEVERITY_ZIPSLIP
    all_scores["suspicious"] = 0
    all_scores["unknown"] = 0
    return True

  _scan_payload_tree(
      pickle_bytes,
      _score_leaf,
      _score_error,
      force_scan=force_scan,
      check_magic_bytes=check_magic_bytes,
      recursion_depth=recursion_depth,
      remaining_budget=_remaining_budget,
  )
  return all_scores


def _security_scan_internal(
    pickle_bytes: bytes | IO[bytes],
    force_scan: bool = False,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
) -> Dict[str, int]:
  """Security scan to detect malicious content in a single pickle payload.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.
    force_scan: If True, force scan even if the file is not a pickle file.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    check_magic_bytes: Whether to perform magic byte checks.

  Returns:
    A dictionary containing the scores for unsafe, suspicious, and unknown
    finds.
  """
  normalized = utils.ensure_seekable_stream(pickle_bytes)
  if isinstance(normalized, (bytes, mmap.mmap)):
    raw_bytes = bytes(normalized)
    stream: IO[bytes] = io.BytesIO(raw_bytes)
    pickle_length = len(raw_bytes)
  else:
    stream = normalized
    current_pos = stream.tell()
    stream.seek(0, io.SEEK_END)
    pickle_length = stream.tell()
    stream.seek(current_pos)

  try:
    is_pickle = utils.is_pickle_file(
        stream, check_magic_bytes=check_magic_bytes
    )
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    is_pickle = False

  if not is_pickle and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  if not is_pickle or utils.peek_bytes(stream, 6) == b"\x93NUMPY":
    try:
      current_pos = stream.tell()
      start_offset = utils.find_pickle_start_offset(stream)
      if start_offset > 0:
        stream.seek(current_pos + start_offset)
        pickle_length -= current_pos + start_offset
      else:
        stream.seek(current_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass

  original_stream_pos = _get_stream_pos(stream)

  try:
    final_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}
    for scan_approach in (_picklemagic_scan_internal, _genops_scan_internal):
      scores = apply_approach(
          scan_approach,
          stream,
          fail_fast=fail_fast,
          pickle_length=pickle_length,
      )
      _safe_seek(stream, original_stream_pos)
      if scores["unsafe"] > 0 and scores["unsafe"] > scores["suspicious"]:
        return scores
      _merge_scores(final_scores, scores)

    return final_scores
  finally:
    _safe_seek(stream, original_stream_pos)


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


def _scan_or_report(
    scan_fn: Callable[..., Any],
    fallback: Any,
    report_only: bool,
    log_info: bool,
    *args: Any,
    **kwargs: Any,
) -> Any:
  """Runs `scan_fn`; report-only mode logs scanner errors and returns `fallback`."""
  try:
    return scan_fn(*args, **kwargs)
  except Exception as exc:  # pylint: disable=broad-exception-caught
    # Report-only mode must never block a load, even when the scanner fails.
    if not report_only:
      raise
    logging_function = logging.info if log_info else logging.error
    logging_function("Security scan failed: %s", exc)
    return fallback


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
      if utils.detect_archive_type(pickle_file) is None:
        start_offset = utils.find_pickle_start_offset(pickle_file)
      else:
        start_offset = 0

      if start_offset > 0:
        pickle_file.seek(current_pos + start_offset)
      else:
        pickle_file.seek(current_pos)
    except (OSError, AttributeError, io.UnsupportedOperation):
      pass

    scan_source = pickle_file
  else:
    if not isinstance(pickle_file_or_bytes, bytes):
      raise TypeError("pickle_file_or_bytes must be bytes when is_load=False")
    data_bytes = pickle_file_or_bytes
    if utils.detect_archive_type(data_bytes) is None:
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
    if _scan_or_report(
        strict_security_scan, False, report_only, log_info, scan_source
    ):
      error_string_strict_check = "Pickle file failed strict security check."
      if report_only:
        logging.error(error_string_strict_check)
        return
      raise StrictCheckError(error_string_strict_check)
  else:
    # Default scanning routines
    scan_scores = _scan_or_report(
        security_scan,
        {"unsafe": 0, "suspicious": 0, "unknown": 0},
        report_only,
        log_info,
        scan_source,
        force_scan=force_scan,
        check_magic_bytes=check_magic_bytes,
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

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
import mmap
import pickle
import pickletools
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


DEFAULT_FAIL_FAST = True


@dataclasses.dataclass
class ScanResults:
  """Results from a pickle security scan."""

  safe_results: Set[str] = dataclasses.field(default_factory=set)
  unsafe_results: Set[str] = dataclasses.field(default_factory=set)
  suspicious_results: Set[str] = dataclasses.field(default_factory=set)
  unknown_results: Set[str] = dataclasses.field(default_factory=set)
  is_denylisted: bool = False
  has_scannable_payload: bool = False


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

  if not utils.is_seekable_stream(pickle_bytes):
    return 0

  cur_pos = _get_stream_pos(pickle_bytes)
  if cur_pos is None:
    return 0

  try:
    end_pos = pickle_bytes.seek(0, io.SEEK_END)
  except (OSError, AttributeError, io.UnsupportedOperation):
    return 0
  finally:
    _safe_seek(pickle_bytes, cur_pos)

  return max(0, end_pos - cur_pos)


def _safe_seek(stream: Any, position: Optional[int]) -> None:
  """Restores `stream` to `position` if seekable."""
  if position is None or not hasattr(stream, "seek"):
    return
  try:
    stream.seek(position)
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    logging.debug("Failed to seek stream back to position %s.", position)


def _extract_genops_buffer(
    pickle_bytes: bytes | IO[bytes],
) -> tuple[bytes | mmap.mmap, int]:
  """Extracts an in-memory buffer and start offset while preserving stream pos."""
  if isinstance(pickle_bytes, (bytes, mmap.mmap)):
    return pickle_bytes, 0
  if isinstance(pickle_bytes, (bytearray, memoryview)):
    return bytes(pickle_bytes), 0
  if isinstance(pickle_bytes, io.BytesIO):
    return pickle_bytes.getvalue(), pickle_bytes.tell()

  start_position = _get_stream_pos(pickle_bytes)
  try:
    return pickle_bytes.read(-1), 0
  finally:
    _safe_seek(pickle_bytes, start_position)


def _custom_genops(
    pickle_bytes: bytes | BinaryIO,
) -> Iterator[tuple[Optional[pickletools.OpcodeInfo], Any | None]]:
  """Generates string-declaring opcodes and their arguments from pickle data.

  Args:
    pickle_bytes: The pickle data to generate opcodes from.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """
  data_buffer, start_offset = _extract_genops_buffer(pickle_bytes)
  yield from utils.custom_genops_from_bytes(data_buffer, start=start_offset)


def _should_collect_operand(
    opcode: Optional[pickletools.OpcodeInfo], operand_str: str
) -> bool:
  """Checks whether a disassembled opcode operand should be collected."""
  if opcode is not None and opcode.name in constants.IMPORT_OPCODES:
    return True
  return utils.is_potentially_dangerous_literal(operand_str)


def _scan_byte_slice(
    data: bytes | mmap.mmap,
    start: int,
    end: int,
    seed_stack: Sequence[Optional[str]] = (),
    fail_fast: bool = False,
    abort_event: Optional[threading.Event] = None,
    seed_memo: Optional[Mapping[int, Optional[str]]] = None,
) -> Set[str]:
  """Scans an opcode-aligned byte slice and collects string-declaring operands.

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
  for chunk_index, (opcode, operand) in enumerate(
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
      if not _should_collect_operand(opcode, operand_string):
        continue
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

  if effective_length < constants.MIN_SIZE_FOR_CHUNKING or num_workers <= 1:
    return _scan_byte_slice(
        pickle_bytes, 0, effective_length, fail_fast=bool(fail_fast)
    )

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
  """Returns string-declaring opcodes from a pickle buffer or stream.

  Args:
    pickle_bytes: The pickle bytecode or stream to yield opcode information for.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.

  Returns:
    The operands associated with the opcodes that declare strings.
  """
  data_buffer, start_offset = _extract_genops_buffer(pickle_bytes)
  return _scan_byte_slice(
      data_buffer, start_offset, len(data_buffer), fail_fast=bool(fail_fast)
  )


def _decode_bytes_or_str(value: Any) -> str | None:
  """Decodes `bytes` as UTF-8 or returns `value` if already a `str`."""
  if isinstance(value, bytes):
    return value.decode("utf-8", errors="ignore")
  if isinstance(value, str):
    return value
  return None


class _SaferFakeWarning(picklemagic.FakeWarning):
  """FakeWarning subclass supporting dict/list population opcodes in sandbox."""

  __module__ = "corrupy.picklemagic"

  def __new__(cls, *args: Any, **kwargs: Any) -> Any:
    """Allocates a sandboxed `FakeWarning` instance and records `kwargs`."""
    instance = super().__new__(cls, *args, **kwargs)
    if kwargs:
      instance._new_kwargs = kwargs
    return instance

  def __setitem__(self, key: Any, value: Any) -> None:
    """Records item assignment on the fake instance during `SETITEM`."""
    self.__dict__[str(key)] = value

  def append(self, value: Any) -> None:
    """Records an appended element on the fake instance during `APPEND`."""
    self.__dict__.setdefault("_list_items", []).append(value)

  def extend(self, values: Any) -> None:
    """Records extended elements on the fake instance during `APPENDS`."""
    self.__dict__.setdefault("_list_items", []).extend(values)


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
      """Reads a line from the stream and normalizes trailing CRLF to LF."""
      line = original_file_readline()
      return line[:-2] + b"\n" if line.endswith(b"\r\n") else line

    self._file_readline = _normalized_readline

    self.dispatch = self.dispatch.copy()
    self.dispatch[pickle.BINBYTES[0]] = self._load_binbytes_fast
    self.dispatch[pickle.BINSTRING[0]] = self._load_binstring_fast
    self.dispatch[pickle.BINBYTES8[0]] = self._load_binbytes8_fast
    self.dispatch[pickle.BYTEARRAY8[0]] = self._load_bytearray8_fast

  def find_class(self, module: Any, name: Any) -> Any:
    """Resolves a pickle global reference into a sandbox `FakeClass` object.

    Args:
      module: Module name token (as `str` or `bytes`) from
        `GLOBAL`/`STACK_GLOBAL`.
      name: Attribute name token (as `str` or `bytes`) from
        `GLOBAL`/`STACK_GLOBAL`.

    Returns:
      A `picklemagic` fake class representing `module.name` in the sandbox.
    """
    module, name = (
        (
            raw_token.decode("utf-8", "replace")
            if isinstance(raw_token, bytes)
            else str(raw_token)
        ).rstrip("\r\n")
        for raw_token in (module, name)
    )

    if module == "__main__":
      std_logging.getLogger("corrupy.picklemagic").warning(
          "Unsafe module/class invoked: %s.%s", module, name
      )
      return self.class_factory(name, module)

    full_name = f"{module}.{name}" if module and name else (module or name)
    deny_list = config.get_deny_list()
    allow_list = config.get_allow_list()
    pm_logger = std_logging.getLogger("corrupy.picklemagic")

    if utils.matches_symbol_prefix_list(full_name, deny_list):
      pm_logger.warning("Unsafe module/class invoked: %s", full_name)
      return self.class_factory(name, module)

    is_allowlisted = not utils.is_self_protected_symbol(
        full_name
    ) and utils.matches_symbol_prefix_list(full_name, allow_list)
    if not is_allowlisted:
      cls_verdict = utils.classify_symbol(full_name)
      if cls_verdict == utils.Classification.UNSAFE:
        pm_logger.warning("Unsafe module/class invoked: %s", full_name)
        return self.class_factory(name, module)
      if cls_verdict in (
          utils.Classification.UNKNOWN,
          utils.Classification.SUSPICIOUS,
      ):
        pm_logger.warning("Unknown module/class imported: %s", full_name)
        return self.class_factory(name, module)

    pm_logger.warning("Safe module/class imported: %s", full_name)
    cls = self.class_factory(name, module)
    if is_allowlisted or full_name != "functools.partial":
      setattr(cls, "_is_safe_symbol", True)
    return cls

  def get_extension(self, code: int) -> None:
    """Resolves a `copyreg` extension code and pushes its fake class onto stack.

    Maps `code` via `utils.resolve_extension_code`, delegates registered
    `"module.name"` targets to `self.find_class`, or logs and pushes an
    unregistered extension placeholder.

    Args:
      code: Integer extension code from `EXT1`, `EXT2`, or `EXT4`.

    Returns:
      None.
    """
    resolved = utils.resolve_extension_code(code)
    if "." in resolved and not resolved.startswith("unregistered_extension."):
      mod, name = resolved.rsplit(".", 1)
      self.append(self.find_class(mod, name))
      return
    std_logging.getLogger("corrupy.picklemagic").warning(
        "Unknown module/class imported: %s", resolved
    )
    self.append(self.class_factory(resolved, "copyreg"))

  def persistent_load(self, pid: Any) -> Any:
    """Inspects a `PERSID`/`BINPERSID` identifier and returns a fake object.

    Args:
      pid: Persistent identifier popped from the unpickler stack or read from
        the stream.

    Returns:
      A sandboxed `FakeClass` instance representing the persistent object.
    """
    if self._state_contains_fake_class(pid):
      self.has_blocked_unsafe_build_instr = True
    pm_logger = std_logging.getLogger("corrupy.picklemagic")

    if (
        isinstance(pid, tuple)
        and len(pid) >= 2
        and pid[0] in ("storage", b"storage")
    ):
      for element in pid[1:]:
        element_str = _decode_bytes_or_str(element)
        if element_str is not None:
          clean_element = element_str.replace("\r", "\\r").replace("\n", "\\n")
          if utils.is_potentially_dangerous_literal(element_str):
            pm_logger.warning("Unsafe module/class invoked: %s", clean_element)
          elif not utils.is_benign_storage_arg(element_str):
            pm_logger.warning(
                "Unknown module/class imported: persistent_id.%s", clean_element
            )
      return self.class_factory("Storage", "torch")()

    decoded_pid = _decode_bytes_or_str(pid)
    pid_str = decoded_pid if decoded_pid is not None else str(pid)
    clean_pid_str = pid_str.replace("\r", "\\r").replace("\n", "\\n")
    if utils.is_potentially_dangerous_literal(pid_str):
      pm_logger.warning("Unsafe module/class invoked: %s", clean_pid_str)
    else:
      pm_logger.warning(
          "Unknown module/class imported: persistent_id.%s", clean_pid_str
      )
    return self.class_factory("PersistentObject", "persistent_id")()

  def _state_has_dangerous_keys(self, state: Any) -> bool:
    """Checks whether a `BUILD` state payload overwrites dangerous attributes.

    Args:
      state: The state argument popped or inspected during the `BUILD` opcode.

    Returns:
      True if `state` attempts to set a dangerous or non-metadata dunder
      attribute, or False otherwise.
    """
    dicts_to_check = []
    visited_dict_ids = set()

    def _enqueue_dict(candidate_dict: dict[Any, Any]) -> None:
      """Appends `candidate_dict` once while tracking visited `id()` values.

      Args:
        candidate_dict: State dictionary to queue for dangerous-key inspection.

      Returns:
        None.
      """
      dict_id = id(candidate_dict)
      if dict_id in visited_dict_ids:
        return
      visited_dict_ids.add(dict_id)
      dicts_to_check.append(candidate_dict)

    if isinstance(state, dict):
      _enqueue_dict(state)
    elif isinstance(state, tuple) and len(state) == 2:
      if isinstance(state[0], dict):
        _enqueue_dict(state[0])
      if isinstance(state[1], dict):
        _enqueue_dict(state[1])

    for state_dict in dicts_to_check:
      for key, val in state_dict.items():
        key_str = _decode_bytes_or_str(key)
        if key_str == "__dict__" and isinstance(val, dict):
          _enqueue_dict(val)
          continue
        if key_str in constants.DANGEROUS_BUILD_STATE_KEYS:
          return True
    return False

  def load_build(self, *unused_args: Any) -> None:
    """Validates and applies the `BUILD` opcode within the unpickler sandbox.

    Blocks `BUILD` instructions that overwrite dangerous dunder keys, target
    class/type objects directly, or inject suspicious `FakeClass` instances
    into state, and fast-paths benign state application on verified-safe
    symbols.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    if not self.stack:
      return

    if self._state_has_dangerous_keys(self.stack[-1]):
      self.has_blocked_unsafe_build_instr = True
      self.stack.pop()
      return

    state = self.stack[-1]
    inst = self.stack[-2] if len(self.stack) >= 2 else None
    is_type_target = isinstance(inst, picklemagic.FakeClassType) or (
        isinstance(inst, type) and issubclass(inst, picklemagic.FakeClass)
    )
    if is_type_target or self._state_contains_fake_class(
        state, only_suspicious=True
    ):
      self.has_blocked_unsafe_build_instr = True
      self.stack.pop()
      return

    if type(inst).__dict__.get("_is_safe_symbol", False):
      self.stack.pop()
      return

    if not isinstance(inst, picklemagic.FakeClass) and (
        self._state_contains_fake_class(state)
    ):
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

  @staticmethod
  def _is_cacheable_safe_arg(arg: Any) -> bool:
    """Checks whether a `REDUCE` argument is side-effect-free and cacheable.

    Args:
      arg: Single positional argument from a `REDUCE` argument tuple.

    Returns:
      True if `arg` is safe to reuse across cached `REDUCE` invocations, or
      False otherwise.
    """
    if isinstance(arg, (int, float, bytes, bytearray, bool, type(None))):
      return True

    arg_type = type(arg)
    if arg_type.__dict__.get("_is_safe_symbol", False):
      instance_dict = getattr(arg, "__dict__", None)
      if isinstance(instance_dict, dict):
        for attribute_key, attribute_value in instance_dict.items():
          if not attribute_key.startswith("_") and isinstance(
              type(attribute_value), picklemagic.FakeClassType
          ):
            return False
      return True

    if arg_type is picklemagic.FakeClassType and arg.__dict__.get(
        "_is_safe_symbol", False
    ):
      return True

    if isinstance(arg, tuple) and len(arg) <= 8:
      return all(
          isinstance(
              tuple_item, (int, float, bytes, bytearray, bool, type(None))
          )
          for tuple_item in arg
      )
    return False

  def load_reduce(self, *unused_args: Any) -> None:
    """Executes the `REDUCE` opcode safely within the `picklemagic` sandbox.

    Verifies that the target callable is a sandboxed `FakeClass` via
    `_is_sandbox_callable`, flags suspicious `FakeClass` arguments, reuses
    cached instances for repeated safe tensor/array reconstructions, and
    replaces failed reductions with a `picklemagic.failed_reduce` placeholder.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.
    """
    stack = self.stack
    args = stack.pop()
    func = stack[-1]

    is_safe_func = isinstance(func, type) and func.__dict__.get(
        "_is_safe_symbol", False
    )
    if self._state_contains_fake_class(args, only_suspicious=True):
      self.has_blocked_unsafe_build_instr = True

    if (
        is_safe_func
        and not self.has_blocked_unsafe_build_instr
        and isinstance(args, tuple)
    ):
      cached_inst = func.__dict__.get("_cached_safe_instance")
      if cached_inst is not None and all(
          self._is_cacheable_safe_arg(arg_item) for arg_item in args
      ):
        stack[-1] = cached_inst
        return

    try:
      stack[-1] = func(*args)
      if (
          is_safe_func
          and not self.has_blocked_unsafe_build_instr
          and isinstance(args, tuple)
          and all(self._is_cacheable_safe_arg(arg_item) for arg_item in args)
      ):
        setattr(func, "_cached_safe_instance", stack[-1])
    except Exception as e:  # pylint: disable=broad-exception-caught
      std_logging.getLogger("corrupy.picklemagic").warning(
          "Failed to reduce %s with %s: %s", func, args, e
      )
      stack[-1] = self.class_factory("failed_reduce", "picklemagic")()

  def _read_exact(self, length: int) -> bytes:
    """Reads `length` bytes from stream or raises `EOFError` if truncated."""
    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")
    return data

  def _skip_bytes_in_stream(self, length: int) -> None:
    """Advances the active pickle stream by `length` bytes.

    Args:
      length: Number of payload bytes to advance past in the stream.

    Raises:
      pickle.UnpicklingError: If `length` is negative.
      EOFError: If the stream ends before `length` bytes are available.
    """
    if length < 0:
      raise pickle.UnpicklingError("BINBYTES/BYTEARRAY count < 0")

    unframer = getattr(self, "_unframer", None)
    current_frame = getattr(unframer, "current_frame", None)
    target_stream = (
        current_frame if current_frame is not None else self._raw_stream
    )
    if (
        length > 4096
        and hasattr(target_stream, "seek")
        and hasattr(target_stream, "tell")
    ):
      cur_pos = target_stream.tell()
      target_stream.seek(0, io.SEEK_END)
      end_pos = target_stream.tell()
      if cur_pos + length > end_pos:
        target_stream.seek(end_pos)
        raise EOFError("Truncated binary payload in pickle stream")

      target_stream.seek(cur_pos + length)
      return

    self._read_exact(length)

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
    if length > 4096:
      self._skip_bytes_in_stream(length)
      self.append(bytearray() if as_bytearray else b"")
      return

    data = self._read_exact(length)
    self.append(bytearray(data) if as_bytearray else data)

  def _load_binstring_fast(self, *unused_args: Any) -> None:
    """Loads a 4-byte signed-length `BINSTRING` payload, skipping large tails.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Raises:
      pickle.UnpicklingError: If the unpacked 4-byte signed length is negative.
      EOFError: If the stream ends before `length` bytes are available.
    """
    (length,) = struct.unpack("<i", self.read(4))
    if length < 0:
      raise pickle.UnpicklingError("BINSTRING count < 0")
    if length > 4096:
      prefix = self._read_exact(4096)
      self._skip_bytes_in_stream(length - 4096)
      self.append(self._decode_string(prefix))
      return

    data = self._read_exact(length)
    self.append(self._decode_string(data))

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

  def _state_contains_fake_class(  # pyrefly: ignore[bad-override]
      self,
      object_to_inspect: Any,
      visited_object_ids: Optional[Set[int]] = None,
      only_suspicious: bool = False,
      inspection_depth: int = 0,
  ) -> bool:
    """Recursively inspects an object graph for `FakeClass` instances or types.

    Traverses containers, `__dict__` attributes, and `__slots__` while tracking
    visited object IDs to avoid infinite recursion on cyclic graphs.

    Args:
      object_to_inspect: Object or state container to inspect.
      visited_object_ids: Set of already-visited `id(obj)` integers.
      only_suspicious: If True, ignores `FakeClass` objects marked with
        `_is_safe_symbol`.
      inspection_depth: Current recursion depth within the inspected object
        graph.

    Returns:
      True if a matching `FakeClass` instance or type is found, or False
      otherwise.
    """
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

    # Multiple checks below involve checking FakeClasses, dicts, sets,
    # lists, __slots__ and tuples

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
      allow_list = config.get_allow_list()
      deny_list = config.get_deny_list()
      if utils.matches_symbol_prefix_list(full_symbol_name, deny_list):
        return True
      if utils.is_self_protected_symbol(full_symbol_name):
        return True
      if utils.matches_symbol_prefix_list(full_symbol_name, allow_list):
        return False
      if not full_symbol_name or module_name == "picklemagic":
        return True

      cls_verdict = utils.classify_symbol(full_symbol_name)
      if cls_verdict == utils.Classification.SAFE:
        return False
      if only_suspicious:
        return cls_verdict in (
            utils.Classification.UNSAFE,
            utils.Classification.SUSPICIOUS,
        )
      return True

    if isinstance(object_to_inspect, (list, tuple, set, frozenset)):
      return any(
          self._state_contains_fake_class(
              element, visited_object_ids, only_suspicious, inspection_depth + 1
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


_PICKLEMAGIC_LOGGER_LOCK = threading.Lock()
_PICKLEMAGIC_ACTIVE_SCANS = 0
_PICKLEMAGIC_ORIG_LEVEL: Optional[int] = None
_PICKLEMAGIC_ORIG_PROPAGATE: Optional[bool] = None


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
  global _PICKLEMAGIC_ACTIVE_SCANS
  global _PICKLEMAGIC_ORIG_LEVEL
  global _PICKLEMAGIC_ORIG_PROPAGATE

  picklemagic_output = io.StringIO()
  unpickler = None
  has_scan_error = False

  target_thread_id = threading.get_ident()

  def _matches_target_thread(record: std_logging.LogRecord) -> bool:
    return record.thread == target_thread_id

  handler = std_logging.StreamHandler(picklemagic_output)
  handler.setFormatter(std_logging.Formatter("%(message)s"))
  handler.addFilter(_matches_target_thread)
  logger = std_logging.getLogger("corrupy.picklemagic")

  with _PICKLEMAGIC_LOGGER_LOCK:
    if _PICKLEMAGIC_ACTIVE_SCANS == 0:
      _PICKLEMAGIC_ORIG_LEVEL = logger.level
      _PICKLEMAGIC_ORIG_PROPAGATE = logger.propagate
      logger.setLevel(std_logging.WARNING)
      logger.propagate = False
    _PICKLEMAGIC_ACTIVE_SCANS += 1
    logger.addHandler(handler)

  # Handle stream seek-back if necessary
  original_pos = None
  if isinstance(pickle_bytes, bytes):
    pickle_stream = io.BytesIO(pickle_bytes)
  else:
    original_pos = pickle_bytes.tell()
    pickle_stream = pickle_bytes

  try:
    try:
      factory = picklemagic.FakeClassFactory([], _SaferFakeWarning)

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
    with _PICKLEMAGIC_LOGGER_LOCK:
      logger.removeHandler(handler)
      _PICKLEMAGIC_ACTIVE_SCANS -= 1
      if _PICKLEMAGIC_ACTIVE_SCANS == 0:
        if _PICKLEMAGIC_ORIG_LEVEL is not None:
          logger.setLevel(_PICKLEMAGIC_ORIG_LEVEL)
        if _PICKLEMAGIC_ORIG_PROPAGATE is not None:
          logger.propagate = _PICKLEMAGIC_ORIG_PROPAGATE
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
  deny_list = config.get_deny_list()
  allow_list = config.get_allow_list()

  try:
    for opcode, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
      if operand is None:
        continue
      stmt = str(operand)
      if opcode is not None and opcode.name in constants.IMPORT_OPCODES:
        if utils.matches_symbol_prefix_list(stmt, deny_list):
          return True
        is_allowed = not utils.is_self_protected_symbol(
            stmt
        ) and utils.matches_symbol_prefix_list(stmt, allow_list)
        if (
            not is_allowed
            and utils.classify_symbol(stmt) != utils.Classification.SAFE
        ):
          return True
      elif utils.is_potentially_dangerous_literal(stmt):
        return True

    _safe_seek(pickle_bytes, original_pos)

    instantiations_output, was_unsafe_build_blocked, has_scan_error = (
        get_class_instantiations(pickle_bytes)
    )

    if was_unsafe_build_blocked or has_scan_error:
      return True

    pm_results = categorize_strings(instantiations_output, use_picklemagic=True)
    if (
        pm_results.is_denylisted
        or pm_results.unsafe_results
        or pm_results.suspicious_results
        or pm_results.unknown_results
    ):
      return True
  finally:
    _safe_seek(pickle_bytes, original_pos)

  return False


_STREAM_ARCHIVE_EXTRACTORS = types.MappingProxyType({
    "bz2": utils.extract_bz2_contents,
    "lzma": utils.extract_lzma_contents,
    "gzip": utils.extract_gzip_contents,
    "zlib": utils.extract_zlib_contents,
    "lz4": utils.extract_lz4_contents,
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
          bytes(normalized_data)
          if isinstance(normalized_data, (bytes, mmap.mmap))
          else normalized_data.read()
      )
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
      except utils.ARCHIVE_EXTRACTION_ERRORS as exc:
        logging.warning("Error processing %s archive: %s", archive_type, exc)
        return on_error("archive_extraction_error")

      # The raw bytes may also load as a pickle, so they are scanned as one too.
      # `PK`-prefixed ZIPs are skipped: their local header is not a loadable
      # pickle start and benign checkpoints would trip the pickle heuristic.
      is_prefix_zip = archive_type == "zip" and utils.is_zip_bytes(
          archive_bytes
      )
      if not is_prefix_zip and utils.is_pickle_file(
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


def strict_security_scan(pickle_bytes: bytes | BinaryIO) -> bool:
  """Strict security scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode or stream to scan.

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
  )


def _merge_scan_results(target: ScanResults, source: ScanResults) -> None:
  """Merges findings from `source` into `target` in place."""
  target.safe_results.update(source.safe_results)
  target.unsafe_results.update(source.unsafe_results)
  target.suspicious_results.update(source.suspicious_results)
  target.unknown_results.update(source.unknown_results)
  target.is_denylisted = target.is_denylisted or source.is_denylisted
  target.has_scannable_payload = (
      target.has_scannable_payload or source.has_scannable_payload
  )


def _scan_bytes_generic(
    data: bytes | IO[bytes],
    scan_func: Callable[[bytes | IO[bytes]], ScanResults],
    *,
    check_magic_bytes: bool = True,
) -> ScanResults:
  """Scans `data` recursively via `_scan_payload_tree` and merges `ScanResults`.

  Args:
    data: Raw bytes or binary stream to scan.
    scan_func: Single-payload scan callable returning `ScanResults`.
    check_magic_bytes: Whether to enable magic-byte fast rejection.

  Returns:
    The combined `ScanResults` produced by scanning `data`.

  Raises:
    MaxRecursionDepthExceededError: If archive nesting exceeds the limit.
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
    combined.has_scannable_payload = True
    combined.unsafe_results.add(error_tag)
    return True

  _scan_payload_tree(
      data,
      _handle_leaf,
      _handle_error,
      check_magic_bytes=check_magic_bytes,
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
  results.has_scannable_payload = True
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
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> ScanResults:
  """Runs the internal opcode-disassembly (`genops`) scan on a single payload.

  Args:
    pickle_bytes: Pickle byte buffer or binary stream to scan.
    fail_fast: Whether to stop scanning immediately upon finding an unsafe or
      suspicious operand.
    pickle_length: Optional byte length of the pickle payload.

  Returns:
    A `ScanResults` object containing categorized safe, unsafe, suspicious,
    and unknown symbols.
  """
  resolved_pickle_length = _resolve_pickle_length(pickle_bytes, pickle_length)
  if resolved_pickle_length >= constants.MIN_SIZE_FOR_CHUNKING:
    raw_buffer, start_offset = _extract_genops_buffer(pickle_bytes)
    data_buffer = raw_buffer[start_offset:] if start_offset else raw_buffer
    genops_output = generate_ops_from_file(
        "",
        pickle_length=resolved_pickle_length,
        fail_fast=fail_fast,
        data_buffer=data_buffer,
    )
  else:
    genops_output = generate_ops(pickle_bytes, fail_fast=fail_fast)

  results = categorize_strings(genops_output)
  results.has_scannable_payload = True
  return results


def genops_scan(
    pickle_bytes: bytes | IO[bytes],
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
    *,
    check_magic_bytes: bool = True,
) -> ScanResults:
  """Genops scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
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
      fail_fast=fail_fast,
      pickle_length=pickle_length,
  )


def apply_approach(
    scan_approach: Callable[..., ScanResults],
    pickle_bytes: bytes | IO[bytes],
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    pickle_length: Optional[int] = None,
) -> Dict[str, int]:
  """Applies the given scan approach to the data.

  Args:
    scan_approach: The scan approach to apply to the data.
    pickle_bytes: The data to scan.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data.

  Returns:
    A dictionary of the resulting scores.
  """
  if scan_approach in (genops_scan, _genops_scan_internal):
    results = scan_approach(
        pickle_bytes,
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

  return {
      "unsafe": len(results.unsafe_results),
      "suspicious": len(results.suspicious_results),
      "unknown": len(results.unknown_results),
  }


def security_scan_results(
    pickle_bytes: bytes | IO[bytes],
) -> Optional[ScanResults]:
  """Runs combined picklemagic and genops scans and returns merged results.

  Args:
    pickle_bytes: Raw bytes or binary stream to analyze.

  Returns:
    Merged `ScanResults` if `pickle_bytes` contains at least one scannable
    pickle payload, or None if the input is not a supported pickle file.
  """
  pickle_bytes = utils.ensure_seekable_stream(pickle_bytes)
  if utils.detect_archive_type(
      pickle_bytes
  ) is None and not utils.is_pickle_file(pickle_bytes):
    return None

  def _scan_both(leaf_data: bytes | IO[bytes]) -> ScanResults:
    pos = _get_stream_pos(leaf_data)
    res = _picklemagic_scan_internal(leaf_data)
    _safe_seek(leaf_data, pos)
    _merge_scan_results(res, _genops_scan_internal(leaf_data, fail_fast=False))
    return res

  results = _scan_bytes_generic(pickle_bytes, _scan_both)
  return results if results.has_scannable_payload else None


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
    pickle_length = _resolve_pickle_length(stream, None)

  try:
    is_pickle = utils.is_pickle_file(
        stream, check_magic_bytes=check_magic_bytes
    )
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    is_pickle = False

  if not is_pickle and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  if not is_pickle or utils.peek_bytes(stream, 6) == b"\x93NUMPY":
    current_pos = _get_stream_pos(stream)
    start_offset = utils.find_pickle_start_offset(stream)
    if start_offset > 0 and current_pos is not None:
      _safe_seek(stream, current_pos + start_offset)
      pickle_length = max(0, pickle_length - start_offset)

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
      if log_info:
        logging.info(error_string_illegal_combination)
      else:
        logging.error(error_string_illegal_combination)
    else:
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
        if log_info:
          logging.info(error_string_strict_check)
        else:
          logging.error(error_string_strict_check)
      else:
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

    if number_of_unsafe_results > 0:
      _report_or_raise(utils.Classification.UNSAFE, report_only, log_info)
    elif number_of_suspicious_results > 0:
      _report_or_raise(utils.Classification.SUSPICIOUS, report_only, log_info)
    elif number_of_unknown_results > 0:
      _report_or_raise(utils.Classification.UNKNOWN, report_only, log_info)
    elif report_only:
      logging.info("Loading safe pickle file")

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
      The object returned by `loader_mod.loads` if the pickle passes the
      security scan, `allow_unsafe` is True (with `strict_check` False), or
      `report_only` is True (after logging any violation; otherwise raises an
      exception without deserializing).

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
      The object returned by `loader_mod.load` if the pickle passes the
      security scan, `allow_unsafe` is True (with `strict_check` False), or
      `report_only` is True (after logging any violation; otherwise raises an
      exception without deserializing).

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
    The unpickled object.

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
  if "google.colab" in sys.modules:
    hook_pickle()

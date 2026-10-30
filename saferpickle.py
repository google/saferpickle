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
import os
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
  """Restores a stream's byte offset if seekable, ignoring unsupported seeks.

  Attempts to call `stream.seek(position)` when `position` is not None and
  suppresses `OSError`, `AttributeError`, `io.UnsupportedOperation`, and
  `ValueError` on non-seekable streams.

  Args:
    stream: Binary stream or buffer object on which to restore position.
    position: Target byte offset to seek to, or None to do nothing.

  Returns:
    None.
  """
  if position is None or not hasattr(stream, "seek"):
    return
  try:
    stream.seek(position)
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    logging.debug("Failed to seek stream back to position %s.", position)


@dataclasses.dataclass
class ScanResults:
  """Results from a pickle security scan."""

  safe_results: Set[str] = dataclasses.field(default_factory=set)
  unsafe_results: Set[str] = dataclasses.field(default_factory=set)
  suspicious_results: Set[str] = dataclasses.field(default_factory=set)
  unknown_results: Set[str] = dataclasses.field(default_factory=set)
  is_denylisted: bool = False


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


def _should_collect_operand(
    opcode: Optional[pickletools.OpcodeInfo], operand_str: str
) -> bool:
  """Determines whether a disassembled opcode operand should be collected.

  Always collects operands from global/import opcodes
  (`constants.IMPORT_OPCODES`) and collects string literal operands only when
  `is_potentially_dangerous_literal` returns True.

  Args:
    opcode: The `pickletools.OpcodeInfo` descriptor for the instruction, or
      None.
    operand_str: String representation of the opcode's operand.

  Returns:
    True if `operand_str` should be recorded for classification, or False
    otherwise.
  """
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
  """Worker function to scan a byte slice of pickle bytecode.

  Scans an opcode-aligned byte slice concurrently in a worker thread and
  extracts all string-declaring operands.

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
    if operand is None:
      continue
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

  Reads pickle bytecode and partitions large payloads for parallel scanning
  using threads.

  Args:
    pickle_file_path: The filesystem path to the pickle file.
    pickle_length: Optional length of the pickle data in bytes.
    fail_fast: Whether to fail fast on first unsafe match.
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
  """Returns string-declaring opcodes from a pickle byte buffer or stream.

  Iterates over opcodes yielded by `_custom_genops` while preserving seekable
  stream positions.

  Args:
    pickle_bytes: The pickle bytecode or stream to disassemble.
    fail_fast: Whether to fail fast on first unsafe match.

  Returns:
    The operands associated with opcodes that declare strings.
  """
  filtered_operands = set()
  original_pos = (
      None
      if isinstance(pickle_bytes, (bytes, bytearray, memoryview, mmap.mmap))
      else _get_stream_pos(pickle_bytes)
  )

  try:
    try:
      for opcode, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
        if operand is None:
          continue
        operand_str = str(operand)
        if not _should_collect_operand(opcode, operand_str):
          continue
        filtered_operands.add(operand_str)
        if fail_fast and utils.is_unsafe_for_fail_fast(operand_str):
          break
    except StopIteration:
      pass
    return filtered_operands
  finally:
    _safe_seek(pickle_bytes, original_pos)


class _SaferFakeWarning(picklemagic.FakeWarning):
  """FakeWarning subclass supporting dict/list population opcodes in sandbox."""

  __module__ = "corrupy.picklemagic"

  def __new__(cls, *args: Any, **kwargs: Any) -> Any:
    """Creates a sandboxed `FakeWarning` instance and records keyword arguments.

    Delegates instance allocation to `picklemagic.FakeWarning.__new__` and
    stores any keyword arguments passed via `NEWOBJ_EX` in
    `instance._new_kwargs` for downstream state inspection.

    Args:
      *args: Positional arguments passed during sandboxed instantiation.
      **kwargs: Keyword arguments passed during sandboxed instantiation.

    Returns:
      The newly created `_SaferFakeWarning` instance.
    """
    instance = super().__new__(cls, *args, **kwargs)
    if kwargs:
      instance._new_kwargs = kwargs
    return instance

  def __setitem__(self, key: Any, value: Any) -> None:
    """Records item assignment on the fake instance during `SETITEM`/`SETITEMS`.

    Stores `value` in `self.__dict__` keyed by `str(key)` so subsequent `BUILD`
    or state inspections can examine dictionary entries populated on fake
    objects.

    Args:
      key: Dictionary key assigned by the pickle stream.
      value: Value associated with `key`.

    Returns:
      None.
    """
    self.__dict__[str(key)] = value

  def append(self, value: Any) -> None:
    """Records an appended element on the fake instance during `APPEND`.

    Appends `value` to the internal `_list_items` list in `self.__dict__` for
    downstream state inspection.

    Args:
      value: Element appended by the `APPEND` opcode.

    Returns:
      None.
    """
    self.__dict__.setdefault("_list_items", []).append(value)

  def extend(self, values: Any) -> None:
    """Records extended elements on the fake instance during `APPENDS`.

    Extends the internal `_list_items` list in `self.__dict__` with `values`
    for downstream state inspection.

    Args:
      values: Iterable of elements pushed by the `APPENDS` opcode.

    Returns:
      None.
    """
    self.__dict__.setdefault("_list_items", []).extend(values)

  def add(self, value: Any) -> None:
    """Records a set element on the fake instance during set population.

    Appends `value` to the internal `_list_items` list in `self.__dict__` for
    downstream state inspection.

    Args:
      value: Element added to the fake instance.

    Returns:
      None.
    """
    self.__dict__.setdefault("_list_items", []).append(value)

  def update(self, values: Any) -> None:
    """Records updated dictionary or iterable entries on the fake instance.

    Copies key-value pairs into `self.__dict__` when `values` is a `dict`, or
    extends `_list_items` when `values` is an iterable (such as `ADDITEMS`).

    Args:
      values: A `dict` or iterable of elements used to update the fake instance.

    Returns:
      None.
    """
    if isinstance(values, dict):
      for key, val in values.items():
        self.__dict__[str(key)] = val
    else:
      self.__dict__.setdefault("_list_items", []).extend(values)


class SaferUnpickler(picklemagic.SafeUnpickler):
  """Subclass of SafeUnpickler to optimize state checking during BUILD."""

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
    kwargs.setdefault("encoding", "latin1")
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
      if line.endswith(b"\r\n"):
        return line[:-2] + b"\n"
      return line

    self._file_readline = _normalized_readline

    self.dispatch = self.dispatch.copy()
    self.dispatch[pickle.BINBYTES[0]] = self._load_binbytes_fast
    if hasattr(pickle, "BINSTRING"):
      self.dispatch[pickle.BINSTRING[0]] = self._load_binstring_fast
    if hasattr(pickle, "BINBYTES8"):
      self.dispatch[pickle.BINBYTES8[0]] = self._load_binbytes8_fast
    if hasattr(pickle, "BYTEARRAY8"):
      self.dispatch[pickle.BYTEARRAY8[0]] = self._load_bytearray8_fast

  def find_class(self, module: Any, name: Any) -> Any:
    """Resolves a pickle global reference into a sandbox `FakeClass` object.

    Normalizes `module` and `name`, checks the configured deny-list and
    allow-list, classifies `"module.name"` via `utils.classify_symbol`, logs
    the corresponding `picklemagic` warning message, and returns a sandboxed
    fake class (marking verified-safe non-`partial` symbols with
    `_is_safe_symbol`).

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

    if not utils.is_self_protected_symbol(
        full_name
    ) and utils.matches_symbol_prefix_list(full_name, allow_list):
      pm_logger.warning("Safe module/class imported: %s", full_name)
      cls = self.class_factory(name, module)
      setattr(cls, "_is_safe_symbol", True)
      return cls

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
    if full_name != "functools.partial":
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

    Checks `pid` for nested fake classes or dangerous string literals,
    validates PyTorch `('storage', ...)` tuples element-by-element, logs
    appropriate `picklemagic` warnings, and returns a sandboxed placeholder
    instance.

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
        if isinstance(element, (str, bytes)):
          element_str = (
              element.decode("utf-8", errors="ignore")
              if isinstance(element, bytes)
              else element
          )
          clean_element = element_str.replace("\r", "\\r").replace("\n", "\\n")
          if utils.is_potentially_dangerous_literal(element_str):
            pm_logger.warning("Unsafe module/class invoked: %s", clean_element)
          elif not utils.is_benign_storage_arg(element_str):
            pm_logger.warning(
                "Unknown module/class imported: persistent_id.%s", clean_element
            )
      return self.class_factory("Storage", "torch")()

    pid_str = (
        pid.decode("utf-8", errors="ignore")
        if isinstance(pid, bytes)
        else str(pid)
    )
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

    Extracts attribute dictionaries and `(key, value)` pairs from `state`
    (including nested `FakeClass` instances) and checks whether any key matches
    `constants.DANGEROUS_BUILD_STATE_KEYS` or a non-metadata
    dunder/introspection attribute.

    Args:
      state: The state argument popped or inspected during the `BUILD` opcode.

    Returns:
      True if `state` attempts to set a dangerous or non-metadata dunder
      attribute, or False otherwise.
    """
    dicts_to_check = []

    def _add_candidate_dict(candidate: Any) -> None:
      """Extracts attribute dictionaries from `candidate` into `dicts_to_check`.

      Appends `candidate` directly if it is a `dict`, or extracts user-populated
      attributes, keyword arguments, positional arguments, and list items when
      `candidate` is a `FakeClass` instance.

      Args:
        candidate: A state dictionary, tuple element, or `FakeClass` instance.

      Returns:
        None.
      """
      if isinstance(candidate, dict):
        dicts_to_check.append(candidate)
        return
      if not isinstance(candidate, picklemagic.FakeClass):
        return
      if not isinstance(getattr(candidate, "__dict__", None), dict):
        return
      filtered_attributes = {
          attribute_key: attribute_value
          for attribute_key, attribute_value in candidate.__dict__.items()
          if attribute_key not in constants.FAKE_CLASS_INTERNAL_ATTRIBUTES
      }
      dicts_to_check.append(filtered_attributes)
      for keyword_attr_name in ("_new_kwargs", "_kwargs"):
        keyword_dict = candidate.__dict__.get(keyword_attr_name)
        if isinstance(keyword_dict, dict):
          dicts_to_check.append(keyword_dict)

      def _extract_key_value_pairs(sequence_candidate: Any) -> None:
        """Recursively extracts `(key, value)` pairs from nested sequences.

        Converts 2-element `(str | bytes, value)` sequences into single-entry
        dictionaries in `dicts_to_check` and recurses into nested containers or
        `FakeClass` instances.

        Args:
          sequence_candidate: Container or element from positional/list args.

        Returns:
          None.
        """
        if isinstance(sequence_candidate, (dict, picklemagic.FakeClass)):
          _add_candidate_dict(sequence_candidate)
          return
        if not isinstance(sequence_candidate, (list, tuple, set, frozenset)):
          return
        if (
            isinstance(sequence_candidate, (list, tuple))
            and len(sequence_candidate) == 2
            and isinstance(sequence_candidate[0], (str, bytes))
        ):
          dicts_to_check.append({sequence_candidate[0]: sequence_candidate[1]})
          return
        for element in sequence_candidate:
          _extract_key_value_pairs(element)

      for positional_attr_name in ("_new_args", "_args"):
        positional_args = candidate.__dict__.get(positional_attr_name)
        if isinstance(positional_args, (list, tuple)):
          for positional_arg in positional_args:
            _extract_key_value_pairs(positional_arg)
      list_items = candidate.__dict__.get("_list_items")
      if isinstance(list_items, (list, tuple)):
        _extract_key_value_pairs(list_items)

    if isinstance(state, tuple) and len(state) == 2:
      _add_candidate_dict(state[0])
      _add_candidate_dict(state[1])
    else:
      _add_candidate_dict(state)

    for state_dict in dicts_to_check:
      for key, val in state_dict.items():
        key_str = (
            key.decode("utf-8", errors="ignore")
            if isinstance(key, bytes)
            else (key if isinstance(key, str) else None)
        )
        if key_str == "__dict__":
          if not isinstance(val, (dict, picklemagic.FakeClass)):
            return True
          _add_candidate_dict(val)
          continue
        if key_str in constants.DANGEROUS_BUILD_STATE_KEYS or (
            isinstance(key_str, str)
            and utils.is_dunder_or_introspection_attr(key_str)
            and key_str not in constants.SAFE_METADATA_ATTRIBUTES
        ):
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

    if type(inst).__dict__.get(
        "_is_safe_symbol", False
    ) and not self._state_contains_fake_class(state):
      self.stack.pop()
      return

    if not isinstance(inst, picklemagic.FakeClass) and (
        self._state_contains_fake_class(state)
    ):
      self.has_blocked_unsafe_build_instr = True
      self.stack.pop()
      return

    if isinstance(state, picklemagic.FakeClass) and isinstance(
        inst, picklemagic.FakeClass
    ):
      self.stack.pop()
      for attr_key, attr_val in state.__dict__.items():
        if attr_key not in ("_args", "_kwargs"):
          inst.__dict__[attr_key] = attr_val
      return

    super().load_build(*unused_args)

  @staticmethod
  def _is_cacheable_safe_arg(arg: Any) -> bool:
    """Checks whether a `REDUCE` argument is side-effect-free and cacheable.

    Permits primitive scalars/bytes, verified-safe `FakeClass` instances whose
    attributes contain no suspicious fake classes, and small tuples of
    primitive scalars.

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

  @staticmethod
  def _is_sandbox_callable(target: Any) -> bool:
    """Checks whether `target` is a sandboxed `FakeClass` callable or type.

    Prevents `REDUCE`, `INST`, `OBJ`, `NEWOBJ`, and `NEWOBJ_EX` from invoking
    methods or constructors on real Python builtins or live non-sandbox objects
    (such as `b"".__sizeof__` or `dict.get`).

    Args:
      target: Callable or class object popped from the unpickler stack.

    Returns:
      True if `target` is a `FakeClass` instance, `FakeClassType`, or
      `FakeClass` subclass, or False otherwise.
    """
    return isinstance(
        target, (picklemagic.FakeClass, picklemagic.FakeClassType)
    ) or (
        isinstance(target, type) and issubclass(target, picklemagic.FakeClass)
    )

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

    if not self._is_sandbox_callable(func):
      self.has_blocked_unsafe_build_instr = True
      stack[-1] = self.class_factory("failed_reduce", "picklemagic")()
      return

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

  def _instantiate(self, klass: Any, args: Any) -> None:
    """Instantiates `klass` for `INST`/`OBJ` opcodes after sandbox validation.

    Blocks instantiation if `klass` is not a sandboxed `FakeClass` or if `args`
    contains suspicious `FakeClass` objects, pushing a `failed_instantiate`
    placeholder instead.

    Args:
      klass: Class or callable object resolved for `INST` or `OBJ`.
      args: Tuple of positional arguments for instantiation.

    Returns:
      None.
    """
    if not self._is_sandbox_callable(klass) or self._state_contains_fake_class(
        args, only_suspicious=True
    ):
      self.has_blocked_unsafe_build_instr = True
      self.stack.append(
          self.class_factory("failed_instantiate", "picklemagic")()
      )
      return
    super()._instantiate(klass, args)

  def _instantiate_newobj(
      self, cls: Any, args: Any, kwargs: Any = None
  ) -> None:
    """Handles `NEWOBJ` and `NEWOBJ_EX` opcodes after sandbox validation.

    Blocks object creation if `cls` is not a sandboxed `FakeClass` or if `args`
    or `kwargs` contains suspicious `FakeClass` objects, pushing a
    `failed_newobj` placeholder instead.

    Args:
      cls: Target class popped from the unpickler stack.
      args: Positional argument tuple passed to `__new__`.
      kwargs: Optional keyword argument dict passed by `NEWOBJ_EX`.

    Returns:
      None.
    """
    if (
        not self._is_sandbox_callable(cls)
        or self._state_contains_fake_class(args, only_suspicious=True)
        or (
            kwargs is not None
            and self._state_contains_fake_class(kwargs, only_suspicious=True)
        )
    ):
      self.has_blocked_unsafe_build_instr = True
      self.stack.append(self.class_factory("failed_newobj", "picklemagic")())
      return
    super()._instantiate_newobj(cls, args, kwargs)

  def _skip_bytes_in_stream(self, length: int) -> None:
    """Advances the active pickle stream by `length` bytes.

    Seeks past payloads larger than 4096 bytes when the underlying stream (or
    current protocol 4+ frame) supports `seek` and `tell`, or reads `length`
    bytes directly while verifying the stream is not truncated.

    Args:
      length: Number of payload bytes to advance past in the stream.

    Returns:
      None.

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
    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")

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

    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")

    self.append(bytearray(data) if as_bytearray else data)

  def _load_binstring_fast(self, *unused_args: Any) -> None:
    """Loads a 4-byte signed-length `BINSTRING` payload, skipping large tails.

    Reads the full string when `length <= 4096`, or reads only the first 4096
    bytes and skips the remaining `length - 4096` bytes in the stream to avoid
    allocating multi-megabyte strings during sandboxed scanning.

    Args:
      *unused_args: Unused dispatch arguments passed by the unpickler loop.

    Returns:
      None.

    Raises:
      pickle.UnpicklingError: If the unpacked 4-byte signed length is negative.
      EOFError: If the stream ends before `length` bytes are available.
    """
    (length,) = struct.unpack("<i", self.read(4))
    if length < 0:
      raise pickle.UnpicklingError("BINSTRING count < 0")
    if length > 4096:
      prefix = self.read(4096)
      if len(prefix) != 4096:
        raise EOFError("Truncated binary payload in pickle stream")
      self._skip_bytes_in_stream(length - 4096)
      self.append(self._decode_string(prefix))
      return
    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")
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
    """Recursively inspects an object to detect FakeClass instances or types."""
    if inspection_depth > 64:
      return True
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

    object_type = type(object_to_inspect)
    if object_type.__module__ in (
        "numpy",
        "torch",
    ) and object_type.__name__ in (
        "ndarray",
        "Tensor",
    ):
      return False

    if visited_object_ids is None:
      visited_object_ids = set()

    current_object_id = id(object_to_inspect)
    if current_object_id in visited_object_ids:
      return False
    visited_object_ids.add(current_object_id)

    if object_type.__dict__.get("_is_safe_symbol", False):
      for attribute_name in constants.FAKE_CLASS_INTERNAL_ATTRIBUTES:
        attribute_value = getattr(object_to_inspect, attribute_name, None)
        if attribute_value and self._state_contains_fake_class(
            attribute_value,
            visited_object_ids,
            only_suspicious,
            inspection_depth + 1,
        ):
          return True
      inst_dict = getattr(object_to_inspect, "__dict__", None)
      if isinstance(inst_dict, dict):
        user_state = {
            attribute_key: attribute_value
            for attribute_key, attribute_value in inst_dict.items()
            if attribute_key not in constants.FAKE_CLASS_INTERNAL_ATTRIBUTES
        }
        if user_state and self._state_contains_fake_class(
            user_state,
            visited_object_ids,
            only_suspicious,
            inspection_depth + 1,
        ):
          return True
      return False

    if (
        object_type is picklemagic.FakeClassType
        and object_to_inspect.__dict__.get("_is_safe_symbol", False)
    ):
      for attribute_key, attribute_value in object_to_inspect.__dict__.items():
        if attribute_key.startswith("_"):
          continue
        if self._state_contains_fake_class(
            attribute_value,
            visited_object_ids,
            only_suspicious,
            inspection_depth + 1,
        ):
          return True
      return False

    if self._is_sandbox_callable(object_to_inspect):
      is_fake_instance = isinstance(object_to_inspect, picklemagic.FakeClass)
      if is_fake_instance:
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
        if not is_fake_instance:
          return False
      elif not full_symbol_name or module_name == "picklemagic":
        return True
      else:
        cls_verdict = utils.classify_symbol(full_symbol_name)
        if cls_verdict == utils.Classification.SAFE:
          return is_fake_instance
        elif only_suspicious:
          if cls_verdict in (
              utils.Classification.UNSAFE,
              utils.Classification.SUSPICIOUS,
          ):
            return True
        else:
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

    if hasattr(object_to_inspect, "__dict__") and isinstance(
        getattr(object_to_inspect, "__dict__", None), dict
    ):
      instance_attributes = getattr(object_to_inspect, "__dict__")
      if any(
          self._state_contains_fake_class(
              attribute_name,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          )
          or self._state_contains_fake_class(
              attribute_value,
              visited_object_ids,
              only_suspicious,
              inspection_depth + 1,
          )
          for attribute_name, attribute_value in instance_attributes.items()
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
    pickle_bytes: bytes | BinaryIO,
) -> tuple[io.StringIO, bool, bool]:
  """Gets the class instantiations from a pickle file or stream.

  Executes `SaferUnpickler` in sandbox mode while capturing
  `corrupy.picklemagic`
  log records and restoring the caller stream offset on exit.

  Args:
    pickle_bytes: The pickle bytecode or stream to disassemble.

  Returns:
    A 3-tuple of `(picklemagic_output, was_unsafe_build_blocked,
    has_scan_error)`.
  """
  picklemagic_output = io.StringIO()
  unpickler = None
  has_scan_error = False

  handler = std_logging.StreamHandler(picklemagic_output)
  handler.setFormatter(std_logging.Formatter("%(message)s"))
  logger = std_logging.getLogger("corrupy.picklemagic")
  logger.addHandler(handler)
  original_level = logger.level
  logger.setLevel(std_logging.WARNING)
  original_propagate = logger.propagate
  logger.propagate = False

  original_pos = _get_stream_pos(pickle_bytes)
  if isinstance(pickle_bytes, (bytes, bytearray, memoryview)):
    pickle_stream = io.BytesIO(bytes(pickle_bytes))
  else:
    pickle_stream = pickle_bytes

  try:
    try:
      bound_warning_cls = type(
          "_BoundSaferFakeWarning",
          (_SaferFakeWarning,),
          {"unpickler": None, "__module__": "corrupy.picklemagic"},
      )
      factory = picklemagic.FakeClassFactory([], bound_warning_cls)
      unpickler = SaferUnpickler(
          pickle_stream,
          class_factory=factory,
      )
      setattr(bound_warning_cls, "unpickler", unpickler)
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
        RecursionError,
    ) as e:
      logging.warning("Sandbox unpickling failed: %s", e)
      has_scan_error = True
  finally:
    logger.removeHandler(handler)
    logger.setLevel(original_level)
    logger.propagate = original_propagate
    _safe_seek(pickle_bytes, original_pos)

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
    return _reclassify_with_resolution(safe, unsafe, suspicious, unknown)

  return _reclassify_with_resolution(
      set(), set(), set(), set(filtered_output)  # pyrefly: ignore[bad-argument-type]
  )


def _reclassify_with_resolution(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> ScanResults:
  """Helper to resolve modules and re-classify results."""
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


def _strict_security_scan_stream(pickle_bytes: bytes | BinaryIO) -> bool:
  """Runs a strict genops and picklemagic security check on a single stream.

  Verifies that every imported symbol in `_custom_genops` classifies as
  `SAFE`, no string literal is potentially dangerous, and sandboxed
  unpickling via `get_class_instantiations` produces no unsafe, suspicious,
  unknown, or blocked build instructions.

  Args:
    pickle_bytes: Unwrapped pickle byte buffer or binary stream to scan.

  Returns:
    True if any non-safe symbol, dangerous literal, or sandbox error is
    detected, or False if the stream passes strict verification.
  """
  original_pos = _get_stream_pos(pickle_bytes)

  try:
    for opcode, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
      if operand is None:
        continue
      stmt = str(operand)
      if opcode is not None and opcode.name in constants.IMPORT_OPCODES:
        if utils.classify_symbol(stmt) != utils.Classification.SAFE:
          return True
      elif utils.is_potentially_dangerous_literal(stmt):
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
  max_depth = constants.MAX_ARCHIVE_RECURSION_DEPTH
  if recursion_depth > max_depth:
    raise MaxRecursionDepthExceededError(
        f"Max recursion depth of {max_depth} exceeded."
    )

  if isinstance(pickle_bytes, (bytearray, memoryview)):
    pickle_bytes = bytes(pickle_bytes)

  original_pos = _get_stream_pos(pickle_bytes)

  try:
    archive_type = _get_archive_type(pickle_bytes)
    if archive_type is not None:
      archive_bytes = (
          pickle_bytes
          if isinstance(pickle_bytes, bytes)
          else pickle_bytes.read()
      )
      budget = (
          _remaining_budget
          if _remaining_budget is not None
          else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
      )
      try:
        for entry_name, content_stream in _iter_archive_entries(
            archive_bytes, archive_type
        ):
          if entry_name is not None and utils.is_unsafe_archive_path(
              entry_name
          ):
            return True

          if entry_name is not None:
            if not _is_scannable_archive_entry(entry_name, content_stream):
              continue
            entry_bytes = utils.read_bounded(
                content_stream, remaining_budget=budget
            )
          else:
            entry_bytes = utils.read_bounded(
                content_stream, remaining_budget=budget
            )
            if not _is_scannable_archive_entry(None, entry_bytes):
              continue

          if strict_security_scan(
              entry_bytes, recursion_depth + 1, _remaining_budget=budget
          ):
            return True
      except MaxRecursionDepthExceededError:
        raise
      except Exception:  # pylint: disable=broad-exception-caught
        return True

      if archive_type == "tar" and utils.is_pickle_file(archive_bytes):
        return _strict_security_scan_stream(archive_bytes)
      return False

    is_numpy_header = utils.peek_bytes(pickle_bytes, 6) == b"\x93NUMPY"
    offset = utils.find_pickle_start_offset(pickle_bytes)
    if is_numpy_header and offset <= 0:
      return False
    if offset > 0:
      if isinstance(pickle_bytes, bytes):
        return _strict_security_scan_stream(pickle_bytes[offset:])
      pickle_bytes.seek((original_pos or 0) + offset)
    return _strict_security_scan_stream(pickle_bytes)
  finally:
    _safe_seek(pickle_bytes, original_pos)


_STREAM_ARCHIVE_EXTRACTORS = types.MappingProxyType({
    "bz2": utils.extract_bz2_contents,
    "lzma": utils.extract_lzma_contents,
    "gzip": utils.extract_gzip_contents,
})


def _get_archive_type(data: bytes | IO[bytes]) -> str | None:
  """Identifies the archive format of `data` from its magic header bytes.

  Reads up to 262 leading bytes (restoring stream position if seekable) and
  checks against supported archive magic signatures.

  Args:
    data: Raw byte buffer or binary stream to inspect.

  Returns:
    The archive format string (`'zip'`, `'bz2'`, `'lzma'`, `'gzip'`, or
    `'tar'`) if recognized, or None otherwise.
  """
  header = utils.peek_bytes(data, 262)

  if utils.is_zip_bytes(header):
    return "zip"
  if utils.is_bz2_bytes(header):
    return "bz2"
  if utils.is_lzma_bytes(header):
    return "lzma"
  if utils.is_gzip_bytes(header):
    return "gzip"
  if utils.is_tar_bytes(header):
    return "tar"
  return None


def _is_archive(data: bytes | IO[bytes]) -> bool:
  """Checks whether `data` represents a supported archive format.

  Delegates to `_get_archive_type` to determine if `data` matches a zip, bz2,
  lzma, gzip, or tar header.

  Args:
    data: Raw byte buffer or binary stream to inspect.

  Returns:
    True if `data` is a supported archive format, or False otherwise.
  """
  return _get_archive_type(data) is not None


def _iter_archive_entries(
    data: bytes,
    archive_type: str,
) -> Iterator[tuple[str | None, IO[bytes]]]:
  """Yields entry names and content streams from a supported archive buffer.

  Dispatches to the appropriate archive extractor in `utils` based on
  `archive_type`. Single-stream compressors (`bz2`, `lzma`, `gzip`) yield
  `None` as the entry name.

  Args:
    data: Raw archive bytes to extract.
    archive_type: Archive format identifier (`'zip'`, `'bz2'`, `'lzma'`,
      `'gzip'`, or `'tar'`).

  Yields:
    Tuples of `(entry_name, content_stream)` for each file or compressed
    stream in the archive.

  Raises:
    ValueError: If `archive_type` is not a supported archive format.
  """
  if archive_type == "zip":
    yield from utils.extract_zip_contents(data)
  elif archive_type in _STREAM_ARCHIVE_EXTRACTORS:
    yield None, _STREAM_ARCHIVE_EXTRACTORS[archive_type](data)
  elif archive_type == "tar":
    yield from utils.extract_tar_contents(data)
  else:
    raise ValueError(f"Unsupported archive type: {archive_type}")


def _is_scannable_archive_entry(
    name: str | None,
    content_stream: bytes | IO[bytes],
    force_scan: bool = False,
    check_magic_bytes: bool = True,
) -> bool:
  """Determines whether an extracted archive entry should be security-scanned.

  Checks whether `content_stream` is a nested archive or passes
  `is_pickle_file` detection (unless `force_scan` is True, in which case all
  entries are scanned).

  Args:
    name: Archive member filename, or None for single-stream compressors.
    content_stream: Extracted byte buffer or stream for the archive entry.
    force_scan: Whether to scan the entry even if it does not look like a pickle
      file.
    check_magic_bytes: Whether to enable magic-byte fast rejection when checking
      named archive entries.

  Returns:
    True if the archive entry should be scanned, or False otherwise.
  """
  if force_scan or _is_archive(content_stream):
    return True
  return bool(
      utils.is_pickle_file(
          content_stream,
          check_magic_bytes=check_magic_bytes if name is not None else True,
      )
  )


def _merge_scan_results(target: ScanResults, source: ScanResults) -> None:
  """Merges findings from `source` into `target` in place.

  Updates the safe, unsafe, suspicious, and unknown result sets on `target`
  and propagates the `is_denylisted` flag.

  Args:
    target: Accumulator `ScanResults` instance to update in place.
    source: `ScanResults` instance whose findings should be merged into
      `target`.

  Returns:
    None.
  """
  target.safe_results.update(source.safe_results)
  target.unsafe_results.update(source.unsafe_results)
  target.suspicious_results.update(source.suspicious_results)
  target.unknown_results.update(source.unknown_results)
  target.is_denylisted = target.is_denylisted or source.is_denylisted


def _scan_archive_generic(
    data: bytes,
    archive_type: str,
    scan_func: Callable[[bytes | IO[bytes]], ScanResults],
    recursion_depth: int = 0,
    *,
    remaining_budget: Optional[list[int]] = None,
) -> ScanResults:
  """Extracts and recursively scans all scannable entries within an archive.

  Iterates over entries in `data`, flags path-traversal entries (`zip_slip` /
  `tar_slip`), recursively scans nested archives and pickle payloads via
  `_scan_bytes_generic`, and scans tar/pickle polyglots directly.

  Args:
    data: Raw archive byte buffer.
    archive_type: Archive format identifier (`'zip'`, `'bz2'`, `'lzma'`,
      `'gzip'`, or `'tar'`).
    scan_func: Underlying single-payload scan function
      (`_picklemagic_scan_internal` or `_genops_scan_internal`).
    recursion_depth: Current archive nesting depth.
    remaining_budget: Optional shared decompression byte budget tracker.

  Returns:
    A combined `ScanResults` instance aggregating findings across all
    entries.
  """
  combined = ScanResults()
  budget = (
      remaining_budget
      if remaining_budget is not None
      else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
  )

  try:
    for name, content_stream in _iter_archive_entries(data, archive_type):
      if name is not None and utils.is_unsafe_archive_path(name):
        combined.unsafe_results.add(f"{archive_type}_slip_detected")
        return combined
      if name is not None:
        if not _is_scannable_archive_entry(name, content_stream):
          continue
        content = utils.read_bounded(content_stream, remaining_budget=budget)
      else:
        content = utils.read_bounded(content_stream, remaining_budget=budget)
        if not _is_scannable_archive_entry(None, content):
          continue

      res = _scan_bytes_generic(
          content,
          scan_func,
          recursion_depth + 1,
          remaining_budget=budget,
      )
      _merge_scan_results(combined, res)
    if archive_type == "tar" and utils.is_pickle_file(data):
      polyglot_res = scan_func(data)
      _merge_scan_results(combined, polyglot_res)
  except MaxRecursionDepthExceededError:
    raise
  except Exception as e:  # pylint: disable=broad-except
    logging.warning("Error processing %s archive in scan: %s", archive_type, e)
    combined.unsafe_results.add("archive_extraction_error")

  return combined


def _scan_bytes_generic(
    data: bytes | IO[bytes],
    scan_func: Callable[[bytes | IO[bytes]], ScanResults],
    recursion_depth: int = 0,
    *,
    remaining_budget: Optional[list[int]] = None,
) -> ScanResults:
  """Scans `data` recursively if it is an archive, or applies `scan_func`.

  Enforces `constants.MAX_ARCHIVE_RECURSION_DEPTH`, unwraps `.npy` object
  headers to their embedded pickle offset, and delegates either to
  `_scan_archive_generic` or directly to `scan_func`.

  Args:
    data: Raw bytes or binary stream to scan.
    scan_func: Single-payload scan callable returning `ScanResults`.
    recursion_depth: Current archive recursion depth.
    remaining_budget: Optional shared decompression byte budget tracker.

  Returns:
    The `ScanResults` produced by scanning `data`.

  Raises:
    MaxRecursionDepthExceededError: If `recursion_depth` exceeds the limit.
  """
  max_depth = constants.MAX_ARCHIVE_RECURSION_DEPTH
  if recursion_depth > max_depth:
    raise MaxRecursionDepthExceededError(
        f"Max recursion depth of {max_depth} exceeded."
    )

  archive_type = _get_archive_type(data)
  if archive_type is not None:
    archive_bytes = data if isinstance(data, bytes) else data.read()
    budget = (
        remaining_budget
        if remaining_budget is not None
        else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
    )
    return _scan_archive_generic(
        archive_bytes,
        archive_type,
        scan_func,
        recursion_depth,
        remaining_budget=budget,
    )

  if isinstance(data, bytes) and data.startswith(b"\x93NUMPY"):
    offset = utils.find_pickle_start_offset(data)
    if offset > 0:
      data = data[offset:]
    else:
      return ScanResults()

  return scan_func(data)


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
) -> ScanResults:
  """Picklemagic scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.

  Returns:
    A ScanResults object.
  """
  return _scan_bytes_generic(
      pickle_bytes,
      _picklemagic_scan_internal,
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
) -> ScanResults:
  """Genops scan for malicious content in pickle files.

  Args:
    pickle_bytes: Pickle bytecode to scan.
    pickle_file_path: Optional path to the pickle file for streaming scan.
    fail_fast: Whether to fail fast on first unsafe or suspicious match.
    pickle_length: Optional length of the pickle data in bytes.

  Returns:
    A ScanResults object.
  """
  if (
      _is_archive(pickle_bytes)
      or utils.peek_bytes(pickle_bytes, 6) == b"\x93NUMPY"
  ):
    archive_bytes = (
        pickle_bytes if isinstance(pickle_bytes, bytes) else pickle_bytes.read()
    )
    return _scan_bytes_generic(
        archive_bytes,
        lambda data_slice: _genops_scan_internal(
            data_slice, fail_fast=fail_fast
        ),
    )
  return _genops_scan_internal(
      pickle_bytes,
      pickle_file_path=pickle_file_path,
      fail_fast=fail_fast,
      pickle_length=pickle_length,
  )


def is_unknown_verdict(
    unused_safe_results: Set[str],
    unused_unsafe_results: Set[str],
    unused_suspicious_results: Set[str],
    unknown_results: Set[str],
) -> bool:
  """Determines whether the scan results contain any unknown symbols.

  Evaluates the set of unclassified symbols discovered during scanning to
  decide whether the unknown-symbol count should be reported.

  Args:
    unused_safe_results: Set of symbols classified as `SAFE`.
    unused_unsafe_results: Set of symbols classified as `UNSAFE`.
    unused_suspicious_results: Set of symbols classified as `SUSPICIOUS`.
    unknown_results: Set of symbols classified as `UNKNOWN`.

  Returns:
    True if `unknown_results` is non-empty, or False otherwise.
  """
  return bool(unknown_results)


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
  if scan_approach is genops_scan:
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

  is_unknown = is_unknown_verdict(
      results.safe_results,
      results.unsafe_results,
      results.suspicious_results,
      results.unknown_results,
  )
  effective_unknown = len(results.unknown_results) if is_unknown else 0
  return {
      "unsafe": len(results.unsafe_results),
      "suspicious": len(results.suspicious_results),
      "unknown": effective_unknown,
  }


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
  max_depth = constants.MAX_ARCHIVE_RECURSION_DEPTH
  if recursion_depth > max_depth:
    raise MaxRecursionDepthExceededError(
        f"Max recursion depth of {max_depth} exceeded."
    )
  if recursion_depth > 3:
    logging.warning("Suspiciously deep recursion depth of %d", recursion_depth)

  original_pos = _get_stream_pos(pickle_bytes)

  try:
    archive_type = _get_archive_type(pickle_bytes)
    if archive_type is not None:
      archive_bytes = (
          pickle_bytes
          if isinstance(pickle_bytes, bytes)
          else pickle_bytes.read()
      )
      budget = (
          _remaining_budget
          if _remaining_budget is not None
          else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
      )
      return _extract_and_scan_archive(
          archive_bytes,
          archive_type,
          recursion_depth,
          force_scan,
          fail_fast=fail_fast,
          check_magic_bytes=check_magic_bytes,
          remaining_budget=budget,
      )

    return _security_scan_internal(
        pickle_bytes,
        force_scan,
        fail_fast=fail_fast,
        check_magic_bytes=check_magic_bytes,
    )
  finally:
    _safe_seek(pickle_bytes, original_pos)


def _extract_and_scan_archive(
    data: bytes,
    archive_type: str,
    recursion_depth: int,
    force_scan: bool = False,
    fail_fast: Optional[bool] = DEFAULT_FAIL_FAST,
    check_magic_bytes: bool = True,
    *,
    remaining_budget: Optional[list[int]] = None,
) -> Dict[str, int]:
  """Extracts and scans contents of an archive.

  Args:
    data: Raw archive bytes to extract and scan.
    archive_type: Archive format identifier (`'zip'`, `'bz2'`, `'lzma'`,
      `'gzip'`, or `'tar'`).
    recursion_depth: Current archive recursion depth.
    force_scan: Whether to scan entries that do not match pickle headers.
    fail_fast: Whether to fail fast on the first unsafe match.
    check_magic_bytes: Whether to perform magic-byte fast rejection.
    remaining_budget: Optional shared cumulative decompression byte budget.

  Returns:
    A dictionary mapping `'unsafe'`, `'suspicious'`, and `'unknown'` to their
    aggregated counts across all archive entries.

  Raises:
    MaxRecursionDepthExceededError: If archive nesting exceeds the maximum
      allowed depth.
  """
  budget = (
      remaining_budget
      if remaining_budget is not None
      else [constants.MAX_ARCHIVE_DECOMPRESSED_BYTES]
  )
  all_scores = {"unsafe": 0, "suspicious": 0, "unknown": 0}

  try:
    for name, content_stream in _iter_archive_entries(data, archive_type):
      if name is not None and utils.is_unsafe_archive_path(name):
        logging.warning("%s slip detected: %s", archive_type.capitalize(), name)
        return {
            "unsafe": constants.HIGH_SEVERITY_ZIPSLIP,
            "suspicious": 0,
            "unknown": 0,
        }

      if name is not None and not _is_scannable_archive_entry(
          name, content_stream, force_scan, check_magic_bytes
      ):
        continue

      payload = utils.read_bounded(content_stream, remaining_budget=budget)
      scores = security_scan(
          payload,
          force_scan=force_scan,
          recursion_depth=recursion_depth + 1,
          fail_fast=fail_fast,
          check_magic_bytes=check_magic_bytes if name is not None else True,
          _remaining_budget=budget,
      )
      for key in ("unsafe", "suspicious", "unknown"):
        all_scores[key] += scores.get(key, 0)
    if archive_type == "tar" and utils.is_pickle_file(data):
      polyglot_scores = _security_scan_internal(
          data,
          force_scan=force_scan,
          fail_fast=fail_fast,
          check_magic_bytes=check_magic_bytes,
      )
      for key in ("unsafe", "suspicious", "unknown"):
        all_scores[key] += polyglot_scores.get(key, 0)
  except MaxRecursionDepthExceededError:
    raise
  except Exception as e:  # pylint: disable=broad-except
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

  try:
    is_pickle = bool(
        utils.is_pickle_file(stream, check_magic_bytes=check_magic_bytes)
    )
  except (OSError, AttributeError, io.UnsupportedOperation, ValueError):
    is_pickle = False

  if not is_pickle and not force_scan:
    return {"unsafe": 0, "suspicious": 0, "unknown": 0}

  if not is_pickle or utils.peek_bytes(stream, 6) == b"\x93NUMPY":
    try:
      current_pos = stream.tell()
      header_bytes = stream.read(262)
      stream.seek(current_pos)
      start_offset = (
          utils.find_pickle_start_offset(stream)
          if not _is_archive(header_bytes)
          else 0
      )
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
    for scan_approach in [picklemagic_scan, genops_scan]:
      scores = apply_approach(
          scan_approach,
          stream,
          fail_fast=fail_fast,
          pickle_length=pickle_length,
      )
      _safe_seek(stream, original_stream_pos)
      if scores["unsafe"] > 0 or scores["suspicious"] > 0:
        return scores
      final_scores["unknown"] += scores["unknown"]

    return final_scores
  finally:
    _safe_seek(stream, original_stream_pos)


_ORIG_METHODS_BEFORE_HOOKING: dict[str, dict[str, Any]] = {}
_HOOKING_LOCK = threading.Lock()
_UNPICKLE_BYPASS_STATE = threading.local()
_OriginalPickleUnpickler = pickle.Unpickler


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


def _enforce_scan_policy(
    scan_source: Any,
    allow_unsafe: bool,
    strict_check: bool,
    report_only: bool,
    force_scan: bool,
    log_info: bool,
    check_magic_bytes: bool = True,
) -> bool:
  """Executes the configured SaferPickle scan policy on `scan_source`.

  Validates flag combinations (`strict_check` vs. `allow_unsafe`), runs
  either `strict_security_scan` or `security_scan` when `allow_unsafe` is
  False, and either logs or raises an exception according to `report_only`.

  Args:
    scan_source: Pickle byte buffer or seekable binary stream to scan.
    allow_unsafe: Whether to bypass security scanning and allow unsafe payloads.
    strict_check: Whether to enforce strict allow-only security scanning.
    report_only: Whether to log violations instead of raising exceptions.
    force_scan: Whether to scan inputs even if they fail magic-byte detection.
    log_info: Whether to log `report_only` findings at `INFO` instead of
      `ERROR`.
    check_magic_bytes: Whether to enable magic-byte fast rejection.

  Returns:
    True if the caller should proceed with unpickling.

  Raises:
    IllegalArgumentCombinationError: If both `strict_check` and
      `allow_unsafe` are True and `report_only` is False.
    StrictCheckError: If `strict_check` is True, the scan fails, and
      `report_only` is False.
    UnsafePickleDetectedError: If `security_scan` detects unsafe, suspicious,
      or unknown symbols and `report_only` is False.
  """
  if strict_check and allow_unsafe:
    error_string_illegal_combination = (
        "Strict scanning and allow_unsafe cannot be used together."
    )
    if report_only:
      if log_info:
        logging.info(error_string_illegal_combination)
      else:
        logging.error(error_string_illegal_combination)
      return True
    raise IllegalArgumentCombinationError(error_string_illegal_combination)

  if allow_unsafe:
    if report_only:
      logging.info("Loading pickle file with allow_unsafe set to True.")
    return True

  if strict_check:
    if strict_security_scan(scan_source):
      error_string_strict_check = "Pickle file failed strict security check."
      if report_only:
        if log_info:
          logging.info(error_string_strict_check)
        else:
          logging.error(error_string_strict_check)
        return True
      raise StrictCheckError(error_string_strict_check)
    return True

  scan_scores = security_scan(
      scan_source,
      force_scan=force_scan,
      check_magic_bytes=check_magic_bytes,
  )
  if scan_scores["unsafe"] > 0:
    _report_or_raise(utils.Classification.UNSAFE, report_only, log_info)
  elif scan_scores["suspicious"] > 0:
    _report_or_raise(utils.Classification.SUSPICIOUS, report_only, log_info)
  elif scan_scores["unknown"] > 0:
    _report_or_raise(utils.Classification.UNKNOWN, report_only, log_info)
  elif report_only:
    logging.info("Loading safe pickle file")
  return True


def _prepare_stream_for_scan_and_load(pickle_file: Any) -> Any:
  """Normalizes a binary stream into a seekable stream positioned at the pickle.

  Buffers non-seekable streams into an `io.BytesIO` instance and advances the
  stream offset to the start of the embedded pickle payload when a leading
  non-archive header (such as a `.npy` header) is present.

  Args:
    pickle_file: Input file-like stream passed to `load` or `Unpickler`.

  Returns:
    A seekable binary stream positioned at the start of the pickle payload.
  """
  try:
    is_seekable = pickle_file.seekable()
  except (AttributeError, ValueError):
    is_seekable = False

  if not is_seekable:
    data_bytes = pickle_file.read()
    pickle_file = io.BytesIO(data_bytes)

  try:
    current_pos = pickle_file.tell()
    header_bytes = pickle_file.read(262)
    pickle_file.seek(current_pos)
    start_offset = (
        utils.find_pickle_start_offset(pickle_file)
        if not _is_archive(header_bytes)
        else 0
    )
    if start_offset > 0:
      pickle_file.seek(current_pos + start_offset)
    else:
      pickle_file.seek(current_pos)
  except (OSError, AttributeError, io.UnsupportedOperation):
    pass

  return pickle_file


def _scan_and_load(
    pickle_file_or_bytes: Any,
    allow_unsafe: bool,
    strict_check: bool,
    report_only: bool,
    force_scan: bool,
    hooked_mod_name: str,
    is_load: bool,
    log_info: bool,
    check_magic_bytes: bool = True,
    *args: Any,
    hooked_func_name: str = "",
    **kwargs: Any,
):
  """Scans pickle data under the configured policy before deserializing it.

  Streams seekable file handles and filesystem paths without loading full
  multi-GB checkpoints into memory prior to unpickling.

  Args:
    pickle_file_or_bytes: File path, binary stream, or byte buffer to load.
    allow_unsafe: Whether to allow unsafe payloads without scanning.
    strict_check: Whether to enforce strict allow-only scanning.
    report_only: Whether to log violations instead of raising exceptions.
    force_scan: Whether to scan inputs that do not match pickle headers.
    hooked_mod_name: Name of the underlying module providing the loader.
    is_load: True when called from a stream/path `load` entrypoint.
    log_info: Whether `report_only` findings log at `INFO` rather than `ERROR`.
    check_magic_bytes: Whether to enable magic-byte fast rejection.
    *args: Additional positional arguments forwarded to `load_func`.
    hooked_func_name: Explicit attribute name on `loader_mod`, if non-default.
    **kwargs: Additional keyword arguments forwarded to `load_func`.

  Returns:
    The deserialized Python object returned by `load_func`.
  """
  loader_mod = utils.get_copied_module(hooked_mod_name or "_pickle")
  resolved_func_name = hooked_func_name or ("load" if is_load else "loads")
  load_func = getattr(loader_mod, resolved_func_name)

  if getattr(_UNPICKLE_BYPASS_STATE, "active", False):
    return load_func(pickle_file_or_bytes, *args, **kwargs)

  already_scanned = False
  scan_source: Any = None
  if is_load:
    if isinstance(pickle_file_or_bytes, (str, os.PathLike)):
      with open(pickle_file_or_bytes, "rb") as file_handle:
        prepared_stream = _prepare_stream_for_scan_and_load(file_handle)
        should_load = _enforce_scan_policy(
            prepared_stream,
            allow_unsafe=allow_unsafe,
            strict_check=strict_check,
            report_only=report_only,
            force_scan=force_scan,
            log_info=log_info,
            check_magic_bytes=check_magic_bytes,
        )
      if not should_load:
        return None
      load_args = (pickle_file_or_bytes,)
      already_scanned = True
    elif hasattr(pickle_file_or_bytes, "read"):
      pickle_file = _prepare_stream_for_scan_and_load(pickle_file_or_bytes)
      scan_source = pickle_file
      load_args = (pickle_file,)
    else:
      raise TypeError("pickle_file_or_bytes must be IOBase when is_load=True")
  else:
    if isinstance(pickle_file_or_bytes, (bytearray, memoryview)):
      data_bytes = bytes(pickle_file_or_bytes)
    elif isinstance(pickle_file_or_bytes, bytes):
      data_bytes = pickle_file_or_bytes
    else:
      raise TypeError("pickle_file_or_bytes must be bytes when is_load=False")

    if not _is_archive(data_bytes):
      start_offset = utils.find_pickle_start_offset(data_bytes)
    else:
      start_offset = 0

    if start_offset > 0:
      data_bytes = data_bytes[start_offset:]
    scan_source = data_bytes
    load_args = (data_bytes,)

  if not already_scanned:
    should_load = _enforce_scan_policy(
        scan_source,
        allow_unsafe=allow_unsafe,
        strict_check=strict_check,
        report_only=report_only,
        force_scan=force_scan,
        log_info=log_info,
        check_magic_bytes=check_magic_bytes,
    )
    if not should_load:
      return None

  previous_bypass = getattr(_UNPICKLE_BYPASS_STATE, "active", False)
  _UNPICKLE_BYPASS_STATE.active = True
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
  finally:
    _UNPICKLE_BYPASS_STATE.active = previous_bypass


def _make_hooked_unpickler_class(
    original_unpickler_cls: type[Any],
    *,
    force_report_only: bool = False,
    default_log_info: bool = False,
) -> type[Any]:
  """Creates a hooked `Unpickler` subclass wrapping `original_unpickler_cls`.

  Produces a subclass whose `__init__` prepares the input stream for scanning
  and whose `load()` method enforces `_enforce_scan_policy` before calling
  `original_unpickler_cls.load`.

  Args:
    original_unpickler_cls: The original `Unpickler` class from `pickle`,
      `_pickle`, `dill`, or `cloudpickle`.
    force_report_only: Whether to force `report_only=True` on all instances of
      the returned class.
    default_log_info: Default value for the `log_info` flag on instances of the
      returned class.

  Returns:
    A `_HookedUnpickler` subclass that scans streams prior to unpickling.
  """

  class _HookedUnpickler(original_unpickler_cls):
    """Hooked Unpickler subclass enforcing security scans before load()."""

    def __init__(
        self,
        file: Any,
        *args: Any,
        allow_unsafe: bool = False,
        strict_check: bool = False,
        report_only: bool = False,
        force_scan: bool = False,
        log_info: bool = default_log_info,
        check_magic_bytes: bool = True,
        **kwargs: Any,
    ):
      """Initializes `_HookedUnpickler` and prepares `file` for scanning.

      Wraps non-seekable streams via `_prepare_stream_for_scan_and_load` when
      not inside an internal bypass context and stores scan policy flags on
      the instance.

      Args:
        file: Binary stream containing pickle data.
        *args: Additional positional arguments for `original_unpickler_cls`.
        allow_unsafe: Whether to bypass security scanning.
        strict_check: Whether to enforce strict security scanning.
        report_only: Whether to log violations instead of raising exceptions.
        force_scan: Whether to force scanning on non-pickle-looking inputs.
        log_info: Whether to log `report_only` findings at `INFO` instead of
          `ERROR`.
        check_magic_bytes: Whether to enable magic-byte fast rejection.
        **kwargs: Additional keyword arguments for `original_unpickler_cls`.

      Returns:
        None.
      """
      if hasattr(file, "read") and not getattr(
          _UNPICKLE_BYPASS_STATE, "active", False
      ):
        prepared_file = _prepare_stream_for_scan_and_load(file)
      else:
        prepared_file = file
      original_unpickler_cls.__init__(self, prepared_file, *args, **kwargs)
      self.file = prepared_file
      self._sp_file = prepared_file
      self._sp_allow_unsafe = allow_unsafe
      self._sp_strict_check = strict_check
      self._sp_report_only = True if force_report_only else report_only
      self._sp_force_scan = force_scan
      self._sp_log_info = log_info
      self._sp_check_magic_bytes = check_magic_bytes

    def load(self) -> Any:
      """Enforces the SaferPickle scan policy on the stream before unpickling.

      Runs `_enforce_scan_policy` on `self._sp_file`, restores the stream
      position, and invokes `original_unpickler_cls.load(self)` under the
      thread-local `_UNPICKLE_BYPASS_STATE` guard.

      Returns:
        The deserialized Python object from `original_unpickler_cls.load`, or
        None if `report_only` blocked execution on an illegal flag combination
        or strict check failure.
      """
      if getattr(_UNPICKLE_BYPASS_STATE, "active", False):
        return original_unpickler_cls.load(self)

      current_pos = _get_stream_pos(self._sp_file)
      try:
        should_load = _enforce_scan_policy(
            self._sp_file,
            allow_unsafe=self._sp_allow_unsafe,
            strict_check=self._sp_strict_check,
            report_only=self._sp_report_only,
            force_scan=self._sp_force_scan,
            log_info=self._sp_log_info,
            check_magic_bytes=self._sp_check_magic_bytes,
        )
      finally:
        _safe_seek(self._sp_file, current_pos)

      if not should_load:
        return None

      previous_bypass = getattr(_UNPICKLE_BYPASS_STATE, "active", False)
      _UNPICKLE_BYPASS_STATE.active = True
      try:
        return original_unpickler_cls.load(self)  # pylint: disable=g-unsafe-pickle-load
      finally:
        _UNPICKLE_BYPASS_STATE.active = previous_bypass

  return _HookedUnpickler


def hook_pickle(
    force_report_only: bool = False,
    log_info: bool = False,
    config_path: Optional[str] = None,
) -> None:
  """This implements the hooking of pickle-like libraries."""
  config.set_config_path(config_path)

  def _make_hooked_loader(
      is_load: bool, default_func_name: str = ""
  ) -> Callable[..., Any]:
    """Creates a hooked `load` or `loads` wrapper function for `hook_pickle`.

    Builds a closure around `force_report_only` and `log_info` that intercepts
    calls to a hooked library's deserialization function and delegates to
    `_scan_and_load`.

    Args:
      is_load: True if wrapping a file-based `load` function, or False if
        wrapping a bytes-based `loads` function.
      default_func_name: Optional attribute name of the original loader function
        on the target module.

    Returns:
      A wrapper callable with SaferPickle scan keyword arguments that scans
      inputs before invoking the underlying loader.
    """

    def _hooked_loader(
        pickle_input: Any,
        *args: Any,
        allow_unsafe: bool = False,
        strict_check: bool = False,
        report_only: bool = False,
        force_scan: bool = False,
        hooked_mod_name: str = "",
        check_magic_bytes: bool = True,
        **kwargs: Any,
    ) -> Any:
      """Scans `pickle_input` before delegating to the hooked module's loader.

      Applies `force_report_only` if configured globally by `hook_pickle` and
      forwards all arguments to `_scan_and_load`.

      Args:
        pickle_input: File path, binary stream, or byte buffer to unpickle.
        *args: Additional positional arguments for the underlying loader.
        allow_unsafe: Whether to bypass security scanning.
        strict_check: Whether to enforce strict security scanning.
        report_only: Whether to log violations instead of raising exceptions.
        force_scan: Whether to force scanning on non-pickle-looking inputs.
        hooked_mod_name: Name of the hooked module whose original loader should
          be called.
        check_magic_bytes: Whether to enable magic-byte fast rejection.
        **kwargs: Additional keyword arguments for the underlying loader.

      Returns:
        The deserialized Python object returned by the underlying loader.
      """
      if force_report_only:
        report_only = True
      return _scan_and_load(
          pickle_input,
          allow_unsafe,
          strict_check,
          report_only,
          force_scan,
          hooked_mod_name,
          is_load,
          log_info,
          check_magic_bytes,
          *args,
          hooked_func_name=default_func_name,
          **kwargs,
      )

    return _hooked_loader

  custom_loads = _make_hooked_loader(is_load=False)
  custom_load = _make_hooked_loader(is_load=True)
  custom_load_module = _make_hooked_loader(
      is_load=True, default_func_name="load_module"
  )
  custom_load_session = _make_hooked_loader(
      is_load=True, default_func_name="load_session"
  )
  custom_load_module_asdict = _make_hooked_loader(
      is_load=True, default_func_name="load_module_asdict"
  )

  hookable_mods: tuple[str, ...] = (
      "_pickle",
      "pickle",
      "dill",
      "dill._dill",
      "dill.session",
      "joblib",
      "joblib.numpy_pickle",
      "cloudpickle",
      "torch",
      "torch.serialization",
  )

  for hookable_mod in hookable_mods:
    if sys.modules.get(hookable_mod):
      module = sys.modules[hookable_mod]
    else:
      logging.debug("%s DOES NOT exist in sys.modules", hookable_mod)
      logging.debug("Importing %s now", hookable_mod)
      try:
        module = importlib.import_module(hookable_mod)
      except (ImportError, ModuleNotFoundError):
        logging.debug("Failed to import %s", hookable_mod)
        continue

    _ = utils.get_copied_module(hookable_mod)

    with _HOOKING_LOCK:
      if hookable_mod not in _ORIG_METHODS_BEFORE_HOOKING:
        _ORIG_METHODS_BEFORE_HOOKING[hookable_mod] = {}

      methods_to_patch: dict[str, Any] = {
          "load": functools.partial(custom_load, hooked_mod_name=hookable_mod),
          "loads": functools.partial(
              custom_loads, hooked_mod_name=hookable_mod
          ),
          "load_module": functools.partial(
              custom_load_module, hooked_mod_name=hookable_mod
          ),
          "load_session": functools.partial(
              custom_load_session, hooked_mod_name=hookable_mod
          ),
          "load_module_asdict": functools.partial(
              custom_load_module_asdict, hooked_mod_name=hookable_mod
          ),
      }
      if hookable_mod not in ("torch", "torch.serialization"):
        methods_to_patch["_load"] = functools.partial(
            custom_load, hooked_mod_name=hookable_mod
        )
        methods_to_patch["_loads"] = functools.partial(
            custom_loads, hooked_mod_name=hookable_mod
        )
      for unpickler_attr in ("Unpickler", "_Unpickler"):
        if hasattr(module, unpickler_attr):
          original_attr = _ORIG_METHODS_BEFORE_HOOKING[hookable_mod].get(
              unpickler_attr, getattr(module, unpickler_attr)
          )
          if isinstance(original_attr, type):
            methods_to_patch[unpickler_attr] = _make_hooked_unpickler_class(
                original_attr,
                force_report_only=force_report_only,
                default_log_info=log_info,
            )

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
  was_already_hooked = bool(_ORIG_METHODS_BEFORE_HOOKING)
  hook_pickle(
      force_report_only=report_only, log_info=log_info, config_path=config_path
  )
  try:
    yield
  finally:
    if not was_already_hooked:
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
    _ORIG_METHODS_BEFORE_HOOKING.clear()


def load(
    pickle_file: Any,
    *args: Any,
    allow_unsafe: bool = False,
    strict_check: bool = False,
    report_only: bool = False,
    force_scan: bool = False,
    log_info: bool = False,
    check_magic_bytes: bool = True,
    **kwargs: Any,
) -> Any:
  """Custom load function to security scan before loading pickle files.

  This function can be used as a replacement for pickle.load or torch.load,
  providing security scan features.

  Args:
    pickle_file: The pickle file to load.
    *args: Additional arguments to pass to torch.load.
    allow_unsafe: If True, allow unsafe pickle files to be loaded.
    strict_check: If True, perform a strict security check on the pickle file.
    report_only: If True, only report errors and do not raise them.
    force_scan: If True, force scan even if the file is not a pickle file.
    log_info: If True, use logging.info instead of logging.error for reporting.
    check_magic_bytes: Whether to perform magic byte checks to fast path reject
      files.
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


def loads(
    pickle_bytes: bytes,
    *args: Any,
    allow_unsafe: bool = False,
    strict_check: bool = False,
    report_only: bool = False,
    force_scan: bool = False,
    log_info: bool = False,
    check_magic_bytes: bool = True,
    **kwargs: Any,
) -> Any:
  """Scans a pickle byte buffer for security risks before deserializing it.

  Validates `pickle_bytes` using the configured SaferPickle scan policy and,
  if permitted, deserializes the payload using an unhooked copy of
  `_pickle.loads`.

  Args:
    pickle_bytes: Raw pickle bytecode to scan and deserialize.
    *args: Additional positional arguments forwarded to `_pickle.loads`.
    allow_unsafe: Whether to bypass security scanning and allow unsafe payloads.
    strict_check: Whether to enforce strict allow-only security scanning.
    report_only: Whether to log violations instead of raising exceptions.
    force_scan: Whether to force scanning even if magic-byte detection fails.
    log_info: Whether to log `report_only` findings at `INFO` instead of
      `ERROR`.
    check_magic_bytes: Whether to enable magic-byte fast rejection.
    **kwargs: Additional keyword arguments forwarded to `_pickle.loads`.

  Returns:
    The deserialized Python object produced from `pickle_bytes`.
  """
  return _scan_and_load(
      pickle_bytes,
      allow_unsafe,
      strict_check,
      report_only,
      force_scan,
      "_pickle",
      False,
      log_info,
      check_magic_bytes,
      *args,
      **kwargs,
  )


Unpickler = _make_hooked_unpickler_class(_OriginalPickleUnpickler)


if __name__ == "__main__":
  if IS_COLAB_ENABLED:
    hook_pickle()

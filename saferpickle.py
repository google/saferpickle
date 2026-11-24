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


DEFAULT_FAIL_FAST = True


def _get_stream_pos(stream: Any) -> Optional[int]:
  """Safely retrieves the current byte offset of `stream` if supported."""
  try:
    return stream.tell()
  except (OSError, AttributeError, io.UnsupportedOperation):
    return None


def _resolve_pickle_length(
    pickle_bytes: Any,
    pickle_length: Optional[int],
) -> int:
  """Resolves the remaining byte length of a pickle buffer or stream.

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
  if position is None or not utils.is_seekable_stream(stream):
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


@dataclasses.dataclass
class ScanResults:
  """Results from a pickle security scan."""

  safe_results: Set[str] = dataclasses.field(default_factory=set)
  unsafe_results: Set[str] = dataclasses.field(default_factory=set)
  suspicious_results: Set[str] = dataclasses.field(default_factory=set)
  unknown_results: Set[str] = dataclasses.field(default_factory=set)
  is_denylisted: bool = False
  has_scannable_payload: bool = False


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

    if operand is None:
      continue
    operand_string = str(operand)
    is_import = opcode is not None and opcode.name in constants.IMPORT_OPCODES
    if not is_import and not utils.is_potentially_dangerous_literal(
        operand_string
    ):
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

  Args:
    pickle_bytes: The pickle bytecode or stream to disassemble.
    fail_fast: Whether to fail fast on first unsafe match.

  Returns:
    The operands associated with opcodes that declare strings.
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

  add = append

  def update(self, values: Any) -> None:
    """Records updated dictionary or iterable entries on the fake instance."""
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
    if full_name != "functools.partial":
      setattr(cls, "_is_safe_symbol", True)
    return cls

  def get_extension(self, code: int) -> None:
    """Resolves a `copyreg` extension code and pushes its fake class onto stack."""
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
    visited_ids = set()

    def _enqueue_dict(candidate_dict: dict[Any, Any]) -> None:
      """Appends `candidate_dict` once while tracking visited `id()` values."""
      dict_id = id(candidate_dict)
      if dict_id in visited_ids:
        return
      visited_ids.add(dict_id)
      dicts_to_check.append(candidate_dict)

    def _add_candidate_dict(candidate: Any) -> None:
      """Extracts attribute dictionaries from `candidate` into `dicts_to_check`.

      Args:
        candidate: A state dictionary, tuple element, or `FakeClass` instance.
      """
      if isinstance(candidate, dict):
        _enqueue_dict(candidate)
        return
      if not isinstance(candidate, picklemagic.FakeClass):
        return

      candidate_id = id(candidate)
      if candidate_id in visited_ids:
        return
      visited_ids.add(candidate_id)

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
          _enqueue_dict(keyword_dict)

      def _extract_key_value_pairs(sequence_candidate: Any) -> None:
        """Recursively extracts `(key, value)` pairs from nested sequences.

        Args:
          sequence_candidate: Container or element from positional/list args.
        """
        if isinstance(sequence_candidate, (dict, picklemagic.FakeClass)):
          _add_candidate_dict(sequence_candidate)
          return
        if not isinstance(sequence_candidate, (list, tuple, set, frozenset)):
          return

        seq_id = id(sequence_candidate)
        if seq_id in visited_ids:
          return
        visited_ids.add(seq_id)

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

    if isinstance(state, tuple):
      for tuple_item in state:
        _add_candidate_dict(tuple_item)
    else:
      _add_candidate_dict(state)

    for state_dict in dicts_to_check:
      for key, val in state_dict.items():
        key_str = _decode_bytes_or_str(key)
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

    state = self.stack[-1]
    inst = self.stack[-2] if len(self.stack) >= 2 else None
    if self._is_functools_partial_instance(inst):
      self.stack.pop()
      if not self._is_valid_partial_setstate(state):
        self.has_blocked_unsafe_build_instr = True
        return
      inst.__dict__["_setstate_args"] = state
      return

    if self._state_has_dangerous_keys(state):
      self.has_blocked_unsafe_build_instr = True
      self.stack.pop()
      return
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

  @staticmethod
  def _is_sandbox_callable(target: Any) -> bool:
    """Checks whether `target` is a sandboxed `FakeClass` callable or type."""
    return isinstance(
        target, (picklemagic.FakeClass, picklemagic.FakeClassType)
    ) or (
        isinstance(target, type) and issubclass(target, picklemagic.FakeClass)
    )

  @staticmethod
  def _is_functools_partial_type(candidate: Any) -> bool:
    """Checks whether `candidate` is the sandbox `functools.partial` class."""
    candidate_type = type(candidate)
    return (
        candidate_type is picklemagic.FakeClassType
        and getattr(candidate, "__module__", "") == "functools"
        and getattr(candidate, "__name__", "") == "partial"
    )

  @staticmethod
  def _is_functools_partial_instance(candidate: Any) -> bool:
    """Checks whether `candidate` is a sandbox `functools.partial` instance."""
    candidate_type = type(candidate)
    return (
        candidate_type is not picklemagic.FakeClassType
        and isinstance(candidate, picklemagic.FakeClass)
        and candidate.__class__.__module__ == "functools"
        and candidate.__class__.__name__ == "partial"
    )

  @staticmethod
  def _has_dangerous_partial_kwds(kwds: Any) -> bool:
    """Checks whether a `functools.partial` keyword dict has invalid keys.

    Args:
      kwds: Keyword argument dictionary bound on `functools.partial`.

    Returns:
      True if `kwds` is not a `dict` or contains non-string or dunder keys, or
      False otherwise.
    """
    if not isinstance(kwds, dict):
      return True

    for kw_key in kwds:
      kw_key_str = _decode_bytes_or_str(kw_key)
      if kw_key_str is None:
        return True
      if utils.is_dunder_or_introspection_attr(kw_key_str):
        return True

    return False

  def _is_safe_partial_target(
      self,
      target: Any,
      visited_object_ids: set[int] | None = None,
      *,
      only_suspicious: bool = False,
      inspection_depth: int = 0,
  ) -> bool:
    """Checks whether `target` is an explicitly safe `functools.partial` target.

    Args:
      target: Wrapped callable argument at index 0 of `functools.partial`.
      visited_object_ids: Set of already-visited `id(obj)` integers.
      only_suspicious: Passed through when inspecting bound argument values.
      inspection_depth: Current recursion depth within the object graph.

    Returns:
      True if `target` is safe to wrap in `functools.partial`, or False
      otherwise.
    """
    if inspection_depth > 64:
      return False

    if visited_object_ids is None:
      visited_object_ids = set()

    target_type = type(target)
    if target_type is picklemagic.FakeClassType and target.__dict__.get(
        "_is_safe_symbol", False
    ):
      return not self._state_contains_fake_class(
          target,
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      )

    if self._is_functools_partial_instance(target):
      target_id = id(target)
      if target_id in visited_object_ids:
        return False

      next_visited = set(visited_object_ids)
      next_visited.add(target_id)
      return not self._partial_instance_has_unsafe_state(
          target,
          next_visited,
          only_suspicious=only_suspicious,
          inspection_depth=inspection_depth + 1,
      )

    return False

  def _is_valid_partial_setstate(
      self,
      state: Any,
      visited_object_ids: set[int] | None = None,
      *,
      only_suspicious: bool = True,
      inspection_depth: int = 0,
  ) -> bool:
    """Validates a `BUILD` state tuple for `functools.partial.__setstate__`.

    Args:
      state: State payload passed to `BUILD` or stored in `_setstate_args`.
      visited_object_ids: Set of already-visited `id(obj)` integers.
      only_suspicious: Passed through when inspecting bound argument values.
      inspection_depth: Current recursion depth within the object graph.

    Returns:
      True if `state` is a valid and safe `functools.partial` state tuple, or
      False otherwise.
    """
    if not isinstance(state, tuple) or len(state) != 4:
      return False

    if visited_object_ids is None:
      visited_object_ids = set()

    state_func, state_args, state_kwds, state_namespace = state
    if not isinstance(state_args, tuple):
      return False
    if state_kwds is not None and self._has_dangerous_partial_kwds(state_kwds):
      return False
    if state_namespace is not None and (
        not isinstance(state_namespace, dict)
        or self._state_has_dangerous_keys(state_namespace)
    ):
      return False

    if not self._is_safe_partial_target(
        state_func,
        visited_object_ids,
        only_suspicious=only_suspicious,
        inspection_depth=inspection_depth + 1,
    ):
      return False

    for state_component in (state_args, state_kwds, state_namespace):
      if state_component is not None and self._state_contains_fake_class(
          state_component,
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      ):
        return False

    return True

  def _has_invalid_partial_construction_args(
      self,
      args: Any,
      kwargs: Any = None,
  ) -> bool:
    """Checks whether construction arguments for `functools.partial` are unsafe.

    Args:
      args: Positional argument tuple passed to `functools.partial`.
      kwargs: Optional keyword argument dictionary from `NEWOBJ_EX`.

    Returns:
      True if the `functools.partial` construction arguments are invalid or
      unsafe, or False otherwise.
    """
    if not isinstance(args, tuple) or not args:
      return True

    if not self._is_safe_partial_target(
        args[0],
        visited_object_ids=set(),
        only_suspicious=True,
        inspection_depth=0,
    ):
      return True

    if len(args) > 1 and self._state_contains_fake_class(
        args[1:], only_suspicious=True
    ):
      return True

    if kwargs is not None and (
        self._has_dangerous_partial_kwds(kwargs)
        or self._state_contains_fake_class(kwargs, only_suspicious=True)
    ):
      return True

    return False

  def _partial_instance_has_unsafe_state(
      self,
      partial_inst: Any,
      visited_object_ids: set[int],
      *,
      only_suspicious: bool,
      inspection_depth: int,
  ) -> bool:
    """Checks whether a sandbox `functools.partial` instance holds unsafe state.

    Args:
      partial_inst: Sandboxed `FakeClass` instance of `functools.partial`.
      visited_object_ids: Set of already-visited `id(obj)` integers.
      only_suspicious: Passed through when inspecting bound argument values.
      inspection_depth: Current recursion depth within the object graph.

    Returns:
      True if `partial_inst` has missing, unapproved, or suspicious bound
      state, or False otherwise.
    """
    if utils.matches_symbol_prefix_list(
        "functools.partial", config.get_deny_list()
    ):
      return True

    inst_dict = getattr(partial_inst, "__dict__", None)
    if not isinstance(inst_dict, dict):
      return True

    has_verified_target = False
    if "_new_args" in inst_dict:
      new_args = inst_dict["_new_args"]
      if not isinstance(new_args, tuple) or not new_args:
        return True

      if not self._is_safe_partial_target(
          new_args[0],
          visited_object_ids,
          only_suspicious=only_suspicious,
          inspection_depth=inspection_depth + 1,
      ):
        return True

      if len(new_args) > 1 and self._state_contains_fake_class(
          new_args[1:],
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      ):
        return True
      has_verified_target = True

    if "_setstate_args" in inst_dict:
      if not self._is_valid_partial_setstate(
          inst_dict["_setstate_args"],
          visited_object_ids,
          only_suspicious=only_suspicious,
          inspection_depth=inspection_depth + 1,
      ):
        return True
      has_verified_target = True

    if not has_verified_target:
      return True

    for kw_attr_name in ("_new_kwargs", "_kwargs"):
      kw_dict = inst_dict.get(kw_attr_name)
      if kw_dict is None:
        continue
      if self._has_dangerous_partial_kwds(
          kw_dict
      ) or self._state_contains_fake_class(
          kw_dict,
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      ):
        return True

    for seq_attr_name in ("_args", "_list_items"):
      seq_value = inst_dict.get(seq_attr_name)
      if seq_value and self._state_contains_fake_class(
          seq_value,
          visited_object_ids,
          only_suspicious,
          inspection_depth + 1,
      ):
        return True

    user_state = {}
    for attr_key, attr_val in inst_dict.items():
      if attr_key not in constants.FAKE_CLASS_INTERNAL_ATTRIBUTES:
        user_state[attr_key] = attr_val

    if user_state and (
        self._state_has_dangerous_keys(user_state)
        or self._state_contains_fake_class(
            user_state,
            visited_object_ids,
            only_suspicious,
            inspection_depth + 1,
        )
    ):
      return True

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

    if not self._is_sandbox_callable(func) or (
        self._is_functools_partial_instance(func)
    ):
      self.has_blocked_unsafe_build_instr = True
      stack[-1] = self.class_factory("failed_reduce", "picklemagic")()
      return

    func_type = type(func)
    if self._is_functools_partial_type(
        func
    ) and self._has_invalid_partial_construction_args(args):
      self.has_blocked_unsafe_build_instr = True

    if (
        func_type is picklemagic.FakeClassType
        and getattr(func, "__module__", "") in ("copyreg", "copy_reg")
        and getattr(func, "__name__", "") == "_reconstructor"
        and isinstance(args, tuple)
        and len(args) >= 2
        and self._is_functools_partial_type(args[1])
    ):
      self.has_blocked_unsafe_build_instr = True

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

    Args:
      klass: Class or callable object resolved for `INST` or `OBJ`.
      args: Tuple of positional arguments for instantiation.
    """
    if (
        not self._is_sandbox_callable(klass)
        or self._is_functools_partial_instance(klass)
        or (
            self._is_functools_partial_type(klass)
            and self._has_invalid_partial_construction_args(args)
        )
        or self._state_contains_fake_class(args, only_suspicious=True)
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

    Args:
      cls: Target class popped from the unpickler stack.
      args: Positional argument tuple passed to `__new__`.
      kwargs: Optional keyword argument dict passed by `NEWOBJ_EX`.
    """
    if (
        not self._is_sandbox_callable(cls)
        or self._is_functools_partial_instance(cls)
        or (
            self._is_functools_partial_type(cls)
            and self._has_invalid_partial_construction_args(args, kwargs)
        )
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
    if length > 4096 and utils.is_seekable_stream(target_stream):
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
      inst_dict = getattr(object_to_inspect, "__dict__", None)
      if isinstance(inst_dict, dict):
        for attribute_value in inst_dict.values():
          if attribute_value and self._state_contains_fake_class(
              attribute_value,
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
      if self._is_functools_partial_instance(object_to_inspect):
        return self._partial_instance_has_unsafe_state(
            object_to_inspect,
            visited_object_ids,
            only_suspicious=only_suspicious,
            inspection_depth=inspection_depth,
        )

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
  global _PICKLEMAGIC_ACTIVE_SCANS
  global _PICKLEMAGIC_ORIG_LEVEL
  global _PICKLEMAGIC_ORIG_PROPAGATE

  picklemagic_output = io.StringIO()
  was_unsafe_build_blocked = False
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

  original_pos = _get_stream_pos(pickle_bytes)
  normalized_input = utils.ensure_seekable_stream(pickle_bytes)
  pickle_stream = (
      io.BytesIO(bytes(normalized_input))
      if isinstance(normalized_input, (bytes, mmap.mmap))
      else normalized_input
  )

  try:
    try:
      while True:
        frame_start = _get_stream_pos(pickle_stream)
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
        try:
          unpickler.load()
        finally:
          if getattr(unpickler, "has_blocked_unsafe_build_instr", False):
            was_unsafe_build_blocked = True

        after_pos = _get_stream_pos(pickle_stream)
        if frame_start is None or after_pos is None or after_pos <= frame_start:
          break
        peeked = utils.peek_bytes(pickle_stream, 1024)
        stripped = peeked.lstrip(b"\x00\n\r ")
        if (
            not stripped
            or stripped.startswith(b"000")
            or not utils.is_pickle_file(stripped, check_magic_bytes=True)
        ):
          break
        _safe_seek(pickle_stream, after_pos + (len(peeked) - len(stripped)))

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
    with _PICKLEMAGIC_LOGGER_LOCK:
      logger.removeHandler(handler)
      _PICKLEMAGIC_ACTIVE_SCANS -= 1
      if _PICKLEMAGIC_ACTIVE_SCANS == 0:
        if _PICKLEMAGIC_ORIG_LEVEL is not None:
          logger.setLevel(_PICKLEMAGIC_ORIG_LEVEL)
        if _PICKLEMAGIC_ORIG_PROPAGATE is not None:
          logger.propagate = _PICKLEMAGIC_ORIG_PROPAGATE
    _safe_seek(pickle_bytes, original_pos)

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
  pickle_bytes = utils.ensure_seekable_stream(pickle_bytes)

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
    is_pickle = bool(
        utils.is_pickle_file(stream, check_magic_bytes=check_magic_bytes)
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


_ORIG_METHODS_BEFORE_HOOKING: dict[str, dict[str, Any]] = {}
_HOOKING_LOCK = threading.Lock()
_UNPICKLE_BYPASS_STATE = threading.local()


@contextlib.contextmanager
def _bypass_unpickle_hooks() -> Iterator[None]:
  """Temporarily marks the current thread as inside a verified unpickle call."""
  previous_bypass = getattr(_UNPICKLE_BYPASS_STATE, "active", False)
  _UNPICKLE_BYPASS_STATE.active = True
  try:
    yield
  finally:
    _UNPICKLE_BYPASS_STATE.active = previous_bypass


def _report_or_raise(
    message: str,
    report_only: bool,
    log_info: bool = False,
    exc_cls: type[Exception] = UnsafePickleDetectedError,
) -> None:
  """Logs `message` when `report_only` is True, or raises `exc_cls(message)`."""
  if report_only:
    logging_function = logging.info if log_info else logging.error
    logging_function("%s", message)
    return
  raise exc_cls(message)


def _enforce_scan_policy(
    scan_source: Any,
    allow_unsafe: bool,
    strict_check: bool,
    report_only: bool,
    force_scan: bool,
    log_info: bool,
    check_magic_bytes: bool = True,
) -> None:
  """Executes the configured SaferPickle scan policy on `scan_source`.

  Args:
    scan_source: Pickle byte buffer or seekable binary stream to scan.
    allow_unsafe: Whether to bypass security scanning and allow unsafe payloads.
    strict_check: Whether to enforce strict allow-only security scanning.
    report_only: Whether to log violations instead of raising exceptions.
    force_scan: Whether to scan inputs even if they fail magic-byte detection.
    log_info: Whether to log `report_only` findings at `INFO` instead of
      `ERROR`.
    check_magic_bytes: Whether to enable magic-byte fast rejection.

  Raises:
    IllegalArgumentCombinationError: If both `strict_check` and
      `allow_unsafe` are True and `report_only` is False.
    StrictCheckError: If `strict_check` is True, the scan fails, and
      `report_only` is False.
    UnsafePickleDetectedError: If `security_scan` detects unsafe, suspicious,
      or unknown symbols and `report_only` is False.
  """
  if strict_check and allow_unsafe:
    _report_or_raise(
        "Strict scanning and allow_unsafe cannot be used together.",
        report_only,
        log_info,
        IllegalArgumentCombinationError,
    )
    return

  if allow_unsafe:
    if report_only:
      logging.info("Loading pickle file with allow_unsafe set to True.")
    return

  try:
    if strict_check:
      if strict_security_scan(scan_source):
        _report_or_raise(
            "Pickle file failed strict security check.",
            report_only,
            log_info,
            StrictCheckError,
        )
      return

    # Bytes headed to an unpickler are always scanned; the pickle-detection
    # heuristic only triages archive members and offline scans.
    is_bare_payload = (
        bool(utils.peek_bytes(scan_source, 1))
        and utils.detect_archive_type(scan_source) is None
    )

    scan_scores = security_scan(
        scan_source,
        force_scan=force_scan or is_bare_payload,
        check_magic_bytes=check_magic_bytes,
    )
    for key, cls in (
        ("unsafe", utils.Classification.UNSAFE),
        ("suspicious", utils.Classification.SUSPICIOUS),
        ("unknown", utils.Classification.UNKNOWN),
    ):
      if scan_scores[key] > 0:
        _report_or_raise(
            constants.ERROR_STRING.substitute(classification=cls.value),
            report_only,
            log_info,
        )
        return
  except Exception as exc:  # pylint: disable=broad-exception-caught
    # Report-only mode must never block a load, even when the scanner fails.
    if not report_only:
      raise
    _report_or_raise(f"Security scan failed: {exc}", report_only, log_info)
    return

  if report_only:
    logging.info("Loading safe pickle file")


def _prepare_stream_for_scan_and_load(pickle_file: Any) -> Any:
  """Normalizes `pickle_file` to a seekable stream at the pickle start."""
  pickle_file = utils.ensure_seekable_stream(pickle_file)
  current_pos = _get_stream_pos(pickle_file)
  if current_pos is not None and utils.detect_archive_type(pickle_file) is None:
    start_offset = utils.find_pickle_start_offset(pickle_file)
    if start_offset > 0:
      _safe_seek(pickle_file, current_pos + start_offset)
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
        _enforce_scan_policy(
            prepared_stream,
            allow_unsafe=allow_unsafe,
            strict_check=strict_check,
            report_only=report_only,
            force_scan=force_scan,
            log_info=log_info,
            check_magic_bytes=check_magic_bytes,
        )
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

    start_offset = 0
    if utils.detect_archive_type(data_bytes) is None:
      start_offset = utils.find_pickle_start_offset(data_bytes)
    if start_offset > 0:
      data_bytes = data_bytes[start_offset:]
    scan_source = data_bytes
    load_args = (data_bytes,)

  if not already_scanned:
    _enforce_scan_policy(
        scan_source,
        allow_unsafe=allow_unsafe,
        strict_check=strict_check,
        report_only=report_only,
        force_scan=force_scan,
        log_info=log_info,
        check_magic_bytes=check_magic_bytes,
    )

  with _bypass_unpickle_hooks():
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


def _make_hooked_unpickler_class(
    original_unpickler_cls: type[Any],
    *,
    force_report_only: bool = False,
    default_log_info: bool = False,
) -> type[Any]:
  """Creates a hooked `Unpickler` subclass wrapping `original_unpickler_cls`.

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

      Returns:
        The deserialized Python object from `original_unpickler_cls.load`.
      """
      if getattr(_UNPICKLE_BYPASS_STATE, "active", False):
        return original_unpickler_cls.load(self)

      current_pos = _get_stream_pos(self._sp_file)
      try:
        _enforce_scan_policy(
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

      with _bypass_unpickle_hooks():
        return original_unpickler_cls.load(self)  # pylint: disable=g-unsafe-pickle-load

  return _HookedUnpickler


def hook_pickle(
    force_report_only: bool = False,
    log_info: bool = False,
    config_path: Optional[str] = None,
) -> None:
  """This implements the hooking of pickle-like libraries."""
  config.set_config_path(config_path)

  def _hooked_loader(
      pickle_input: Any,
      *args: Any,
      allow_unsafe: bool = False,
      strict_check: bool = False,
      report_only: bool = False,
      force_scan: bool = False,
      hooked_mod_name: str = "",
      check_magic_bytes: bool = True,
      _is_load: bool = True,
      _hooked_func_name: str = "",
      **kwargs: Any,
  ) -> Any:
    """Scans `pickle_input` before delegating to the hooked module's loader.

    Args:
      pickle_input: File path, binary stream, or byte buffer to unpickle.
      *args: Additional positional arguments for the underlying loader.
      allow_unsafe: Whether to bypass security scanning.
      strict_check: Whether to enforce strict security scanning.
      report_only: Whether to log violations instead of raising exceptions.
      force_scan: Whether to force scanning on non-pickle-looking inputs.
      hooked_mod_name: Name of the hooked module whose original loader is used.
      check_magic_bytes: Whether to enable magic-byte fast rejection.
      _is_load: Internal flag indicating file-based (`True`) vs bytes (`False`).
      _hooked_func_name: Internal override for the underlying attribute name.
      **kwargs: Additional keyword arguments for the underlying loader.

    Returns:
      The deserialized object if allowed, otherwise raises an exception.
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
        _is_load,
        log_info,
        check_magic_bytes,
        *args,
        hooked_func_name=_hooked_func_name,
        **kwargs,
    )

  base_loader_specs = (
      ("load", True, ""),
      ("loads", False, ""),
      ("load_module", True, "load_module"),
      ("load_session", True, "load_session"),
      ("load_module_asdict", True, "load_module_asdict"),
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

      loader_specs = list(base_loader_specs)
      if hookable_mod not in ("torch", "torch.serialization"):
        loader_specs.extend([("_load", True, ""), ("_loads", False, "")])

      methods_to_patch: dict[str, Any] = {
          attr_name: functools.partial(
              _hooked_loader,
              hooked_mod_name=hookable_mod,
              _is_load=is_load,
              _hooked_func_name=func_name,
          )
          for attr_name, is_load, func_name in loader_specs
      }
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
  previous_config_path = config.get_config_path()
  previous_active_hooks: dict[str, dict[str, Any]] = {}
  with _HOOKING_LOCK:
    was_already_hooked = bool(_ORIG_METHODS_BEFORE_HOOKING)
    if was_already_hooked:
      for module_name, methods in _ORIG_METHODS_BEFORE_HOOKING.items():
        module = sys.modules.get(module_name)
        if module is None:
          continue
        module_snapshot: dict[str, Any] = {}
        for method_name in methods:
          if hasattr(module, method_name):
            module_snapshot[method_name] = getattr(module, method_name)
        previous_active_hooks[module_name] = module_snapshot

  effective_config_path = (
      config_path if config_path is not None else previous_config_path
  )
  hook_pickle(
      force_report_only=report_only,
      log_info=log_info,
      config_path=effective_config_path,
  )
  try:
    yield
  finally:
    if not was_already_hooked:
      unhook_pickle()
    else:
      with _HOOKING_LOCK:
        for module_name, methods in list(_ORIG_METHODS_BEFORE_HOOKING.items()):
          module = sys.modules.get(module_name)
          if module is None:
            continue
          saved_module_hooks = previous_active_hooks.get(module_name)
          if saved_module_hooks is None:
            for method_name, orig_method in methods.items():
              if hasattr(module, method_name):
                setattr(module, method_name, orig_method)
            del _ORIG_METHODS_BEFORE_HOOKING[module_name]
          else:
            for method_name in list(methods.keys()):
              if method_name in saved_module_hooks:
                setattr(module, method_name, saved_module_hooks[method_name])
              else:
                setattr(module, method_name, methods.pop(method_name))
    config.set_config_path(previous_config_path)


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


Unpickler = _make_hooked_unpickler_class(pickle.Unpickler)


if __name__ == "__main__":
  if "google.colab" in sys.modules:
    hook_pickle()

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

import collections
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
import re
import struct
import sys
import threading
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    IO,
    Iterator,
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


def _custom_genops(
    pickle_bytes: bytes | BinaryIO,
) -> Iterator[tuple[Optional[pickletools.OpcodeInfo], Any | None]]:
  """Generates string-declaring opcodes and their arguments from pickle data.

  Args:
    pickle_bytes: The pickle data to generate opcodes from.

  Yields:
    A tuple of (opcode, opcode_argument) for each string-declaring opcode.
  """
  if isinstance(pickle_bytes, (bytes, io.BytesIO)):
    raw_bytes = (
        pickle_bytes
        if isinstance(pickle_bytes, bytes)
        else pickle_bytes.getvalue()
    )
    yield from utils.custom_genops_from_bytes(raw_bytes)
    return

  pickle_file = pickle_bytes
  memo: dict[int, str] = {}
  memo_index = 0
  recent_strings: collections.deque[str] = collections.deque(maxlen=16)
  mark_stack: list[int] = []
  last_emitted_string: str | None = None

  while True:
    charcode = pickle_file.read(1)
    if not charcode:
      break

    try:
      opcode = constants.OPCODES_INFO_INT.get(charcode[0])
    except IndexError:
      continue

    if opcode is None:
      continue

    opcode_argument = None
    if opcode.arg is not None:
      skipped = False
      if charcode in constants.LENGTH_PREFIXED_OPCODES:
        try:
          n_len = (
              4
              if charcode in constants.OPCODES_4BYTE_LEN
              else (8 if charcode in constants.OPCODES_8BYTE_LEN else 1)
          )
          length = int.from_bytes(pickle_file.read(n_len), byteorder="little")
          pickle_file.seek(length, os.SEEK_CUR)
          skipped = True
        except (AttributeError, io.UnsupportedOperation, OSError):
          pass
      if not skipped:
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

    # Memo tracking
    if opcode.name == "MEMOIZE":
      if last_emitted_string is not None:
        memo[memo_index] = last_emitted_string
        last_emitted_string = None
      memo_index += 1
      continue
    elif opcode.name in ("PUT", "BINPUT", "LONG_BINPUT"):
      if last_emitted_string is not None and isinstance(opcode_argument, int):
        memo[opcode_argument] = last_emitted_string
      last_emitted_string = None
      continue
    elif opcode.name in ("GET", "BINGET", "LONG_BINGET"):
      if isinstance(opcode_argument, int) and opcode_argument in memo:
        val = memo[opcode_argument]
        recent_strings.append(val)
        last_emitted_string = val
      else:
        last_emitted_string = None
      continue

    # Stack manipulation opcodes
    if opcode.name == "MARK":
      mark_stack.append(len(recent_strings))
      last_emitted_string = None
    elif opcode.name == "POP":
      if recent_strings:
        recent_strings.pop()
      last_emitted_string = None
    elif opcode.name == "POP_MARK":
      target_length = mark_stack.pop() if mark_stack else 0
      while len(recent_strings) > target_length:
        recent_strings.pop()
      last_emitted_string = None
    elif opcode.name == "DUP":
      if recent_strings:
        recent_strings.append(recent_strings[-1])
        last_emitted_string = recent_strings[-1]

    # STACK_GLOBAL tracking
    if opcode.name == "STACK_GLOBAL":
      if len(recent_strings) >= 2:
        attribute_member = recent_strings.pop()
        module_member = recent_strings.pop()
        qualname = f"{module_member}.{attribute_member}"
        recent_strings.append(qualname)
        last_emitted_string = qualname
        yield opcode, qualname
      else:
        yield opcode, "STACK_GLOBAL"
      continue

    # Extension registry lookup opcodes
    if opcode.name in ("EXT1", "EXT2", "EXT4") and isinstance(
        opcode_argument, int
    ):
      resolved_ext = utils.resolve_extension_code(opcode_argument)
      recent_strings.append(resolved_ext)
      last_emitted_string = resolved_ext
      yield opcode, resolved_ext
      continue

    # Persistent ID opcodes
    if opcode.name in ("PERSID", "BINPERSID"):
      last_emitted_string = None
      if opcode.name == "PERSID":
        pid_str = str(opcode_argument) if opcode_argument is not None else ""
      elif "storage" in recent_strings:
        recent_strings.clear()
        continue
      else:
        pid_str = recent_strings.pop() if recent_strings else ""
      if pid_str:
        operand = (
            pid_str
            if utils.is_potentially_dangerous_literal(pid_str)
            else f"persistent_id.{pid_str}"
        )
        yield opcode, operand
      else:
        yield opcode, f"persistent_id.{opcode.name}"
      continue

    # GLOBAL and INST space-separated / tuple normalization
    if opcode.name in ("GLOBAL", "INST") and opcode_argument is not None:
      if isinstance(opcode_argument, str):
        qualname = opcode_argument.replace(" ", ".", 1)
      elif isinstance(opcode_argument, tuple) and len(opcode_argument) == 2:
        qualname = f"{opcode_argument[0]}.{opcode_argument[1]}"
      else:
        continue
      recent_strings.append(qualname)
      last_emitted_string = qualname
      yield opcode, qualname
      continue

    # We only yield opcodes that declare strings and have arguments
    should_yield = any(
        s in opcode.name for s in constants.OPCODE_SUBSTRS_THAT_DECLARE_STRINGS
    )
    if should_yield and opcode_argument is not None:
      if isinstance(opcode_argument, (str, bytes)) and len(opcode_argument) > 1:
        if isinstance(opcode_argument, bytes):
          try:
            opcode_argument = opcode_argument.decode("utf-8")
          except (UnicodeDecodeError, AttributeError):
            pass
        if isinstance(opcode_argument, str):
          recent_strings.append(opcode_argument)
          last_emitted_string = opcode_argument
        yield opcode, opcode_argument
      elif isinstance(opcode_argument, tuple):
        yield opcode, opcode_argument
    else:
      last_emitted_string = None

    if charcode == b".":
      break


def _should_collect_operand(
    opcode: Optional[pickletools.OpcodeInfo], operand_str: str
) -> bool:
  """Returns True if an operand is an import or a dangerous string literal."""
  if opcode is not None and opcode.name in constants.IMPORT_OPCODES:
    return True
  return utils.is_potentially_dangerous_literal(operand_str)


def _scan_byte_slice(
    data: bytes | mmap.mmap,
    start: int,
    end: int,
    seed_stack: Sequence[str] = (),
    fail_fast: bool = False,
    abort_event: Optional[threading.Event] = None,
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

  Returns:
    A set of string operands discovered within the byte slice.
  """
  discovered_operands = set()
  for chunk_index, (opcode, operand) in enumerate(
      utils.custom_genops_from_bytes(
          data, start=start, end=end, seed_stack=seed_stack
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
      if fail_fast and utils.is_unsafe_or_suspicious(operand_string):
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
      pickle_bytes = file_handle.read()

  effective_length = (
      pickle_length if pickle_length is not None else len(pickle_bytes)
  )
  num_workers = utils.get_optimal_workers(effective_length)

  if (
      effective_length < constants.MIN_SIZE_FOR_CHUNKING
      or num_workers <= 1
      or not utils.is_sys_executable_patched()
  ):
    return _scan_byte_slice(
        pickle_bytes, 0, effective_length, fail_fast=bool(fail_fast)
    )

  target_chunk_size = max(
      constants.MIN_SIZE_FOR_CHUNKING, effective_length // num_workers
  )
  chunk_ranges = utils.partition_pickle_chunks(
      pickle_bytes, target_chunk_size, end=effective_length
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
        )
        for start_offset, end_offset, seed_stack in chunk_ranges
    ]
    for future in concurrent.futures.as_completed(futures):
      chunk_results = future.result()
      all_operands.update(chunk_results)
      if fail_fast and any(
          utils.is_unsafe_or_suspicious(item) for item in chunk_results
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
  original_pos = None
  if not isinstance(pickle_bytes, bytes):
    original_pos = pickle_bytes.tell()

  try:
    try:
      for opcode, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
        if operand is None:
          continue
        operand_str = str(operand)
        if not _should_collect_operand(opcode, operand_str):
          continue
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


class _SaferFakeWarning(picklemagic.FakeWarning):
  """FakeWarning subclass supporting dict/list population opcodes in sandbox."""

  __module__ = "corrupy.picklemagic"

  def __setitem__(self, key: Any, value: Any) -> None:
    self.__dict__[str(key)] = value

  def append(self, value: Any) -> None:
    self.__dict__.setdefault("_list_items", []).append(value)

  def extend(self, values: Any) -> None:
    self.__dict__.setdefault("_list_items", []).extend(values)


class SaferUnpickler(picklemagic.SafeUnpickler):
  """Subclass of SafeUnpickler to optimize state checking during BUILD.

  Overrides and refines object state verification to prevent bypasses from
  injecting malicious state or invoking dangerous reduction callbacks on
  untrusted classes.
  """

  def __init__(self, file: Any, *args: Any, **kwargs: Any) -> None:
    super().__init__(file, *args, **kwargs)
    self._raw_stream = file
    self.dispatch = self.dispatch.copy()
    self.dispatch[pickle.BINBYTES[0]] = self._load_binbytes_fast
    if hasattr(pickle, "BINSTRING"):
      self.dispatch[pickle.BINSTRING[0]] = self._load_binstring_fast
    if hasattr(pickle, "BINBYTES8"):
      self.dispatch[pickle.BINBYTES8[0]] = self._load_binbytes8_fast
    if hasattr(pickle, "BYTEARRAY8"):
      self.dispatch[pickle.BYTEARRAY8[0]] = self._load_bytearray8_fast

  def find_class(self, module: Any, name: Any) -> Any:
    module, name = (
        x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x)
        for x in (module, name)
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

    if any(full_name.startswith(d) for d in deny_list):
      pm_logger.warning("Unsafe module/class invoked: %s", full_name)
      return self.class_factory(name, module)

    if any(full_name.startswith(a) for a in allow_list):
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
    if self._state_contains_fake_class(pid):
      self.has_blocked_unsafe_build_instr = True
    if (
        isinstance(pid, tuple)
        and len(pid) >= 2
        and pid[0] in ("storage", b"storage")
    ):
      return self.class_factory("Storage", "torch")()
    pid_str = (
        pid.decode("utf-8", errors="ignore")
        if isinstance(pid, bytes)
        else str(pid)
    )
    pm_logger = std_logging.getLogger("corrupy.picklemagic")
    if utils.is_potentially_dangerous_literal(pid_str):
      pm_logger.warning("Unsafe module/class invoked: %s", pid_str)
    else:
      pm_logger.warning(
          "Unknown module/class imported: persistent_id.%s", pid_str
      )
    return self.class_factory("PersistentObject", "persistent_id")()

  def _state_has_dangerous_keys(self, state: Any) -> bool:
    """Checks if a BUILD state dict or tuple overwrites dangerous attributes."""
    dicts_to_check = []
    if isinstance(state, dict):
      dicts_to_check.append(state)
    elif isinstance(state, tuple) and len(state) == 2:
      if isinstance(state[0], dict):
        dicts_to_check.append(state[0])
      if isinstance(state[1], dict):
        dicts_to_check.append(state[1])
    for state_dict in dicts_to_check:
      for key, val in state_dict.items():
        key_str = (
            key.decode("utf-8", errors="ignore")
            if isinstance(key, bytes)
            else (key if isinstance(key, str) else None)
        )
        if key_str == "__dict__" and isinstance(val, dict):
          dicts_to_check.append(val)
          continue
        if key_str in constants.DANGEROUS_BUILD_STATE_KEYS:
          if not key_str.startswith("__") and isinstance(
              val, (int, float, str, bytes, bool, type(None))
          ):
            continue
          return True
    return False

  def load_build(self, *unused_args: Any) -> None:
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
    if is_type_target or self._inspect_state_for_fake_class(
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
      self.stack.pop()
      return
    super().load_build(*unused_args)

  @staticmethod
  def _is_cacheable_safe_arg(arg: Any) -> bool:
    if isinstance(arg, (int, float, bytes, bytearray, bool, type(None))):
      return True
    arg_type = type(arg)
    if arg_type.__dict__.get("_is_safe_symbol", False):
      return True
    if arg_type is picklemagic.FakeClassType and arg.__dict__.get(
        "_is_safe_symbol", False
    ):
      return True
    if isinstance(arg, tuple) and len(arg) <= 8:
      return all(
          isinstance(x, (int, float, bytes, bytearray, bool, type(None)))
          for x in arg
      )
    return False

  def load_reduce(self, *unused_args: Any) -> None:
    stack = self.stack
    args = stack.pop()
    func = stack[-1]

    is_safe_func = isinstance(func, type) and func.__dict__.get(
        "_is_safe_symbol", False
    )
    if is_safe_func and isinstance(args, tuple):
      cached_inst = func.__dict__.get("_cached_safe_instance")
      if cached_inst is not None and all(
          self._is_cacheable_safe_arg(a) for a in args
      ):
        stack[-1] = cached_inst
        return

    if self._inspect_state_for_fake_class(args, only_suspicious=True):
      self.has_blocked_unsafe_build_instr = True

    try:
      stack[-1] = func(*args)
      if is_safe_func and not self.has_blocked_unsafe_build_instr:
        setattr(func, "_cached_safe_instance", stack[-1])
    except Exception as e:  # pylint: disable=broad-exception-caught
      std_logging.getLogger("corrupy.picklemagic").warning(
          "Failed to reduce %s with %s: %s", func, args, e
      )
      stack[-1] = self.class_factory("failed_reduce", "picklemagic")()

  def _skip_or_read_bytes(
      self, length: int, as_bytearray: bool = False
  ) -> None:
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
      self.append(bytearray() if as_bytearray else b"")
      return
    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")
    self.append(bytearray(data) if as_bytearray else data)

  def _load_binstring_fast(self, *unused_args: Any) -> None:
    (length,) = struct.unpack("<i", self.read(4))
    if length < 0:
      raise pickle.UnpicklingError("BINSTRING count < 0")
    if length > 4096:
      self._skip_or_read_bytes(length)
      return
    data = self.read(length)
    if len(data) != length:
      raise EOFError("Truncated binary payload in pickle stream")
    self.append(self._decode_string(data))

  def _load_binbytes_fast(self, *unused_args: Any) -> None:
    (length,) = struct.unpack("<I", self.read(4))
    self._skip_or_read_bytes(length)

  def _load_binbytes8_fast(self, *unused_args: Any) -> None:
    (length,) = struct.unpack("<Q", self.read(8))
    self._skip_or_read_bytes(length)

  def _load_bytearray8_fast(self, *unused_args: Any) -> None:
    (length,) = struct.unpack("<Q", self.read(8))
    self._skip_or_read_bytes(length, as_bytearray=True)

  def _state_contains_fake_class(
      self,
      object_to_inspect: Any,
      visited_object_ids: Optional[Set[int]] = None,
  ) -> bool:
    """Recursively inspects an object to detect FakeClass instances or types."""
    return self._inspect_state_for_fake_class(
        object_to_inspect, visited_object_ids, only_suspicious=False
    )

  def _inspect_state_for_fake_class(
      self,
      object_to_inspect: Any,
      visited_object_ids: Optional[Set[int]] = None,
      only_suspicious: bool = False,
  ) -> bool:
    """Recursively inspects an object to detect FakeClass instances or types.

    Args:
      object_to_inspect: The candidate object, container, or state dictionary.
      visited_object_ids: Set of memory addresses visited to prevent infinite
        cycles in self-referential structures.
      only_suspicious: If True, only returns True for unsafe, suspicious,
        failed_reduce, or non-class function FakeClassType objects, allowing
        benign UNKNOWN class instances and PascalCase types.

    Returns:
      True if the object contains a disallowed FakeClass instance or type.
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
    if object_type.__dict__.get("_is_safe_symbol", False):
      return False
    if (
        object_type is picklemagic.FakeClassType
        and object_to_inspect.__dict__.get("_is_safe_symbol", False)
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
      if any(full_symbol_name.startswith(d) for d in deny_list):
        return True
      if any(full_symbol_name.startswith(a) for a in allow_list):
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
          self._inspect_state_for_fake_class(
              element, visited_object_ids, only_suspicious
          )
          for element in object_to_inspect
      )

    if isinstance(object_to_inspect, dict):
      return any(
          self._inspect_state_for_fake_class(
              dict_key, visited_object_ids, only_suspicious
          )
          or self._inspect_state_for_fake_class(
              dict_value, visited_object_ids, only_suspicious
          )
          for dict_key, dict_value in object_to_inspect.items()
      )

    if hasattr(object_to_inspect, "__dict__") and isinstance(
        getattr(object_to_inspect, "__dict__", None), dict
    ):
      instance_attributes = getattr(object_to_inspect, "__dict__")
      if any(
          self._inspect_state_for_fake_class(
              attribute_name, visited_object_ids, only_suspicious
          )
          or self._inspect_state_for_fake_class(
              attribute_value, visited_object_ids, only_suspicious
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
          if self._inspect_state_for_fake_class(
              slot_value, visited_object_ids, only_suspicious
          ):
            return True

    return False


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
      factory = picklemagic.FakeClassFactory([], _SaferFakeWarning)

      # Instead of using safe_loads, we do this to get the
      # has_blocked_unsafe_build_instr boolean properly.
      unpickler = SaferUnpickler(
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
    cls = utils.classify_symbol(line)
    match cls:
      case utils.Classification.SAFE:
        safe_results.add(line)
      case utils.Classification.UNSAFE:
        unsafe_results.add(line)
      case utils.Classification.SUSPICIOUS:
        suspicious_results.add(line)
      case _:
        unknown_results.add(line)

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

  # Only resolve qualified symbols (e.g. 'pkg.mod') to avoid plain words.
  candidate_results = safe_results.union(unsafe_results, suspicious_results)
  dotted_unknowns = {s for s in unknown_results if "." in s}
  all_candidates = candidate_results.union(dotted_unknowns)

  resolved_results = utils.resolve_library_modules_from_results(all_candidates)
  resolved_results.update(unknown_results - dotted_unknowns)

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
    classification = utils.classify_symbol(result)

    if classification == utils.Classification.SAFE:
      new_safe_results.add(result)
    elif classification == utils.Classification.UNSAFE:
      new_unsafe_results.add(result)
    elif classification == utils.Classification.SUSPICIOUS:
      new_suspicious_results.add(result)
    elif classification == utils.Classification.UNKNOWN:
      # Fallback: Check against original categories if
      # classify_symbol returns UNKNOWN.
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
    for opcode, operand in _custom_genops(pickle_bytes):  # pyrefly: ignore[bad-argument-type]
      if operand is None:
        continue
      stmt = str(operand)
      for pattern in unsafe_and_suspicious_strings:
        if re.search(pattern, stmt):
          return True
      if opcode is not None and opcode.name in constants.IMPORT_OPCODES:
        if utils.classify_symbol(stmt) != utils.Classification.SAFE:
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
      if instantiation.startswith("Safe module/class imported:"):
        continue
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


_STREAM_ARCHIVE_EXTRACTORS = {
    "bz2": utils.extract_bz2_contents,
    "lzma": utils.extract_lzma_contents,
    "gzip": utils.extract_gzip_contents,
}


def _get_archive_type(data: bytes | IO[bytes]) -> str | None:
  """Returns the archive format ('zip', 'bz2', 'lzma', 'gzip', 'tar')."""
  if isinstance(data, bytes):
    header = data[:262]
  else:
    if not hasattr(data, "tell") or not hasattr(data, "seek"):
      return None
    current_pos = data.tell()
    header = data.read(262)
    data.seek(current_pos)

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
  """Checks if the bytes or stream represent a supported archive format."""
  return _get_archive_type(data) is not None


def _iter_archive_entries(
    data: bytes,
    archive_type: str,
) -> Iterator[tuple[str | None, IO[bytes]]]:
  """Yields (entry_name, content_stream) for supported archive formats."""
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
  """Returns True if an archive entry should be scanned for pickle payloads."""
  if force_scan or _is_archive(content_stream):
    return True
  if (
      name is not None
      and check_magic_bytes
      and os.path.basename(name).isdigit()
  ):
    return utils.peek_bytes(content_stream, 2).startswith(b"\x80")
  return bool(
      utils.is_pickle_file(
          content_stream,
          check_magic_bytes=check_magic_bytes if name is not None else True,
      )
  )


def _merge_scan_results(target: ScanResults, source: ScanResults) -> None:
  """Merges a source ScanResults into a target ScanResults."""
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
) -> ScanResults:
  """Extracts and scans contents of an archive using a generic scan function."""
  combined = ScanResults()
  try:
    for name, content_stream in _iter_archive_entries(data, archive_type):
      if name is not None and utils.is_unsafe_archive_path(name):
        combined.unsafe_results.add(f"{archive_type}_slip_detected")
        return combined
      target = content_stream if name is not None else content_stream.read()
      if _is_scannable_archive_entry(name, target):
        content = target.read() if not isinstance(target, bytes) else target
        res = _scan_bytes_generic(content, scan_func, recursion_depth + 1)
        _merge_scan_results(combined, res)
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
) -> ScanResults:
  """Scans data recursively if it's an archive, else applies the scan_func."""
  if recursion_depth > 10:
    raise MaxRecursionDepthExceededError("Max recursion depth of 10 exceeded.")

  archive_type = _get_archive_type(data)
  if archive_type is not None:
    archive_bytes = data if isinstance(data, bytes) else data.read()
    return _scan_archive_generic(
        archive_bytes, archive_type, scan_func, recursion_depth
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
  """Internal genops scan for malicious content in pickle files."""
  resolved_pickle_length = (
      pickle_length if pickle_length is not None else len(pickle_bytes)  # pyrefly: ignore[bad-argument-type]
  )
  if pickle_file_path:
    genops_output = generate_ops_from_file(
        pickle_file_path,
        pickle_length=resolved_pickle_length,
        fail_fast=fail_fast,
    )
  elif resolved_pickle_length >= constants.MIN_SIZE_FOR_CHUNKING:
    if isinstance(pickle_bytes, bytes):
      data_buffer = pickle_bytes
    elif isinstance(pickle_bytes, io.BytesIO):
      cur_pos = pickle_bytes.tell()
      full_bytes = pickle_bytes.getvalue()
      data_buffer = full_bytes if cur_pos == 0 else full_bytes[cur_pos:]
    else:
      cur_pos = pickle_bytes.tell()
      try:
        data_buffer = pickle_bytes.read()
      finally:
        pickle_bytes.seek(cur_pos)
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


def score_results(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> Tuple[int, int, int, int]:
  """Count the results from the security scan.

  Args:
    safe_results: Set of safe strings.
    unsafe_results: Set of unsafe strings.
    suspicious_results: Set of suspicious strings.
    unknown_results: Set of unknown strings.

  Returns:
    A tuple of safe, unsafe, suspicious, and unknown counts.
  """
  return (
      len(safe_results),
      len(unsafe_results),
      len(suspicious_results),
      len(unknown_results),
  )


def is_unknown_verdict(
    safe_results: Set[str],
    unsafe_results: Set[str],
    suspicious_results: Set[str],
    unknown_results: Set[str],
) -> bool:
  """Returns True if unknown symbols warrant an UNKNOWN verdict.

  A file receives an UNKNOWN verdict when either:
  1. The number of unknown symbols strictly exceeds the sum of safe, unsafe,
     and suspicious symbols; or
  2. Any unknown symbol originates from a root package not in
     APPROVED_ROOT_PACKAGES (or is an unresolved/malformed import token).

  Args:
    safe_results: Set of safe strings.
    unsafe_results: Set of unsafe strings.
    suspicious_results: Set of suspicious strings.
    unknown_results: Set of unknown strings.
  """
  if not unknown_results:
    return False
  if len(unknown_results) > (
      len(safe_results) + len(unsafe_results) + len(suspicious_results)
  ):
    return True
  for symbol in unknown_results:
    if "." not in symbol or " " in symbol:
      return True
    root_pkg = symbol.split(".", 1)[0]
    if root_pkg not in constants.APPROVED_ROOT_PACKAGES:
      return True
  return False


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
  is_unknown = is_unknown_verdict(
      results.safe_results,
      results.unsafe_results,
      results.suspicious_results,
      results.unknown_results,
  )
  effective_unknown = number_of_unknown_results if is_unknown else 0
  scores = {
      "unsafe": number_of_unsafe_results,
      "suspicious": number_of_suspicious_results,
      "unknown": effective_unknown,
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
    archive_type = _get_archive_type(pickle_bytes)
    if archive_type is not None:
      archive_bytes = (
          pickle_bytes
          if isinstance(pickle_bytes, bytes)
          else pickle_bytes.read()
      )
      return _extract_and_scan_archive(
          archive_bytes,
          archive_type,
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

  if archive_type not in ("zip", "bz2", "lzma", "gzip", "tar"):
    logging.warning("Unsupported archive type: %s", archive_type)
    return {
        "unsafe": 0,
        "suspicious": 0,
        "unknown": constants.HIGH_SEVERITY_ZIPSLIP,
    }

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
      payload = content_stream.read() if name is not None else content_stream
      scores = security_scan(
          payload,
          force_scan=force_scan,
          recursion_depth=recursion_depth + 1,
          fail_fast=fail_fast,
          check_magic_bytes=check_magic_bytes if name is not None else True,
      )
      _merge_scores(all_scores, scores)
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

  # Find start of valid pickle payload if it has leading garbage or .npy header
  start_offset = 0
  if not is_pickle or utils.peek_bytes(stream, 6) == b"\x93NUMPY":
    try:
      current_pos = stream.tell()
      stream.seek(0)
      header_bytes = stream.read(1024)
      stream.seek(current_pos)
      if not _is_archive(header_bytes):
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
      if not _is_archive(header_bytes):
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
    if not _is_archive(data_bytes):
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

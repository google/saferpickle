"""Custom exceptions for safer_pickle."""


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


class MaxRecursionDepthExceededError(Exception):
  """Custom exception for exceeding maximum recursion depth in archives."""

  def __init__(self, m: str) -> None:
    self.message = m

  def __str__(self) -> str:
    return self.message

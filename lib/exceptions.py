"""Custom exceptions for safer_pickle."""


class IllegalArgumentCombinationError(Exception):
  """Custom exception for using allow_unsafe and strict_check together."""


class StrictCheckError(Exception):
  """Custom exception for strict check failures."""


class UnsafePickleDetectedError(Exception):
  """Custom exception for unsafe pickle files."""


class MaxRecursionDepthExceededError(Exception):
  """Custom exception for exceeding maximum recursion depth in archives."""


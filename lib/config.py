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

"""Configuration management for the safer_pickle library."""

import json
from typing import Optional, Set

from absl import logging


class _ConfigManager:
  """Manages the configuration for the safer_pickle library."""

  def __init__(self):
    self._config_path: Optional[str] = None
    self._cache: dict[str, Set[str]] = {}

  def set_path(self, path: Optional[str]) -> None:
    """Sets the path for the configuration file and resets the cache."""
    self._config_path = path
    self._cache.clear()

  def _get_list(self, key: str) -> Set[str]:
    """Loads and caches a configured symbol set (`allow_list` or `deny_list`).

    Opens and reads the JSON configuration file at `self._config_path`
    if not already cached, validates that the target `key` under
    `"safer_pickle"` is a list, and caches the resulting set.

    Args:
      key: Configuration key under `"safer_pickle"` (`'allow_list'` or
        `'deny_list'`).

    Returns:
      A set of symbol strings configured under `key`, or an empty set if no
      configuration path is set or the file cannot be read.

    Raises:
      json.JSONDecodeError: If the configuration file contains invalid JSON.
      TypeError: If the configured value for `key` is not a JSON array.
    """
    if key in self._cache:
      return self._cache[key]

    result: Set[str] = set()
    if self._config_path:
      try:
        with open(self._config_path, "r", encoding="utf-8") as f:
          config_data = json.load(f)
        items = config_data.get("safer_pickle", {}).get(key, [])
        if not isinstance(items, list):
          raise TypeError(f"The '{key}' in the config must be an array.")
        result = set(items)
      except FileNotFoundError:
        logging.warning(
            "SaferPickle config file not found at %s. ",
            self._config_path,
        )
      except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Could not parse SaferPickle config at {self._config_path}:"
            f" {e.msg}",
            e.doc,
            e.pos,
        ) from e
      except TypeError as e:
        raise TypeError(
            f"Invalid SaferPickle config at {self._config_path}: {e}"
        ) from e
      except IOError as e:
        logging.warning(
            "Could not read SaferPickle config at %s: %s. ",
            self._config_path,
            e,
        )

    self._cache[key] = result
    return result

  def get_allow_list(self) -> Set[str]:
    """Loads the allow-list from the configured JSON file and caches it."""
    return self._get_list("allow_list")

  def get_deny_list(self) -> Set[str]:
    """Loads the deny-list from the configured JSON file and caches it."""
    return self._get_list("deny_list")


# A single, global instance of the configuration manager.
_config_manager = _ConfigManager()


def set_config_path(path: Optional[str]) -> None:
  """Sets the path for the configuration file and resets the cache."""
  _config_manager.set_path(path)


def get_allow_list() -> Set[str]:
  """Loads the allow-list from the configured JSON file and caches it."""
  return _config_manager.get_allow_list()


def get_deny_list() -> Set[str]:
  """Loads the deny-list from the configured JSON file and caches it."""
  return _config_manager.get_deny_list()

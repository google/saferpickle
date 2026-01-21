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

import io


class _ConfigManager:
  """Manages the configuration for the safer_pickle library."""

  def __init__(self):
    self._config_path: Optional[str] = None
    self._allow_list_cache: Optional[Set[str]] = None
    self._deny_list_cache: Optional[Set[str]] = None

  def set_path(self, path: Optional[str]) -> None:
    """Sets the path for the configuration file and resets the cache."""
    self._config_path = path
    # Reset the cache to None to force a reload on the next scan.
    self._allow_list_cache = None
    self._deny_list_cache = None

  def get_allow_list(self) -> Set[str]:
    """Loads the allow-list from the configured JSON file and caches it."""
    # Return the cached result immediately if available.
    if self._allow_list_cache is not None:
      return self._allow_list_cache

    # If no config path is set, cache and return an empty set.
    if not self._config_path:
      self._allow_list_cache = set()
      return self._allow_list_cache

    try:
      with open(self._config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)
        # Safely access the nested allow_list.
        allow_list = config_data.get("safer_pickle", {}).get("allow_list", [])
        if not isinstance(allow_list, list):
          raise TypeError("The 'allow_list' in the config must be an array.")
        self._allow_list_cache = set(allow_list)
    except FileNotFoundError:
      logging.warning(
          "SaferPickle config file not found at %s. ",
          self._config_path,
      )
      self._allow_list_cache = set()
    except json.JSONDecodeError as e:
      raise json.JSONDecodeError(
          f"Could not parse SaferPickle config at {self._config_path}: {e.msg}",
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
      self._allow_list_cache = set()

    return self._allow_list_cache

  def get_deny_list(self) -> Set[str]:
    """Loads the deny-list from the configured JSON file and caches it."""
    # Return the cached result immediately if available.
    if self._deny_list_cache is not None:
      return self._deny_list_cache

    # If no config path is set, cache and return an empty set.
    if not self._config_path:
      self._deny_list_cache = set()
      return self._deny_list_cache

    try:
      with open(self._config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)
        # Safely access the nested deny_list.
        deny_list = config_data.get("safer_pickle", {}).get("deny_list", [])
        if not isinstance(deny_list, list):
          raise TypeError("The 'deny_list' in the config must be an array.")
        self._deny_list_cache = set(deny_list)
    except FileNotFoundError:
      logging.warning(
          "SaferPickle config file not found at %s. ",
          self._config_path,
      )
      self._deny_list_cache = set()
    except json.JSONDecodeError as e:
      raise json.JSONDecodeError(
          f"Could not parse SaferPickle config at {self._config_path}: {e.msg}",
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
      self._deny_list_cache = set()
    return self._deny_list_cache


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

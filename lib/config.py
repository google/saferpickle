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
from typing import Any

from absl import logging

_config_path: str | None = None
_parsed_section: dict[str, Any] | None = None
_cache: dict[str, set[str]] = {}


def set_config_path(path: str | None) -> None:
  """Sets the path for the configuration file and resets the cache."""
  global _config_path
  global _parsed_section
  _config_path = path
  _parsed_section = None
  _cache.clear()


def get_config_path() -> str | None:
  """Returns the currently configured JSON file path, if any."""
  return _config_path


def _get_list(key: str) -> set[str]:
  """Loads and caches a configured symbol set (`allow_list` or `deny_list`).

  Args:
    key: Configuration key under `"safer_pickle"` (`'allow_list'` or
      `'deny_list'`).

  Returns:
    A set of symbol strings configured under `key`, or an empty set if no
    configuration path is set or the file cannot be read.

  Raises:
    json.JSONDecodeError: If the configuration file contains invalid JSON.
    TypeError: If the root, section, or configured `key` has an invalid type.
  """
  global _parsed_section
  if key in _cache:
    return set(_cache[key])

  result: set[str] = set()
  if _config_path:
    if _parsed_section is None:
      try:
        with open(_config_path, "r", encoding="utf-8") as f:
          config_data = json.load(f)
      except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Could not parse SaferPickle config at {_config_path}: {e.msg}",
            e.doc,
            e.pos,
        ) from e
      except (FileNotFoundError, IOError) as e:
        logging.warning(
            "Could not read SaferPickle config at %s: %s.", _config_path, e
        )
        _cache[key] = result
        return set()

      if not isinstance(config_data, dict):
        raise TypeError(
            f"Invalid SaferPickle config at {_config_path}: "
            "The config root must be a JSON object."
        )

      section = config_data.get("safer_pickle", {})
      if not isinstance(section, dict):
        raise TypeError(
            f"Invalid SaferPickle config at {_config_path}: "
            "The 'safer_pickle' section must be a JSON object."
        )
      _parsed_section = section

    items = _parsed_section.get(key, [])
    if not isinstance(items, list):
      raise TypeError(
          f"Invalid SaferPickle config at {_config_path}: "
          f"The '{key}' in the config must be an array."
      )
    if not all(isinstance(item, str) for item in items):
      raise TypeError(
          f"Invalid SaferPickle config at {_config_path}: "
          f"All entries in '{key}' must be strings."
      )
    result = set(items)

  _cache[key] = result
  return set(result)


def get_allow_list() -> set[str]:
  """Loads the allow-list from the configured JSON file and caches it."""
  return _get_list("allow_list")


def get_deny_list() -> set[str]:
  """Loads the deny-list from the configured JSON file and caches it."""
  return _get_list("deny_list")

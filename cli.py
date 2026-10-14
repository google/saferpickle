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

"""A CLI script to scan a directory for potentially malicious pickle files using safer pickle."""

import json
import os
from typing import Any, Dict, List, Sequence
from absl import app
from absl import flags
import saferpickle as safer_pickle


def security_scan_with_justifications(
    pickle_bytes: bytes,
) -> Dict[str, Any]:
  """Analyzes pickle byte content and returns a detailed analysis result.

  Args:
    pickle_bytes: The bytes of the pickle file to analyze.

  Returns:
    A dictionary containing the analysis result. It includes:
      - "classification": A string indicating if the pickle is malicious,
      suspicious or benign.
      - "justification": (Optional) A string providing a list of appropriate
      keywords for the classification.
  """
  results = safer_pickle.security_scan_results(pickle_bytes)
  if results is None:
    return {
        "classification": "Not supported",
        "justification": "Not a pickle file",
    }

  if results.unsafe_results:
    all_results = [f"malicious results: {', '.join(results.unsafe_results)}"]
    if results.suspicious_results:
      all_results.append(
          f"suspicious results: {', '.join(results.suspicious_results)}"
      )
    return {
        "classification": "unsafe",
        "justification": f"Found {' and '.join(all_results)}",
    }
  if results.suspicious_results:
    return {
        "classification": "suspicious",
        "justification": (
            f"Found suspicious results: {', '.join(results.suspicious_results)}"
        ),
    }
  if results.unknown_results:
    return {
        "classification": "unknown",
        "justification": (
            f"Found unknown results: {', '.join(results.unknown_results)}"
        ),
    }

  justification = ""
  if results.safe_results:
    justification = f"Found safe results: {', '.join(results.safe_results)}"
  return {
      "classification": "benign",
      "justification": justification,
  }


def scan_directory(directory_path: str) -> List[Dict[str, Any]]:
  """Recursively scans all files in a given directory, analyzes them for potential malicious pickles, and returns a list of results in JSON format.

  Args:
      directory_path: The path to the directory to scan.

  Returns:
      A list of dictionaries, where each dictionary represents the analysis
      result of a file. Each dictionary includes:
        - "status": "success" if the file was analyzed successfully, "error"
        otherwise.
        - "filename": The path to the analyzed file.
        - "classification": (Optional) "benign", "suspicious" or "unsafe"
        indicating the result of the analysis.
        - "justification": (Optional) A string providing a reason for the
        "suspicious" or "unsafe" classification.
        - "error_msg": (Optional) A string describing the error if status is
        "error".
  """
  results = []
  try:
    is_valid_dir = os.path.isdir(directory_path)
  except (IOError, OSError):
    is_valid_dir = False

  if not is_valid_dir:
    results.append({
        "status": "error",
        "filename": directory_path,
        "error_msg": "Input path is not a valid directory.",
    })
    return results

  for root, _, files in os.walk(directory_path):
    for filename in files:
      file_path = os.path.join(root, filename)
      try:
        with open(file_path, "rb") as f:
          content = f.read()

        if not content:
          analysis_result = {"classification": "Not supported"}
        else:
          analysis_result = security_scan_with_justifications(content)

        file_result = {
            "status": "success",
            "filename": file_path,
            **analysis_result,
        }

      except (IOError, OSError, ValueError) as e:
        file_result = {
            "status": "error",
            "filename": file_path,
            "error_msg": f"Exception during parsing: {type(e).__name__} - {e}",
        }
      results.append(file_result)
  return results


_DIRECTORY = flags.DEFINE_string(
    "directory",
    ".",
    "The path to the directory you want to scan.",
    required=False,
)


def main(argv: Sequence[str]) -> None:
  """Defines the command-line interface and executes the scan."""
  if len(argv) > 1:
    raise app.UsageError("Too many command-line arguments.")

  scan_results = scan_directory(_DIRECTORY.value)
  print(json.dumps(scan_results, indent=2))


if __name__ == "__main__":
  app.run(main)

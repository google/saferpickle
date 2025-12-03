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
import saferpickle
from lib import utils


def security_scan_with_justifications(
    pickle_bytes: bytes, file_path: str | None = None
) -> Dict[str, Any]:
  """Analyzes pickle byte content and returns a detailed analysis result.

  Args:
    pickle_bytes: The bytes of the pickle file to analyze.
    file_path: The path to the pickle file, for streaming scan.

  Returns:
    A dictionary containing the analysis result. It includes:
      - "classification": A string indicating if the pickle is malicious,
      suspicious or benign.
      - "justification": (Optional) A string providing a list of appropriate
      keywords for the classification.
  """
  classification = "Not supported"
  justification = "Not a pickle file"
  safe_results, unsafe_results, suspicious_results, unknown_results = (
      set(),
      set(),
      set(),
      set(),
  )

  if utils.is_zip_bytes(pickle_bytes):
    unzipped_files = utils.extract_zip_contents(pickle_bytes)
    for unzipped_file in unzipped_files:
      _, file_bytes = unzipped_file

      if not utils.is_pickle_file(file_bytes) or not file_bytes:
        continue

      pickle_bytes = file_bytes
      break

  if not utils.is_pickle_file(pickle_bytes):
    return {"classification": classification, "justification": justification}

  # Call the individual scan functions from SaferPickle to sets of results.
  # Picklemagic Scan
  picklemagic_results = safer_pickle.picklemagic_scan(pickle_bytes)

  safe_results.update(picklemagic_results.safe_results)
  unsafe_results.update(picklemagic_results.unsafe_results)
  suspicious_results.update(picklemagic_results.suspicious_results)
  unknown_results.update(picklemagic_results.unknown_results)

  # Genops Scan
  genops_results = safer_pickle.genops_scan(
      pickle_bytes, pickle_file_path=file_path
  )
  safe_results.update(genops_results.safe_results)
  unsafe_results.update(genops_results.unsafe_results)
  suspicious_results.update(genops_results.suspicious_results)
  unknown_results.update(genops_results.unknown_results)

  final_safe_results = utils.resolve_library_modules_from_results(safe_results)
  final_unsafe_results = utils.resolve_library_modules_from_results(
      unsafe_results
  )
  final_suspicious_results = utils.resolve_library_modules_from_results(
      suspicious_results
  )
  final_unknown_results = utils.resolve_library_modules_from_results(
      unknown_results
  )

  # Score the results
  (
      num_safe,
      num_unsafe,
      num_suspicious,
      _,  # The unknown_score is not used for classification, only reporting
  ) = safer_pickle.score_results(
      final_safe_results,
      final_unsafe_results,
      final_suspicious_results,
      final_unknown_results,
  )

  # Check for safety and return the results with justifications.
  if safer_pickle.is_unsafe(num_safe, num_unsafe, num_suspicious):
    if num_unsafe > num_suspicious:
      classification = "unsafe"
      all_results = []
      if unsafe_results:
        all_results.append(
            f"malicious results: {', '.join(map(str, final_unsafe_results))}"
        )
      if suspicious_results:
        all_results.append(
            "suspicious results:"
            f" {', '.join(map(str, final_suspicious_results))}"
        )
      justification = f"Found {' and '.join(all_results)}"
    else:
      classification = "suspicious"
      justification = (
          "Found suspicious results:"
          f" {', '.join(map(str, final_suspicious_results))}"
      )
  else:
    justification_parts = []
    if safe_results:
      justification_parts.append(
          f"Found safe results: {', '.join(map(str, final_safe_results))}"
      )
    if unknown_results:
      justification_parts.append(
          f"Found unknown results: {', '.join(map(str, final_unknown_results))}"
      )
    justification = " and ".join(justification_parts)
    classification = "benign"

  return {"classification": classification, "justification": justification}


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
  if not os.path.isdir(directory_path):
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
          analysis_result = security_scan_with_justifications(
              content, file_path=file_path
          )

        file_result = {
            "status": "success",
            "filename": file_path,
            **analysis_result,
        }

      except (IOError, ValueError) as e:
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

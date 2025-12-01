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

"""Setup script for the saferpickle package."""

import setuptools

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
    name="saferpickle",
    version="0.1.0",
    author="The SaferPickle Authors",
    author_email="saferpickle-dev@google.com",
    description="A safer alternative to Python's pickle module.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/google/saferpickle",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "absl-py",
        "immutabledict",
    ],
)

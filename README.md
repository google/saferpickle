# SaferPickle

**SaferPickle** is a Python library that provides a safer alternative to
Python's `pickle` module. It is a heuristic-based system that uses a two-tiered
approach to scan pickle files for malicious content, minimizing latency in
trivially identifiable cases and providing high-confidence results in more
complex situations.

## How it Works

SaferPickle employs a two-tiered scanning approach:

1.  **Picklemagic**: A fast approach that detects suspicious module
    instantiations by safely loading the file using fake objects.
2.  **Genops**: This approach string-matches the opcodes from the pickle file
    against predefined lists of unsafe, suspicious, and safe strings to assess
    the potential for malicious intent.

## Installation

You may install saferpickle by cloning the repository and running pip:

```bash
pip install -e .
```

Or alternatively install the requirements, then you may import the module:

```bash
pip install -r requirements.txt
```

Alternatively, please use `requirements.txt` to install dependencies.

## Usage

Here are the different ways you can use SaferPickle:

### 1. Security Scan a Pickle File

You can use the `security_scan` function to scan a pickle file and get a report
of the findings.

```py
import safer_pickle
import pickle

class MyObject:
    def __init__(self, value):
        self.value = value

my_object = MyObject("some data")
pickle_bytes = pickle.dumps(my_object)

scan_results = safer_pickle.security_scan(pickle_bytes)

if scan_results["unsafe"] > 0:
    print("Unsafe content found!")
elif scan_results["suspicious"] > 0:
    print("Suspicious content found!")
else:
    print("Pickle file seems safe.")
```

The `security_scan` function returns a dictionary containing scores for
`unsafe`, `suspicious`, and `unknown` finds.

### 2. Auto-hook Pickle Unpickling

You can use `hook_pickle()` to automatically and transparently add SaferPickle's
security scan to all the standard pickle-like libraries (`pickle`, `_pickle`,
`cloudpickle`, `joblib`, `dill`). This is the easiest way to protect your
application from unsafe pickles.

```py
import safer_pickle
import pickle

safer_pickle.hook_pickle()

# Now, any call to pickle.load() or pickle.loads() will be protected.
# For example, if you try to load a malicious pickle file, it will raise
# a safer_pickle.UnsafePickleDetectedError.

try:
    # malicious_pickle_bytes is a pickle file that contains malicious code
    pickle.loads(malicious_pickle_bytes)
except safer_pickle.UnsafePickleDetectedError as e:
    print(f"Blocked malicious pickle file: {e}")
```

### 3. Use `safer_pickle.load()` and `safer_pickle.loads()`

You can also use `safer_pickle.load()` and `safer_pickle.loads()` as direct
replacements for `pickle.load()` and `pickle.loads()`. These functions provide
more control over the security scan.

```py
import safer_pickle

# This will raise a safer_pickle.UnsafePickleDetectedError if the pickle is unsafe
try:
    obj = safer_pickle.loads(malicious_pickle_bytes)
except safer_pickle.UnsafePickleDetectedError as e:
    print(f"Blocked malicious pickle file: {e}")

# You can also use a strict check, which is more aggressive in detecting
# potentially malicious content.
try:
    obj = safer_pickle.loads(malicious_pickle_bytes, strict_check=True)
except safer_pickle.StrictCheckError as e:
    print(f"Blocked by strict check: {e}")

# If you trust the source of the pickle file, you can bypass the security scan.

obj = safer_pickle.loads(pickle_bytes, allow_unsafe=True)
```

### 4. Command-Line Interface (CLI)

SaferPickle also comes with a command-line tool for scanning pickle files.

```bash
safer_pickle_cli --directory=<dir_path_to_scan>
```

This will recursively scan the specified directory and generate a JSON report
with the classification for each file.

## Contributing

We welcome contributions! Please see our contributing guidelines in
CONTRIBUTING.md for more information.

## License

SaferPickle is licensed under the Apache 2.0 License. See the LICENSE file for
more details.

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

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

"""Constants used by the safer_pickle library."""

import os
import pickletools
import string
from typing import FrozenSet
import immutabledict

# List of globals below can be updated if additional modules are identified
# Note: The strings in this list should be in the format of
# "library.member" or "library" or "member"
# Eg. "os.system", "loads", "system"
SUSPICIOUS_STRINGS: FrozenSet[str] = frozenset([
    "__builtin__.",
    "__builtins__",
    "__call__",
    "__class__",
    "__code__",
    "__getattribute__",
    "__getitem__",
    "__globals__",
    "__import__",
    "__setstate__",
    "__sub__",
    "__subclasses__",
    "attr",
    "builtin",
    "builtins",
    "cgitb.lookup",
    "copy_reg",
    "doctest.debug_script",
    "fnmatch",
    "getattr",
    "glob",
    "hasattr",
    "itertools",
    "lib2to3.fixer_util.attr_chain",
    "linecache",
    "numpy.f2py.capi_maps.getinit",
    "operator",
    "pathlib",
    "builtins.print",
    "setattr",
    "shlex",
    "str.join",
    "sympy.utilities.lambdify.lambdify",
    "tempfile",
    "test.support.get_attribute",
    "types.FunctionType",
    "unittest.mock._dot_lookup",
    "unittest.mock._importer",
    "xml.etree",
    "xmlrpc.server.resolve_dotted_attribute",
])

UNSAFE_STRINGS: FrozenSet[str] = frozenset([
    "CreateThread",
    "Crypto",
    "RtlMoveMemory",
    "VirtualAlloc",
    "WaitForSingleObject",
    "_compat_pickle",
    "_pickle",
    "_pickle.load",
    "_pickle.loads",
    "__builtin__.apply",
    "__builtin__.compile",
    "__builtin__.eval",
    "__builtin__.exec",
    "__builtin__.execfile",
    "__builtin__.open",
    "_codecs.decode",
    "aiohttp",
    "asyncio",
    "base64",
    "bdb",
    "breakpoint",
    "builtins.apply",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "builtins.execfile",
    "builtins.open",
    "cProfile",
    "cloudpickle",
    "cloudpickle.load",
    "cloudpickle.loads",
    "code.InteractiveConsole",
    "code.InteractiveInterpreter",
    "code.interact",
    "codecs.decode",
    "codeop.compile_command",
    "commands",
    "config.set_config_path",
    "copyreg",
    "corrupy",
    "cryptography",
    "ctorch",
    "ctypes",
    "dill",
    "fileinput",
    "get_type_hints",
    "gzip",
    "hashlib",
    "httplib",
    "importlib",
    "io.open",
    "itemgetter",
    "joblib",
    "load_module",
    "lzma.open",
    "malicious",
    "marshal",
    "msvcrt",
    "nt.system",
    "numpy.DataSource",
    "numpy.f2py.capi_maps.getinit",
    "numpy.lib._datasource",
    "numpy.lib.npyio.loadtxt",
    "numpy.load",
    "numpy.memmap",
    "operator.attrgetter",
    "operator.itemgetter",
    "operator.methodcaller",
    "os.exec",
    "os.kill",
    "os.open",
    "os.popen",
    "os.read",
    "os.spawn",
    "os.system",
    "os.write",
    "pandas.ExcelFile",
    "pandas.ExcelWriter",
    "pandas.HDFStore",
    "pandas.io.clipboard",
    "pandas.read_pickle",
    "pexpect",
    "pickle.load",
    "pickle.loads",
    "picklemagic",
    "posix.exec",
    "posix.kill",
    "posix.open",
    "posix.popen",
    "posix.read",
    "posix.spawn",
    "posix.system",
    "posix.write",
    "profile.Profile",
    "profile.run",
    "psutil",
    "pty.spawn",
    "pty.fork",
    "pycrypto",
    "pydoc.locate",
    "pydoc.pipepager",
    "pydoc.replace",
    "python",
    "pywin32_system32",
    "pyyaml",
    "raise",
    "requests",
    "runpy",
    "safer_pickle",
    "saferpickle",
    "scipy.weave",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.move",
    "socket.create_connection",
    "socket.socket",
    "ssl",
    "stdin",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
    "sys.exit",
    "sys.modules",
    "timeit",
    "torch.load",
    "torch.unsupported_tensor_ops",
    "trace",
    "txwinrm",
    "unittest.mock._dot_lookup",
    "unittest.mock._importer",
    "urllib.request",
    "webbrowser",
    "winapi",
    "winreg",
    "zlib",
])

# Dangerous root modules whose qualified member accesses (e.g.
# subprocess.getoutput, os.execv, posix.fork, marshal.loads) are unsafe even
# when the bare module name is excluded from UNSAFE_STRINGS to avoid false
# positives on plain English vocabulary words.
UNSAFE_PREFIX_MODULES: FrozenSet[str] = frozenset([
    "__main__",
    "_codecs",
    "_compat_pickle",
    "_ctypes",
    "_osx_support",
    "_pickle",
    "_pickle_copy",
    "_posixsubprocess",
    "_thread",
    "aiohttp",
    "antigravity",
    "asyncio",
    "atexit",
    "base64",
    "bdb",
    "bz2",
    "cProfile",
    "cgitb",
    "cloudpickle_copy",
    "code",
    "codecs",
    "codeop",
    "commands",
    "compileall",
    "concurrent",
    "ctypes",
    "dbm",
    "dill",
    "dill_copy",
    "distutils",
    "doctest",
    "ensurepip",
    "faulthandler",
    "fcntl",
    "fileinput",
    "ftplib",
    "gzip",
    "http",
    "httplib",
    "idlelib",
    "imaplib",
    "imp",
    "importlib",
    "io",
    "joblib",
    "joblib_copy",
    "lib2to3",
    "logging",
    "lzma",
    "marshal",
    "mmap",
    "msvcrt",
    "multiprocessing",
    "nt",
    "os",
    "pdb",
    "pexpect",
    "pickle",
    "pickle_copy",
    "picklemagic",
    "poplib",
    "posix",
    "profile",
    "psutil",
    "pty",
    "pydoc",
    "pyyaml",
    "requests",
    "resource",
    "runpy",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtplib",
    "socket",
    "sqlite3",
    "ssl",
    "subprocess",
    "sys",
    "sysconfig",
    "tarfile",
    "telnetlib",
    "tempfile",
    "test",
    "threading",
    "timeit",
    "tkinter",
    "torch_copy",
    "trace",
    "turtle",
    "unittest",
    "urllib",
    "urllib2",
    "urllib3",
    "venv",
    "weakref",
    "webbrowser",
    "winapi",
    "winreg",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
])


SAFE_STRINGS: FrozenSet[str] = frozenset([
    "PIL",
    "__builtin__.print",
    "__builtin__.set",
    "cloudpickle.cloudpickle",
    "collections",
    "complex",
    "ctorch.nn",
    "cv2",
    "dtypes",
    "epoch_loop",
    "functools.partial",
    "gensim",
    "google3",
    "jax",
    "keras",
    "layer",
    "lightning",
    "nltk",
    "nn",
    "numpy",
    "opacus",
    "pandas",
    "pillow",
    "pydoc",
    "python.v2.dataclasses",
    "reconstruct",
    "scipy",
    "set",
    "shutil.disk_usage",
    "sklearn",
    "spacy",
    "str",
    "tensorflow",
    "theano",
    "torch",
    "torch_frame",
    "torchmetrics",
    "torchvision",
    "training_step",
    "transformers",
    "usage",
])

# Error template for the hook
ERROR_STRING = string.Template(
    "ERROR: Loading this pickle file may result in code execution."
    " Only proceed if you trust the file.\nClassification: $classification\nIf"
    " this file was flagged inappropriately, please contact"
    " ise-static-analysis@ with details."
)

# Combination of all the globals for exclusion to identify unknown method calls
ALL_STRINGS = UNSAFE_STRINGS.union(SUSPICIOUS_STRINGS).union(SAFE_STRINGS)

NON_PICKLE_MAGIC_BYTES = (
    b"\x7fELF",  # ELF executable
    b"MZ",  # PE executable
    b"\x93NUMPY",  # numpy npy
    b"\x89PNG\r\n\x1a\n",  # png
    b"\xff\xd8\xff",  # jpeg
    b"GIF8",  # gif
    b"II*\x00",  # tiff little-endian
    b"MM\x00*",  # tiff big-endian
    b"%PDF-",  # pdf
    b"\x00asm",  # wasm
    b"\xca\xfe\xba\xbe",  # Java class
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit big-endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big-endian
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"dex\n",  # dex
    b"SQLite format 3",  # sqlite
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE Compound File (DOC, XLS, PPT)
    b"BM",  # BMP Image
    b"FWS",  # Uncompressed Flash SWF
    b"CWS",  # Compressed Flash SWF
    b"MSCF",  # Microsoft Cabinet File
    b"dey\n",  # Dalvik ODEX
    b"\x1bLua",  # Lua bytecode
    b"\x30\x82",  # DER certificate
    b"L\x00\x00\x00",  # Windows Shortcut (LNK)
)

CODE_KEYWORDS = (
    b"import ",  # Javascript/Python
    b"export ",  # Javascript
    b"package ",  # Go
    b"func ",  # Go
    b"type ",  # Go
    b"fn ",  # Rust
    b"mod ",  # Rust
    b"use ",  # Rust
    b"pub ",  # Rust
    b"struct ",  # Rust
    b"enum ",  # Rust
    b"impl ",  # Rust
    b"trait ",  # Rust
)

TEXT_BASED_PREFIXES = (
    b"#!",  # Shebang script
    b"<?xml",  # XML
    b"<html",  # HTML
    b"<!DOCTYPE",  # HTML5 doctype
    b"---",  # YAML document separator
    b"%YAML",  # YAML directive
    b"function",  # Javascript
    b"var ",  # Javascript
    b"const ",  # Javascript
    b"let ",  # Javascript
    b"//",  # Comment for scripts
    b"/*",  # Comment for scripts
    b"def ",  # Python
    b"class ",  # Python
    b"{",  # JSON object
    b"[",  # JSON array
    b"{\\rtf",  # Rich Text Format
    b"#",  # Hash comment (Python, Shell, Ruby, etc.)
    b"<!--",  # HTML/XML comment
    b"Windows Registry Editor",  # Windows Registry file
)


# These are substrings of opcodes that declare strings often before
# REDUCE, BUILD, and MEMOIZE opcodes
OPCODE_SUBSTRS_THAT_DECLARE_STRINGS: FrozenSet[str] = frozenset([
    "GLOBAL",
    "INST",
    "UNICODE",
    "STRING",
])

OPCODES_INFO = immutabledict.immutabledict(
    {opcode.code: opcode for opcode in pickletools.opcodes}
)
# Integer-based lookup for opcodes for faster lookups
OPCODES_INFO_INT = immutabledict.immutabledict(
    {ord(opcode.code): opcode for opcode in pickletools.opcodes}
)

MAX_BYTES_TO_CHECK = 128
MIN_SIZE_FOR_CHUNKING = 30 * 1024 * 1024  # 30 MB
CHUNK_OVERLAP = 512  # Bytes to overlap between chunks

# Tiers for dynamically scaling the number of workers based on file size.
# Each tuple is (file_size_threshold, num_workers). The threshold is the upper
# bound for a given number of workers.
WORKER_TIERS = [
    (MIN_SIZE_FOR_CHUNKING, 1),  # up to 30MB -> 1 worker
    (128 * 1024 * 1024, 4),  # up to 128MB -> 4 workers
    (512 * 1024 * 1024, 8),  # up to 512MB -> 8 workers
    (1 * 1024 * 1024 * 1024, 16),  # up to 1GB -> 16 workers
    (4 * 1024 * 1024 * 1024, 32),  # up to 4GB -> 32 workers
]

# Cap the number of workers at half the available CPU cores to avoid excessive
# overhead and resource contention.
MAX_NUM_CHUNKS = (os.cpu_count() or 1) // 2

# High score to indicate definite unsafety due to a detected zip slip.
HIGH_SEVERITY_ZIPSLIP = 1337


OPCODES_4BYTE_LEN = (b"B",)
OPCODES_8BYTE_LEN = (b"\x8e", b"\x96")
OPCODES_1BYTE_LEN = (b"C",)
LENGTH_PREFIXED_OPCODES = (
    OPCODES_4BYTE_LEN + OPCODES_8BYTE_LEN + OPCODES_1BYTE_LEN
)

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
    "copy_reg",
    "getattr",
    "hasattr",
    "itertools",
    "operator",
    "print",
    "setattr",
    "str.join",
    "xmlrpc.server.resolve_dotted_attribute",
    "unittest.mock._dot_lookup",
    "lib2to3.fixer_util.attr_chain",
    "test.support.get_attribute",
    "numpy.f2py.capi_maps.getinit",
    "cgitb.lookup",
    "doctest.debug_script",
    "unittest.mock._importer",
    "sympy.utilities.lambdify.lambdify",
    "xml.etree",
])

UNSAFE_STRINGS: FrozenSet[str] = frozenset([
    "CreateThread",
    "Crypto",
    "RtlMoveMemory",
    "VirtualAlloc",
    "WaitForSingleObject",
    "_codecs.decode",
    "_compat_pickle",
    "_pickle",
    "aiohttp",
    "apply",
    "asyncio",
    "base64",
    "bdb",
    "breakpoint",
    "cProfile",
    "cloudpickle.load",
    "cloudpickle.loads",
    "code.InteractiveInterpreter",
    "codecs.decode",
    "codeop.compile_command",
    "commands",
    "compile",
    "config.set_config_path",
    "copyreg",
    "corrupy",
    "cryptography",
    "ctorch",
    "ctypes",
    "decode",
    "dill",
    "eval",
    "exec",
    "execfile",
    "get_type_hints",
    "gzip",
    "hashlib",
    "httplib",
    "importlib",
    "itemgetter",
    "joblib",
    "load",
    "load_module",
    "loads",
    "lzma.open",
    "marshal",
    "msvcrt",
    "open",
    "os",
    "pexpect",
    "pickle",
    "picklemagic",
    "posix",
    "profile",
    "psutil",
    "pty",
    "numpy.lib.npyio.loadtxt",
    "pycrypto",
    "pydoc.pipepager",
    "pandas.read_pickle",
    "python",
    "pywin32_system32",
    "pyyaml",
    "raise",
    "read",
    "requests",
    "runpy",
    "safer_pickle_hook",
    "socket",
    "ssl",
    "stdin",
    "subprocess",
    "sys",
    "system",
    "timeit",
    "torch.load",
    "torch.unsupported_tensor_ops",
    "trace",
    "txwinrm",
    "urllib",
    "webbrowser",
    "winapi",
    "winreg",
    "write",
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
    " your system administrator with details."
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
CHUNK_OVERLAP = 16  # Bytes to overlap between chunks

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

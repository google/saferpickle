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

import itertools
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
    "CodeType",
    "_builtin_type",
    "_make_function",
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
    "builtins",
    "cgitb.lookup",
    "cloudpickle",
    "cloudpickle.cloudpickle",
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
    "__builtin__.print",
    "setattr",
    "shlex",
    "str.join",
    "sympy.utilities.lambdify.lambdify",
    "tempfile",
    "test.support.get_attribute",
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
    "base64.b64decode",
    "base64.decode",
    "bdb",
    "breakpoint",
    "builtins.apply",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "builtins.execfile",
    "builtins.open",
    "cProfile",
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
    "eval",
    "exec",
    "fileinput",
    "get_type_hints",
    "gzip.decompress",
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
    "numpy.lib.npyio.loadtxt",
    "numpy.load",
    "os.exec",
    "os.kill",
    "os.open",
    "os.popen",
    "os.read",
    "os.spawn",
    "os.system",
    "os.write",
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
    "pywin32_system32",
    "pyyaml",
    "requests",
    "runpy",
    "safer_pickle",
    "saferpickle",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.move",
    "socket.create_connection",
    "socket.socket",
    "ssl",
    "sys.stdin",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
    "sys.exit",
    "sys.modules",
    "timeit.timeit",
    "timeit.repeat",
    "timeit.Timer",
    "torch.jit.load",
    "torch.load",
    "torch.unsupported_tensor_ops",
    "types.BuiltinFunctionType",
    "types.CodeType",
    "types.FunctionType",
    "txwinrm",
    "urllib.request",
    "urllib2",
    "urllib3",
    "webbrowser",
    "winapi",
    "winreg",
    "zlib",
])


SAFE_STRINGS: FrozenSet[str] = frozenset([
    "PIL",
    "copyreg._reconstructor",
    "copy_reg._reconstructor",
    "__builtin__.set",
    "_codecs.encode",
    "codecs.encode",
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

PAYLOAD_PREFIX_SIZES = immutabledict.immutabledict({
    "SHORT_BINBYTES": 1,
    "SHORT_BINUNICODE": 1,
    "BINBYTES": 4,
    "BINUNICODE": 4,
    "BINBYTES8": 8,
    "BINUNICODE8": 8,
    "BYTEARRAY8": 8,
})

OPCODES_STRIDE_1: FrozenSet[int] = frozenset({
    0x28,
    0x29,
    0x2E,
    0x30,
    0x31,
    0x32,
    0x4E,
    0x7D,
    0x5D,
    0x61,
    0x65,
    0x73,
    0x75,
    0x74,
    0x6C,
    0x64,
    0x85,
    0x86,
    0x87,
    0x88,
    0x89,
    0x8F,
    0x90,
    0x91,
    0x94,
    0x97,
    0x98,
})
OPCODES_STRIDE_2: FrozenSet[int] = frozenset({0x80, 0x4B, 0x68, 0x71})
OPCODES_STRIDE_3: FrozenSet[int] = frozenset({0x4D})
OPCODES_STRIDE_5: FrozenSet[int] = frozenset({0x4A, 0x6A, 0x72})
OPCODES_STRIDE_9: FrozenSet[int] = frozenset({0x47, 0x95})


def _build_opcode_strides() -> tuple[int, ...]:
  """Constructs a 256-element byte stride lookup table for fixed-size opcodes."""
  strides = [-1] * 256
  for opcode_byte in OPCODES_STRIDE_1:
    strides[opcode_byte] = 1
  for opcode_byte in OPCODES_STRIDE_2:
    strides[opcode_byte] = 2
  for opcode_byte in OPCODES_STRIDE_3:
    strides[opcode_byte] = 3
  for opcode_byte in OPCODES_STRIDE_5:
    strides[opcode_byte] = 5
  for opcode_byte in OPCODES_STRIDE_9:
    strides[opcode_byte] = 9
  return tuple(strides)


OPCODE_STRIDES: tuple[int, ...] = _build_opcode_strides()

APPROVED_ROOT_PACKAGES: FrozenSet[str] = frozenset({
    "torch",
    "torchaudio",
    "torchvision",
    "flax",
    "jax",
    "optax",
    "tensorflow",
    "keras",
    "tensorboard",
    "numpy",
    "scipy",
    "pandas",
    "sklearn",
    "scikit_learn",
    "sympy",
    "shapely",
    "nltk",
    "geopandas",
    "pytorch3d",
    "jaxlib",
    "ml_dtypes",
    "collections",
    "dataclasses",
    "typing",
    "enum",
    "types",
    "numbers",
    "decimal",
    "datetime",
    "uuid",
    "math",
    "functools",
})

SAFE_METADATA_ATTRIBUTES: FrozenSet[str] = frozenset({
    "__name__",
    "__doc__",
    "__file__",
    "__package__",
    "__qualname__",
    "__module__",
    "__annotations__",
    "__kwdefaults__",
    "__defaults__",
    "__closure__",
    "__path__",
})

UNSAFE_ROOT_PACKAGES: FrozenSet[str] = frozenset({
    "os",
    "posix",
    "nt",
    "subprocess",
    "_posixsubprocess",
    "sys",
    "base64",
    "ssl",
    "codecs",
    "_codecs",
    "runpy",
    "pty",
    "marshal",
    "compileall",
    "code",
    "codeop",
    "importlib",
    "imp",
    "dill",
    "joblib",
    "shelve",
    "atexit",
    "site",
    "sysconfig",
    "pdb",
    "bdb",
    "cProfile",
    "profile",
    "trace",
    "faulthandler",
    "socket",
    "http",
    "urllib",
    "requests",
    "webbrowser",
    "xmlrpc",
    "multiprocessing",
    "concurrent",
    "asyncio",
    "ctypes",
    "_ctypes",
    "httplib",
    "urllib2",
    "urllib3",
    "pydoc",
    "logging",
    "weakref",
    "doctest",
    "unittest",
    "zipapp",
    "venv",
    "ensurepip",
    "tkinter",
    "turtle",
    "antigravity",
    "idlelib",
    "__main__",
})

APPROVED_BASE_CLASS_SPECS = immutabledict.immutabledict({
    "torch": (
        "torch.nn.Module",
        "torch.Tensor",
        "torch.nn.parameter.Parameter",
        "torch.dtype",
    ),
    "torchaudio": ("torch.nn.Module", "torch.Tensor"),
    "torchvision": ("torch.nn.Module", "torch.Tensor"),
    "flax": ("flax.linen.Module", "flax.struct.dataclass"),
    "jax": ("jax.Array", "jax.core.ShapedArray"),
    "numpy": (
        "numpy.ndarray",
        "numpy.dtype",
        "numpy.generic",
        "numpy.number",
    ),
    "pandas": ("pandas.DataFrame", "pandas.Series", "pandas.Index"),
    "datetime": (
        "datetime.date",
        "datetime.datetime",
        "datetime.time",
        "datetime.timedelta",
        "datetime.timezone",
    ),
    "enum": ("enum.Enum", "enum.IntEnum", "enum.Flag", "enum.IntFlag"),
    "collections": (
        "collections.OrderedDict",
        "collections.defaultdict",
        "collections.Counter",
    ),
})

ALL_BASE_CLASS_SPECS: tuple[str, ...] = tuple(
    itertools.chain.from_iterable(APPROVED_BASE_CLASS_SPECS.values())
)

APPROVED_AST_BASE_NAMES: FrozenSet[str] = frozenset(
    set(ALL_BASE_CLASS_SPECS)
    | {path.rsplit(".", 1)[-1] for path in ALL_BASE_CLASS_SPECS}
    | {
        "nn.Module",
        "linen.Module",
        "os.PathLike",
        "PathLike",
        "pathlib.PurePath",
        "PurePath",
        "dict",
        "list",
        "tuple",
        "set",
        "frozenset",
        "int",
        "float",
        "str",
        "bytes",
        "bool",
    }
)

UNSAFE_INLINE_PATTERNS: FrozenSet[str] = frozenset({
    "__import__(",
    "import os",
    "import posix",
    "import subprocess",
    "import requests",
    "import urllib",
    "import socket",
    ".requests.",
    ".urllib.",
    ".socket.",
    ".http.",
    ".subprocess.",
})

DANGEROUS_EXEC_MODULES: FrozenSet[str] = frozenset({
    "os",
    "posix",
    "nt",
    "subprocess",
    "_posixsubprocess",
    "pty",
    "commands",
    "ctypes",
    "_ctypes",
    "shlex",
})

DANGEROUS_EXEC_METHODS: FrozenSet[str] = frozenset({
    "system",
    "popen",
    "spawn",
    "spawnlp",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "exec",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execvp",
    "fork",
    "kill",
    "call",
    "check_call",
    "check_output",
    "run",
    "Popen",
})

SAFE_BUILTIN_TYPES: FrozenSet[str] = frozenset({
    "int",
    "float",
    "str",
    "bytes",
    "bytearray",
    "bool",
    "list",
    "tuple",
    "dict",
    "set",
    "frozenset",
    "slice",
    "range",
    "complex",
    "object",
    "memoryview",
    "ellipsis",
    "NotImplemented",
})

DANGEROUS_PACKAGE_MEMBERS: FrozenSet[str] = frozenset({
    "eval",
    "exec",
    "execfile",
    "compile",
    "sympify",
    "system",
    "popen",
    "spawn",
    "tempfilepager",
    "pipepager",
    "pager",
    "importfile",
    "safeimport",
    "locate",
    "_get_command_stdout",
    "load_library",
    "load_model",
    "read_pickle",
    "fromfile",
    "tofile",
    "loadtxt",
    "savetxt",
    "genfromtxt",
    "save",
    "savez",
    "savez_compressed",
    "loadmat",
    "savemat",
    "f2py",
    "distutils",
    "fileConfig",
    "dictConfig",
    "finalize",
    "testfile",
    "debug_script",
    "findTestCases",
    "loadTestsFromName",
    "loadTestsFromNames",
    "loadTestsFromModule",
    "create_archive",
    "_unix_getnode",
    "_windll_getnode",
    "_popen",
    "_arp_getnode",
    "_ifconfig_getnode",
    "_ip_getnode",
    "_netstat_getnode",
    "_lanscan_getnode",
    "methodcaller",
    "attrgetter",
})

APPROVED_RECONSTRUCTOR_FUNCTIONS: FrozenSet[str] = frozenset({
    "_reconstruct",
    "scalar",
    "from_buffer",
    "_from_backing_data",
    "_new_Index",
    "new_block",
    "_unpickle_block",
    "_unpickle_named_sharding",
    "unpickle_pspec",
    "_rebuild_tensor",
    "_rebuild_tensor_v2",
    "_rebuild_parameter",
    "_rebuild_device_tensor_from_numpy",
    "_rebuild_qtensor",
    "_pickle_ufunc",
    "_LoadEndianness",
    "__newobj__",
    "__newobj_ex__",
    "_reconstructor",
    "dataclass",
})

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
import types
from typing import FrozenSet

# List of globals below can be updated if additional modules are identified
# Note: The strings in this list should be in the format of
# "library.member" or "library" or "member"
# Eg. "os.system", "loads", "system"
SUSPICIOUS_STRINGS: FrozenSet[str] = frozenset([
    "CodeType",
    "_builtin_type",
    "_make_function",
    "__builtin__",
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
    "fnmatch",
    "getattr",
    "glob",
    "hasattr",
    "itertools",
    "linecache",
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
    "doctest.debug_script",
    "eval",
    "exec",
    "fileinput",
    "get_type_hints",
    "gzip.decompress",
    "httplib",
    "importlib",
    "io.open",
    "itemgetter",
    "joblib.load",
    "joblib.memory",
    "joblib.numpy_pickle.NumpyArrayWrapper",
    "keras.saving.pickle_utils",
    "lib2to3.fixer_util.attr_chain",
    "load_module",
    "lzma.open",
    "malicious",
    "marshal",
    "mlflow",
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
    "pywin32_system32",
    "pyyaml",
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
    "torch._dynamo",
    "torch._inductor",
    "torch.distributed",
    "torch.fx.experimental",
    "torch.hub",
    "torch.jit.load",
    "torch.load",
    "torch.unsupported_tensor_ops",
    "torch.utils.collect_env",
    "torch.utils.cpp_extension",
    "types.BuiltinFunctionType",
    "types.CodeType",
    "types.FunctionType",
    "txwinrm",
    "unittest.mock._dot_lookup",
    "unittest.mock._importer",
    "urllib.request",
    "urllib2",
    "urllib3",
    "webbrowser",
    "winapi",
    "winreg",
    "zlib",
])

# Dangerous root modules whose qualified member accesses (e.g.
# subprocess.getoutput, os.execv, posix.fork, marshal.loads) are unsafe even
# when the bare module name is excluded from UNSAFE_STRINGS to avoid false
# positives on plain English vocabulary words.
UNSAFE_ROOT_PACKAGES: FrozenSet[str] = frozenset([
    "__main__",
    "_codecs",
    "_ctypes",
    "_pickle_copy",
    "_posixsubprocess",
    "antigravity",
    "asyncio",
    "atexit",
    "base64",
    "bdb",
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
    "dill",
    "dill_copy",
    "doctest",
    "ensurepip",
    "faulthandler",
    "http",
    "httplib",
    "idlelib",
    "imp",
    "importlib",
    "joblib_copy",
    "lib2to3",
    "logging",
    "marshal",
    "mlflow",
    "multiprocessing",
    "nt",
    "os",
    "pdb",
    "pickle_copy",
    "posix",
    "profile",
    "pty",
    "pydoc",
    "requests",
    "runpy",
    "shelve",
    "shlex",
    "site",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "sysconfig",
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
    "xmlrpc",
    "zipapp",
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
    "custom_pkg",
    "jax",
    "keras",
    "layer",
    "lightning",
    "nltk",
    "nn",
    "numpy",
    "numpy.mean",
    "numpy.sum",
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

OPCODES_INFO = types.MappingProxyType(
    {opcode.code: opcode for opcode in pickletools.opcodes}
)
# Integer-based lookup for opcodes for faster lookups
OPCODES_INFO_INT = types.MappingProxyType(
    {ord(opcode.code): opcode for opcode in pickletools.opcodes}
)

MAX_BYTES_TO_CHECK = 128
MIN_SIZE_FOR_CHUNKING = 30 * 1024 * 1024  # 30 MB

# Tiers for dynamically scaling the number of workers based on file size.
# Each tuple is (file_size_threshold, num_workers). The threshold is the upper
# bound for a given number of workers.
WORKER_TIERS: tuple[tuple[int, int], ...] = (
    (MIN_SIZE_FOR_CHUNKING, 1),  # up to 30MB -> 1 worker
    (128 * 1024 * 1024, 4),  # up to 128MB -> 4 workers
    (512 * 1024 * 1024, 8),  # up to 512MB -> 8 workers
    (1 * 1024 * 1024 * 1024, 16),  # up to 1GB -> 16 workers
    (4 * 1024 * 1024 * 1024, 32),  # up to 4GB -> 32 workers
)

# Cap the number of workers at half the available CPU cores to avoid excessive
# overhead and resource contention.
MAX_NUM_CHUNKS = (os.cpu_count() or 1) // 2

# High score to indicate definite unsafety due to a detected zip slip.
HIGH_SEVERITY_ZIPSLIP = 1337

MAX_ARCHIVE_RECURSION_DEPTH: int = 10
MAX_ARCHIVE_DECOMPRESSED_BYTES: int = 512 * 1024 * 1024  # 512 MB

PAYLOAD_PREFIX_SIZES = types.MappingProxyType({
    "SHORT_BINBYTES": 1,
    "SHORT_BINUNICODE": 1,
    "SHORT_BINSTRING": 1,
    "BINBYTES": 4,
    "BINUNICODE": 4,
    "BINSTRING": 4,
    "BINBYTES8": 8,
    "BINUNICODE8": 8,
    "BYTEARRAY8": 8,
})

OPCODE_STRIDE_GROUPS: tuple[tuple[int, FrozenSet[int]], ...] = (
    (
        1,
        frozenset({
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
        }),
    ),
    (2, frozenset({0x80, 0x4B, 0x68, 0x71, 0x82})),
    (3, frozenset({0x4D, 0x83})),
    (5, frozenset({0x4A, 0x6A, 0x72, 0x84})),
    (9, frozenset({0x47, 0x95})),
)

APPROVED_ROOT_PACKAGES: FrozenSet[str] = frozenset({
    "PIL",
    "collections",
    "cv2",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "flax",
    "functools",
    "gensim",
    "geopandas",
    "custom_pkg",
    "jax",
    "jaxlib",
    "keras",
    "lightgbm",
    "lightning",
    "math",
    "matplotlib",
    "ml_dtypes",
    "mxnet",
    "nltk",
    "numbers",
    "numpy",
    "onnx",
    "opacus",
    "optax",
    "pandas",
    "pillow",
    "pytorch3d",
    "scikit_learn",
    "scipy",
    "seaborn",
    "shapely",
    "sklearn",
    "spacy",
    "statsmodels",
    "sympy",
    "tensorboard",
    "tensorflow",
    "theano",
    "torch",
    "torch_frame",
    "torchaudio",
    "torchmetrics",
    "torchvision",
    "transformers",
    "types",
    "typing",
    "uuid",
    "xgboost",
})

SAFE_METADATA_ATTRIBUTES: FrozenSet[str] = frozenset({
    "__annotations__",
    "__doc__",
    "__file__",
    "__module__",
    "__name__",
    "__package__",
    "__path__",
    "__qualname__",
})

ALL_BASE_CLASS_SPECS: tuple[str, ...] = (
    "torch.nn.Module",
    "torch.Tensor",
    "torch.nn.parameter.Parameter",
    "torch.dtype",
    "flax.linen.Module",
    "flax.struct.dataclass",
    "jax.Array",
    "jax.core.ShapedArray",
    "numpy.ndarray",
    "numpy.dtype",
    "numpy.generic",
    "numpy.number",
    "pandas.DataFrame",
    "pandas.Series",
    "pandas.Index",
    "datetime.date",
    "datetime.datetime",
    "datetime.time",
    "datetime.timedelta",
    "datetime.timezone",
    "enum.Enum",
    "enum.IntEnum",
    "enum.Flag",
    "enum.IntFlag",
    "collections.OrderedDict",
    "collections.defaultdict",
    "collections.Counter",
    "collections.deque",
    "collections.UserDict",
)

SAFE_BUILTIN_TYPES: FrozenSet[str] = frozenset({
    "NotImplemented",
    "bool",
    "bytearray",
    "bytes",
    "complex",
    "dict",
    "ellipsis",
    "float",
    "frozenset",
    "int",
    "list",
    "memoryview",
    "object",
    "range",
    "set",
    "slice",
    "str",
    "tuple",
})

APPROVED_AST_BASE_NAMES: FrozenSet[str] = (
    SAFE_BUILTIN_TYPES
    | frozenset(ALL_BASE_CLASS_SPECS)
    | frozenset({
        "Array",
        "Counter",
        "DataFrame",
        "Enum",
        "Flag",
        "Index",
        "IntEnum",
        "IntFlag",
        "Module",
        "OrderedDict",
        "Parameter",
        "PathLike",
        "PurePath",
        "Series",
        "ShapedArray",
        "Tensor",
        "UserDict",
        "dataclass",
        "date",
        "datetime",
        "defaultdict",
        "deque",
        "dtype",
        "generic",
        "linen.Module",
        "ndarray",
        "nn.Module",
        "number",
        "os.PathLike",
        "pathlib.PurePath",
        "time",
        "timedelta",
        "timezone",
    })
)

SELF_PROTECTED_PREFIXES: FrozenSet[str] = frozenset({
    "config.set_config_path",
    "corrupy",
    "picklemagic",
    "safer_pickle",
    "saferpickle",
})

UNSAFE_INLINE_PATTERNS: FrozenSet[str] = frozenset({
    "__import__(",
    "__import__ (",
    "eval(",
    "exec(",
    "compile(",
    "os.system(",
    "os.popen(",
    "posix.system(",
    "posix.popen(",
    ".system(",
    ".popen(",
    "import os;",
    "import os ",
    "from os import ",
    "import posix;",
    "from posix import ",
    "import subprocess;",
    "from subprocess import ",
    "import pty;",
    "from pty import ",
    "import ctypes;",
    "from ctypes import ",
    "import runpy;",
    "from runpy import ",
    "import requests;",
    "from requests import ",
    "import urllib;",
    "from urllib import ",
    "import socket;",
})

DANGEROUS_EXEC_MODULES: FrozenSet[str] = frozenset({
    "_ctypes",
    "_posixsubprocess",
    "commands",
    "ctypes",
    "http",
    "nt",
    "os",
    "posix",
    "pty",
    "requests",
    "shlex",
    "socket",
    "subprocess",
    "urllib",
})

DANGEROUS_PACKAGE_MEMBERS: FrozenSet[str] = frozenset({
    "_FuncBuilder",
    "_arp_getnode",
    "_create_fn",
    "_eval_type",
    "_get_command_stdout",
    "_ifconfig_getnode",
    "_ip_getnode",
    "_lanscan_getnode",
    "_netstat_getnode",
    "_popen",
    "_run_entry_point",
    "_unix_getnode",
    "_windll_getnode",
    "add_fns_to_class",
    "attrgetter",
    "compile",
    "create_archive",
    "debug_script",
    "dictConfig",
    "distutils",
    "eval",
    "exec",
    "execfile",
    "f2py",
    "fileConfig",
    "finalize",
    "findTestCases",
    "from_pretrained",
    "fromfile",
    "genfromtxt",
    "get_type_hints",
    "getattribute_from_module",
    "importfile",
    "loadTestsFromModule",
    "loadTestsFromName",
    "loadTestsFromNames",
    "load_library",
    "load_model",
    "loadmat",
    "loadtxt",
    "locate",
    "make_dataclass",
    "methodcaller",
    "pager",
    "pipepager",
    "popen",
    "read_csv",
    "read_feather",
    "read_fwf",
    "read_html",
    "read_json",
    "read_orc",
    "read_parquet",
    "read_pickle",
    "read_sql",
    "read_table",
    "read_xml",
    "safeimport",
    "save",
    "savemat",
    "savetxt",
    "savez",
    "savez_compressed",
    "spawn",
    "spawnv_passfds",
    "sympify",
    "system",
    "tempfilepager",
    "testfile",
    "tofile",
})

APPROVED_RECONSTRUCTOR_FUNCTIONS: FrozenSet[str] = frozenset({
    "_LoadEndianness",
    "__newobj__",
    "__newobj_ex__",
    "_from_backing_data",
    "_frombuffer",
    "_new_Index",
    "_pickle_ufunc",
    "_rebuild_device_tensor_from_numpy",
    "_rebuild_parameter",
    "_rebuild_qtensor",
    "_rebuild_tensor",
    "_rebuild_tensor_v2",
    "_reconstruct",
    "_reconstructor",
    "_unpickle_block",
    "_unpickle_named_sharding",
    "dataclass",
    "new_block",
    "scalar",
    "unpickle_pspec",
})

DANGEROUS_CLASS_LIFECYCLE_HOOKS: FrozenSet[str] = frozenset({
    "__del__",
    "__getnewargs__",
    "__getnewargs_ex__",
    "__reduce__",
    "__reduce_ex__",
    "__setstate__",
})

RECONSTRUCTOR_NAME_MARKERS: tuple[str, ...] = (
    "reconstruct",
    "rebuild",
    "unpickle",
    "frombuffer",
    "from_backing",
    "_new_",
)

DANGEROUS_CODE_NAMES: FrozenSet[str] = (
    UNSAFE_ROOT_PACKAGES
    | DANGEROUS_PACKAGE_MEMBERS
    | frozenset({
        "CodeType",
        "FunctionType",
        "__builtins__",
        "__import__",
        "__subclasses__",
        "_pickle",
        "builtins",
        "delattr",
        "getattr",
        "globals",
        "import_module",
        "io",
        "locals",
        "open",
        "pathlib",
        "pickle",
        "setattr",
        "shutil",
        "tempfile",
        "vars",
    })
)

INTERNAL_FAKE_WARNING_CLASSES: FrozenSet[str] = frozenset({
    "corrupy.picklemagic.FakeWarning",
    "corrupy.picklemagic._SaferFakeWarning",
    "corrupy.picklemagic._BoundSaferFakeWarning",
})

INTERNAL_SANDBOX_SAFE_SYMBOLS: FrozenSet[str] = (
    INTERNAL_FAKE_WARNING_CLASSES
    | frozenset({
        "picklemagic.failed_reduce",
        "picklemagic.failed_instantiate",
        "picklemagic.failed_newobj",
    })
)

IMPORT_OPCODES: FrozenSet[str] = frozenset({
    "GLOBAL",
    "STACK_GLOBAL",
    "INST",
    "EXT1",
    "EXT2",
    "EXT4",
    "PERSID",
    "BINPERSID",
})

DANGEROUS_BUILD_STATE_KEYS: FrozenSet[str] = frozenset({
    "__setstate__",
    "__getstate__",
    "__reduce__",
    "__reduce_ex__",
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__del__",
    "__call__",
    "__setitem__",
    "__getitem__",
    "__delitem__",
    "__hash__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__enter__",
    "__exit__",
    "__class__",
    "__dict__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__init_subclass__",
    "__new__",
    "__init__",
    "append",
    "extend",
})

SAFE_DUNDER_RECONSTRUCTORS: FrozenSet[str] = frozenset({
    "__newobj__",
    "__newobj_ex__",
})

INTROSPECTION_ATTRIBUTE_PREFIXES: tuple[str, ...] = (
    "func_",
    "f_",
    "gi_",
    "cr_",
    "ag_",
    "co_",
)

INTROSPECTION_ATTRIBUTES: FrozenSet[str] = frozenset({
    "cell_contents",
    "tb_frame",
    "tb_next",
})

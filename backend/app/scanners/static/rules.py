"""Static analysis rule tables.

Severities are ProvenanceX rule severities, not CVSS. A match means "this code can do X",
which is a signal for review. It is not evidence of malice and not a known vulnerability.

`os` is deliberately not a dangerous import, because almost every Python file uses it.
Its dangerous calls (os.system, os.popen, ...) are API rules instead.
"""

from dataclasses import dataclass

KIND_IMPORT = "dangerous_import"
KIND_API = "suspicious_api"
KIND_INSTALL = "install_script"
KIND_ARCHIVE = "archive_anomaly"


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    severity: str  # HIGH | MEDIUM | LOW
    title: str


# ---------------------------------------------------------------------- imports
IMPORT_PROCESS = Rule("PX-STATIC-IMPORT-PROCESS", KIND_IMPORT, "LOW", "Process-control import")
IMPORT_NATIVE = Rule("PX-STATIC-IMPORT-NATIVE", KIND_IMPORT, "MEDIUM", "Native-code import")
IMPORT_NETWORK = Rule("PX-STATIC-IMPORT-NETWORK", KIND_IMPORT, "LOW", "Network import")
IMPORT_DESERIALIZE = Rule(
    "PX-STATIC-IMPORT-DESERIALIZE", KIND_IMPORT, "LOW", "Unsafe-deserialization import"
)
IMPORT_DYNAMIC = Rule("PX-STATIC-IMPORT-DYNAMIC", KIND_IMPORT, "MEDIUM", "Dynamic-execution import")

_IMPORT_GROUPS: dict[Rule, tuple[str, ...]] = {
    IMPORT_PROCESS: ("subprocess", "pty"),
    IMPORT_NATIVE: ("ctypes", "cffi"),
    IMPORT_NETWORK: (
        "socket",
        "urllib.request",
        "urllib3",
        "http.client",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "telnetlib",
        "smtplib",
        "paramiko",
    ),
    IMPORT_DESERIALIZE: ("pickle", "cPickle", "marshal", "dill", "cloudpickle", "shelve"),
    IMPORT_DYNAMIC: ("runpy",),
}
DANGEROUS_IMPORTS: dict[str, Rule] = {
    module: rule for rule, modules in _IMPORT_GROUPS.items() for module in modules
}


def import_rule(module: str) -> Rule | None:
    """Rule for a module or any of its parent packages (`a.b.c`, then `a.b`, then `a`)."""
    parts = module.split(".")
    for end in range(len(parts), 0, -1):
        rule = DANGEROUS_IMPORTS.get(".".join(parts[:end]))
        if rule is not None:
            return rule
    return None


# ---------------------------------------------------------------------- API calls
API_PROCESS = Rule("PX-STATIC-API-PROCESS", KIND_API, "MEDIUM", "Spawns a process or shell")
API_EVAL = Rule("PX-STATIC-API-EVAL", KIND_API, "MEDIUM", "Evaluates dynamic code")
API_EXEC_DECODED = Rule("PX-STATIC-API-EXEC-DECODED", KIND_API, "HIGH", "Executes decoded data")
API_DYNAMIC_IMPORT = Rule(
    "PX-STATIC-API-DYNAMIC-IMPORT", KIND_API, "MEDIUM", "Imports a module chosen at runtime"
)
API_NATIVE = Rule("PX-STATIC-API-NATIVE", KIND_API, "MEDIUM", "Loads native code")
API_NETWORK = Rule("PX-STATIC-API-NETWORK", KIND_API, "LOW", "Makes a network call")
API_DESERIALIZE = Rule("PX-STATIC-API-DESERIALIZE", KIND_API, "MEDIUM", "Deserializes unsafe data")
API_OBFUSCATION = Rule(
    "PX-STATIC-API-OBFUSCATED-ATTR", KIND_API, "MEDIUM", "Computes an attribute name dynamically"
)

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "request")
_API_GROUPS: dict[Rule, tuple[str, ...]] = {
    API_PROCESS: (
        "os.system",
        "os.popen",
        "os.fork",
        "os.forkpty",
        *[f"os.{n}" for n in ("execl", "execle", "execlp", "execlpe", "execv", "execve")],
        *[f"os.{n}" for n in ("execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnv")],
        *[f"os.{n}" for n in ("spawnve", "spawnvp", "posix_spawn", "posix_spawnp")],
        "posix.system",
        "pty.spawn",
        *[f"subprocess.{n}" for n in ("Popen", "run", "call", "check_call", "check_output")],
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    ),
    API_EVAL: ("eval", "exec", "compile", "runpy.run_path", "runpy.run_module"),
    API_NATIVE: (
        "ctypes.CDLL",
        "ctypes.WinDLL",
        "ctypes.OleDLL",
        "ctypes.cdll.LoadLibrary",
        "ctypes.windll.LoadLibrary",
    ),
    API_NETWORK: (
        "socket.socket",
        "socket.create_connection",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        *[f"requests.{v}" for v in _HTTP_VERBS],
        *[f"httpx.{v}" for v in _HTTP_VERBS],
    ),
    API_DESERIALIZE: (
        "pickle.load",
        "pickle.loads",
        "cPickle.load",
        "cPickle.loads",
        "marshal.load",
        "marshal.loads",
        "dill.load",
        "dill.loads",
        "cloudpickle.load",
        "cloudpickle.loads",
        "shelve.open",
        "joblib.load",
        "torch.load",
    ),
}
API_RULES: dict[str, Rule] = {name: rule for rule, names in _API_GROUPS.items() for name in names}

DECODER_CALLS = frozenset(
    {
        "base64.b64decode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.b85decode",
        "base64.a85decode",
        "base64.urlsafe_b64decode",
        "base64.standard_b64decode",
        "binascii.a2b_base64",
        "binascii.unhexlify",
        "bytes.fromhex",
        "codecs.decode",
        "zlib.decompress",
        "gzip.decompress",
        "bz2.decompress",
        "lzma.decompress",
        "marshal.loads",
    }
)
# getattr() on these with a variable name can reach any of their dangerous attributes.
SENSITIVE_ROOTS = frozenset(
    {"os", "subprocess", "builtins", "sys", "socket", "ctypes", "importlib"}
)

# ---------------------------------------------------------------------- text rules
TEXT_PIPE_TO_SHELL = Rule(
    "PX-STATIC-TEXT-PIPE-TO-SHELL", KIND_API, "HIGH", "Pipes downloaded or decoded data to a shell"
)
TEXT_REVERSE_SHELL = Rule("PX-STATIC-TEXT-REVERSE-SHELL", KIND_API, "HIGH", "Reverse-shell pattern")
TEXT_JS_CHILD_PROCESS = Rule(
    "PX-STATIC-TEXT-JS-CHILD-PROCESS", KIND_IMPORT, "MEDIUM", "JavaScript process-control import"
)
TEXT_JS_EVAL = Rule("PX-STATIC-TEXT-JS-EVAL", KIND_API, "MEDIUM", "JavaScript dynamic code")
TEXT_PS_ENCODED = Rule("PX-STATIC-TEXT-PS-ENCODED", KIND_API, "HIGH", "Encoded PowerShell command")
TEXT_PS_DOWNLOAD_EXEC = Rule(
    "PX-STATIC-TEXT-PS-DOWNLOAD-EXEC",
    KIND_API,
    "MEDIUM",
    "PowerShell download or dynamic execution",
)
TEXT_BATCH_DOWNLOAD = Rule(
    "PX-STATIC-TEXT-BATCH-DOWNLOAD", KIND_API, "MEDIUM", "Batch download through a system tool"
)
TEXT_PY_FALLBACK = Rule(
    "PX-STATIC-TEXT-PY-UNPARSED",
    KIND_API,
    "MEDIUM",
    "Risky call in Python that could not be parsed",
)

# ---------------------------------------------------------------------- install hooks
INSTALL_NPM = Rule(
    "PX-STATIC-INSTALL-NPM", KIND_INSTALL, "MEDIUM", "npm lifecycle script runs on install"
)
INSTALL_SETUP_PY = Rule(
    "PX-STATIC-INSTALL-SETUP-PY", KIND_INSTALL, "LOW", "setup.py runs code on install"
)
INSTALL_SETUP_CMDCLASS = Rule(
    "PX-STATIC-INSTALL-CMDCLASS", KIND_INSTALL, "MEDIUM", "setup.py overrides install commands"
)

# ---------------------------------------------------------------------- archive anomalies
ARCHIVE_NESTED = Rule("PX-STATIC-ARCHIVE-NESTED", KIND_ARCHIVE, "LOW", "Nested archive")
ARCHIVE_NOT_INSPECTED = Rule(
    "PX-STATIC-ARCHIVE-NOT-INSPECTED", KIND_ARCHIVE, "LOW", "Nested archive was not inspected"
)
ARCHIVE_UNSAFE = Rule(
    "PX-STATIC-ARCHIVE-NESTED-UNSAFE", KIND_ARCHIVE, "HIGH", "Nested archive has unsafe entries"
)
ARCHIVE_CORRUPT = Rule(
    "PX-STATIC-ARCHIVE-CORRUPT", KIND_ARCHIVE, "LOW", "Nested archive could not be read"
)
ARCHIVE_DISGUISED_EXE = Rule(
    "PX-STATIC-ARCHIVE-DISGUISED-EXE", KIND_ARCHIVE, "HIGH", "Executable under a non-binary name"
)
ARCHIVE_DOUBLE_EXT = Rule(
    "PX-STATIC-ARCHIVE-DOUBLE-EXT", KIND_ARCHIVE, "MEDIUM", "Executable double file extension"
)
ARCHIVE_NEAR_LIMIT = Rule(
    "PX-STATIC-ARCHIVE-NEAR-LIMIT-RATIO",
    KIND_ARCHIVE,
    "LOW",
    "Upload entry compression ratio is near the limit",
)

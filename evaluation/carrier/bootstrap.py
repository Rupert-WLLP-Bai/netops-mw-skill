"""Trusted, stdlib-only Linux restriction bootstrap for M6.

Supported boundary: x86-64 Linux, Landlock filesystem ABI 3 through 11, and seccomp-BPF.
The candidate adapter is exec'd only after the filesystem and syscall filters are
installed. This is a narrow evaluator boundary, not a hostile-kernel sandbox.
"""
from __future__ import annotations

import ctypes
import errno
import importlib
import json
import os
import platform
import signal
import stat
import sys
from pathlib import Path

_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000

# Landlock filesystem rights through ABI 3 cover every path mutation needed here.
# Device ioctl is denied directly by seccomp; ABI 5 can additionally handle it
# in Landlock. A missing required path right never weakens the filesystem policy.
_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_DIR = 1 << 4
_REMOVE_FILE = 1 << 5
_MAKE_CHAR = 1 << 6
_MAKE_DIR = 1 << 7
_MAKE_REG = 1 << 8
_MAKE_SOCK = 1 << 9
_MAKE_FIFO = 1 << 10
_MAKE_BLOCK = 1 << 11
_MAKE_SYM = 1 << 12
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_IOCTL_DEV = 1 << 15
_RESOLVE_UNIX = 1 << 16
_FS_HANDLED = (1 << 15) - 1
_READ_ACCESS = _EXECUTE | _READ_FILE | _READ_DIR
_READ_ONLY_ACCESS = _READ_FILE | _READ_DIR
_TEMP_ACCESS = (_READ_FILE | _READ_DIR | _WRITE_FILE | _REMOVE_DIR |
                _REMOVE_FILE | _MAKE_DIR | _MAKE_REG | _REFER | _TRUNCATE)


class _RulesetAttr(ctypes.Structure):
    # Pass the current zero-extended layout. Older ABI kernels accept zeroed
    # trailing fields, while omitted controls stay disabled.
    _fields_ = [('handled_access_fs', ctypes.c_uint64),
                ('handled_access_net', ctypes.c_uint64),
                ('scoped', ctypes.c_uint64),
                ('handled_permissions', ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]


class _SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_uint16), ('jt', ctypes.c_uint8),
                ('jf', ctypes.c_uint8), ('k', ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint16),
                ('filters', ctypes.POINTER(_SockFilter))]


def _fail(reason: str) -> None:
    os.write(2, ('isolation_unavailable:' + reason + '\n').encode('ascii'))
    raise SystemExit(125)


def _syscall(number: int, *args: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(number), *(ctypes.c_ulong(arg) for arg in args))
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def _safe_existing(path_text: str, *, reject_symlinks: bool = True) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        raise ValueError('non_absolute')
    if reject_symlinks:
        for part in (path, *path.parents):
            if part.is_symlink():
                raise ValueError('symlink')
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or
            stat.S_ISCHR(info.st_mode)):
        raise ValueError('unsupported_path_type')
    return resolved


def _within(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _runtime_grants(blocked: list[Path]) -> list[Path]:
    # Python -I -S starts with the configured stdlib paths only. Grant each exact
    # existing entry plus the exact mapped executable/shared-library files. Load
    # extension modules the copied provider CLIs need before taking the map snapshot.
    for name in ('hashlib', 'multiprocessing', 'subprocess', 'sqlite3', 'math',
                 'datetime', 're', 'zlib', 'bz2', 'lzma'):
        importlib.import_module(name)
    grants: set[Path] = set()
    for item in sys.path:
        if item:
            candidate = Path(item)
            if candidate.exists():
                grants.add(_safe_existing(str(candidate), reject_symlinks=False))
    grants.add(_safe_existing(sys.executable, reject_symlinks=False))
    try:
        maps = Path('/proc/self/maps').read_text(encoding='ascii', errors='strict')
    except (OSError, UnicodeError):
        raise RuntimeError('runtime_map_unavailable') from None
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or not fields[5].startswith('/'):
            continue
        mapped = fields[5].removesuffix(' (deleted)')
        try:
            path = _safe_existing(mapped, reject_symlinks=False)
        except (OSError, ValueError):
            continue
        if path.is_file():
            grants.add(path)
    loader_cache = Path('/etc/ld.so.cache')
    if loader_cache.exists():
        grants.add(_safe_existing(str(loader_cache)))
    null_device = _safe_existing('/dev/null')
    grants.add(null_device)
    for grant in grants:
        if any(_within(grant, item) or _within(item, grant) for item in blocked):
            raise RuntimeError('runtime_grant_intersects_blocked_root')
    return sorted(grants, key=str)


def _add_path_rule(ruleset_fd: int, path: Path, rights: int) -> None:
    if not path.is_dir():
        # Landlock rejects directory-only rights in a rule attached to a file.
        rights &= ~_READ_DIR
    fd = os.open(path, getattr(os, 'O_PATH', 0o10000000) | os.O_CLOEXEC)
    try:
        attr = _PathBeneathAttr(rights, fd)
        _syscall(_LANDLOCK_ADD_RULE, ruleset_fd, _LANDLOCK_RULE_PATH_BENEATH,
                 ctypes.addressof(attr), 0)
    finally:
        os.close(fd)


def _install_landlock(read_roots: list[Path], write_root: Path,
                      blocked: list[Path]) -> None:
    try:
        abi = _syscall(_LANDLOCK_CREATE_RULESET, 0, 0,
                       _LANDLOCK_CREATE_RULESET_VERSION)
    except OSError:
        raise RuntimeError('landlock_unavailable') from None
    if abi < 3 or abi > 11:
        raise RuntimeError('landlock_abi_unrepresented')
    try:
        runtime = _runtime_grants(blocked)
        handled = _FS_HANDLED
        if abi >= 5:
            handled |= _IOCTL_DEV
        if abi >= 9:
            handled |= _RESOLVE_UNIX
        attr = _RulesetAttr(handled)
        ruleset_fd = _syscall(_LANDLOCK_CREATE_RULESET, ctypes.addressof(attr),
                              ctypes.sizeof(attr), 0)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError('landlock_setup_failed') from None
    try:
        for root in read_roots:
            _add_path_rule(ruleset_fd, root, _READ_ONLY_ACCESS)
        for path in runtime:
            _add_path_rule(ruleset_fd, path, _READ_ACCESS)
        _add_path_rule(ruleset_fd, write_root, _TEMP_ACCESS)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), 'prctl')
            _syscall(_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
        except OSError:
            raise RuntimeError('landlock_enforcement_failed') from None
    except (OSError, RuntimeError):
        raise RuntimeError('landlock_rules_failed') from None
    finally:
        os.close(ruleset_fd)


# Reviewed x86-64 syscall numbers. Other audit architectures fail before policy
# construction; x32 is explicitly rejected despite sharing the audit arch value.
_DENIED_SYSCALLS = {
    # socket creation, connection, naming, accept, send/receive and options
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    288, 299, 307,
    # Metadata mutation not mediated by Landlock filesystem rules
    90, 91, 92, 93, 94, 132, 188, 189, 190, 194, 195, 196, 197, 198, 199,
    235, 260, 261, 268, 280, 452,
    # io_uring, ptrace-family access, pidfd acquisition and device ioctl
    425, 426, 427, 101, 310, 311, 438, 434, 424, 16,
    # Handle-based path access, mount and namespace routes
    155, 161, 165, 166, 303, 304, 272, 308, 428, 429, 430, 431, 432,
    433, 442,
    # Kernel interfaces that expose or redirect memory, devices or execution
    298, 321, 323, 425, 437, 313, 316, 317,
}


def _seccomp_filter() -> tuple[_SockFilter, ...]:
    # Classic BPF: architecture mismatch and x32 enter are fatal; explicit deny
    # entries return EPERM, leaving Python's normal spawn/exec syscalls available.
    code = [
        _SockFilter(0x20, 0, 0, 4),                         # LD arch
        _SockFilter(0x15, 1, 0, _AUDIT_ARCH_X86_64),       # JEQ arch
        _SockFilter(0x06, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(0x20, 0, 0, 0),                         # LD nr
        _SockFilter(0x45, 0, 1, _X32_SYSCALL_BIT),          # JSET x32
        _SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
        _SockFilter(0x15, 0, 3, 56),                        # JEQ clone
        _SockFilter(0x20, 0, 0, 16),                        # LD clone flags low word
        _SockFilter(0x45, 0, 1, 0x7E020080),                # JSET CLONE_NEW* flags
        _SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM),
        _SockFilter(0x20, 0, 0, 0),                         # LD nr again
        _SockFilter(0x15, 0, 1, 435),                        # JEQ clone3
        _SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.ENOSYS),
    ]
    for number in sorted(_DENIED_SYSCALLS):
        code.append(_SockFilter(0x15, 0, 1, number))         # JEQ nr
        code.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | errno.EPERM))
    code.append(_SockFilter(0x06, 0, 0, _SECCOMP_RET_ALLOW))
    return tuple(code)


def _install_seccomp() -> None:
    instructions = (_SockFilter * len(_seccomp_filter()))(*_seccomp_filter())
    program = _SockFprog(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER,
                  ctypes.byref(program), 0, 0) != 0:
        raise RuntimeError('seccomp_enforcement_failed')


def _read_policy() -> dict:
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError('policy_too_large')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_key')
            result[key] = value
        return result
    return json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def _normalize_policy(value: dict):
    if set(value) != {'argv', 'read_roots', 'write_root', 'blocked_roots'}:
        raise ValueError('policy_fields')
    argv = value['argv']
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x or '\x00' in x for x in argv):
        raise ValueError('argv')
    reads = sorted({_safe_existing(p) for p in value['read_roots']}, key=str)
    blocked = sorted({_safe_existing(p) for p in value['blocked_roots']}, key=str)
    write = _safe_existing(value['write_root'])
    if any(not p.is_dir() for p in [*reads, write, *blocked]):
        raise ValueError('directory_required')
    for private in blocked:
        if any(_within(grant, private) or _within(private, grant)
               for grant in [*reads, write]):
            raise ValueError('blocked_root_overlap')
    if any(_within(write, root) or _within(root, write) for root in reads):
        raise ValueError('read_write_overlap')
    return argv, reads, write, blocked


def main() -> int:
    try:
        if platform.machine().lower() not in ('x86_64', 'amd64'):
            _fail('unsupported_architecture')
        policy = _read_policy()
        argv, read_roots, write_root, blocked = _normalize_policy(policy)
        # fd 0 carried the trusted bootstrap policy, including blocked roots.
        # Replace it with empty input so the adapter and provider children inherit
        # no copy of the policy channel and still have a conventional stdin handle.
        os.close(0)
        null_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        if null_fd != 0:
            os.dup2(null_fd, 0)
            os.close(null_fd)
        os.set_inheritable(0, True)
        # Popen(close_fds=True) intentionally provides only stdio. Close every
        # other descriptor defensively before installing restrictions.
        _syscall(436, 3, 0xFFFFFFFF, 0)  # close_range(3, UINT_MAX, 0)
        os.environ.clear()
        os.environ.update({'HOME': str(write_root), 'TMPDIR': str(write_root),
                           'PATH': os.defpath, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                           'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                           'PYTHONSAFEPATH': '1'})
        _install_landlock(read_roots, write_root, blocked)
        _install_seccomp()
        os.execve(argv[0], argv, dict(os.environ))
    except SystemExit:
        raise
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        _fail('bootstrap_policy_failed')
    return 125


if __name__ == '__main__':
    sys.exit(main())

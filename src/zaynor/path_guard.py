"""Read-only path confinement for frozen case evidence.

ADAPTED from ANNACONDA's `core/path_guard.py` (annatchijova/annaconda),
translated to English and re-pointed at ZAYNOR's own case root instead of
VIGÍA/ANNACONDA's default paths. The validation logic (lexical
normalization, symlink/reparse-point detection on every path component,
component-wise allowlist, TOCTOU re-check, O_NOFOLLOW + flock on open) is
kept essentially as-is — this is exactly the "casi copy paste, podés
simplificar" case: the security properties are the reusable part, not the
prose.

Not called live against VIGÍA's version because VIGÍA's `PathGuard`
equivalent lives inside `vigia_sift_bridge.py`, coupled to the MCP
bridge's session/work-dir/mount-root state (see AGENTS.md §2.1 — that
coupling is the documented incompatibility for adapting instead of calling
it directly).
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path


@dataclass(frozen=True)
class PathValidationResult:
    valid: bool
    reason: str
    inode: int
    size: int
    # Exact seconds represented as a Fraction derived from st_mtime_ns.
    mtime: Fraction
    hash_prefix: str


class PathGuard:
    """Read-only path validator. Protects against:

    - Symlink attacks (including intermediate symlinks anywhere in the path)
    - Path traversal
    - TOCTOU (time-of-check to time-of-use)
    - FIFO/device/socket injection
    """

    def __init__(self, allowed_base_paths: list[Path]):
        if not allowed_base_paths:
            raise ValueError("PathGuard requires at least one allowed base path")
        self._allowed = [self._lexical_absolute(base) for base in allowed_base_paths]

    @staticmethod
    def _lexical_absolute(path: os.PathLike[str] | str) -> Path:
        """Absolute, lexically normalized path — '.', '..' collapsed, but
        symlinks NOT resolved. Resolving them before checking would lose the
        evidence that the path traversed one.
        """
        return Path(os.path.abspath(os.fspath(path)))

    def validate(self, path_str: str, allow_dir: bool = False) -> PathValidationResult:
        """Validate a path with TOCTOU protection. Never follows symlinks —
        uses lstat() to detect them.

        `allow_dir=True` permits validating a directory (for read-only
        listing); every other protection (symlink, allowlist, TOCTOU) still
        applies — only the regular-file requirement relaxes to
        regular-file-or-directory.
        """
        try:
            raw_path = os.fspath(path_str)
            if not isinstance(raw_path, str):
                raise ValueError("path must be text")
            p = Path(raw_path)
            # A path containing '..' has no stable acquisition identity, even
            # if it lexically ends up inside an allowed root — reject before
            # any normalization or allowlist check.
            if ".." in p.parts:
                return PathValidationResult(
                    valid=False, reason="PATH_TRAVERSAL",
                    inode=0, size=0, mtime=Fraction(0), hash_prefix="",
                )
            abs_path = self._lexical_absolute(p)
        except (OSError, TypeError, ValueError) as exc:
            return PathValidationResult(
                valid=False, reason=f"INVALID_PATH: {exc}",
                inode=0, size=0, mtime=Fraction(0), hash_prefix="",
            )

        try:
            for parent in [abs_path, *abs_path.parents]:
                if not parent.exists():
                    continue
                if parent.is_symlink():
                    return PathValidationResult(
                        valid=False, reason="SYMLINK_DETECTED_IN_PATH",
                        inode=0, size=0, mtime=Fraction(0), hash_prefix="",
                    )
                if getattr(os.lstat(str(parent)), "st_reparse_tag", 0):
                    return PathValidationResult(
                        valid=False, reason="REPARSE_POINT_DETECTED_IN_PATH",
                        inode=0, size=0, mtime=Fraction(0), hash_prefix="",
                    )
        except OSError as exc:
            return PathValidationResult(
                valid=False, reason=f"SYMLINK_CHECK_FAILED: {exc}",
                inode=0, size=0, mtime=Fraction(0), hash_prefix="",
            )

        # Allowlist by path component, not text prefix: "<root>-neighbor" is
        # not inside "<root>".
        allowed = any(
            abs_path == base or base in abs_path.parents for base in self._allowed
        )
        if not allowed:
            reason = "FILE_NOT_FOUND" if not abs_path.exists() else "OUTSIDE_ALLOWLIST"
            return PathValidationResult(
                valid=False, reason=reason,
                inode=0, size=0, mtime=Fraction(0), hash_prefix="",
            )

        if not abs_path.exists():
            return PathValidationResult(
                valid=False, reason="FILE_NOT_FOUND",
                inode=0, size=0, mtime=Fraction(0), hash_prefix="",
            )

        try:
            st = abs_path.lstat()
            inode, size = st.st_ino, st.st_size
            mtime = Fraction(st.st_mtime_ns, 1_000_000_000)
            if allow_dir:
                if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                    return PathValidationResult(
                        valid=False, reason="NOT_A_REGULAR_FILE_OR_DIR",
                        inode=inode, size=size, mtime=mtime, hash_prefix="",
                    )
            elif not stat.S_ISREG(st.st_mode):
                return PathValidationResult(
                    valid=False, reason="NOT_A_REGULAR_FILE",
                    inode=inode, size=size, mtime=mtime, hash_prefix="",
                )
        except OSError as exc:
            return PathValidationResult(
                valid=False, reason=f"STAT_FAILED: {exc}",
                inode=0, size=0, mtime=Fraction(0), hash_prefix="",
            )

        hash_prefix = ""
        if size > 0 and not stat.S_ISDIR(st.st_mode):
            try:
                with abs_path.open("rb") as handle:
                    prefix = handle.read(4096)
                hash_prefix = hashlib.sha256(prefix).hexdigest()[:16]
            except OSError:
                pass

        return PathValidationResult(
            valid=True, reason="VALID",
            inode=inode, size=size, mtime=mtime, hash_prefix=hash_prefix,
        )

    def verify_no_toctou(
        self, path_str: str, previous: PathValidationResult
    ) -> PathValidationResult:
        """Re-check after access (USE). A changed inode, size, mtime, or
        content-prefix hash between check and use is a TOCTOU attack.
        """
        current = self.validate(path_str)
        if not current.valid:
            return PathValidationResult(
                valid=False, reason=f"TOCTOU_VIOLATION: {current.reason}",
                inode=current.inode, size=current.size,
                mtime=current.mtime, hash_prefix=current.hash_prefix,
            )
        if current.inode != previous.inode:
            return PathValidationResult(
                valid=False, reason="TOCTOU_INODE_CHANGED",
                inode=current.inode, size=current.size,
                mtime=current.mtime, hash_prefix=current.hash_prefix,
            )
        if current.size != previous.size:
            return PathValidationResult(
                valid=False, reason="TOCTOU_SIZE_CHANGED",
                inode=current.inode, size=current.size,
                mtime=current.mtime, hash_prefix=current.hash_prefix,
            )
        if abs(current.mtime - previous.mtime) > Fraction(1, 1_000):
            return PathValidationResult(
                valid=False, reason="TOCTOU_MTIME_CHANGED",
                inode=current.inode, size=current.size,
                mtime=current.mtime, hash_prefix=current.hash_prefix,
            )
        if current.hash_prefix != previous.hash_prefix:
            return PathValidationResult(
                valid=False, reason="TOCTOU_CONTENT_CHANGED",
                inode=current.inode, size=current.size,
                mtime=current.mtime, hash_prefix=current.hash_prefix,
            )
        return current

    def safe_open(self, path_str: str, mode: str = "rb"):
        """Open a file with full TOCTOU protection: validate, open with
        O_NOFOLLOW, fstat-verify it's still a regular file, hold a shared
        lock for the read.
        """
        check = self.validate(path_str)
        if not check.valid:
            raise PermissionError(f"PathGuard REJECT: {check.reason}")

        p = self._lexical_absolute(path_str)

        if hasattr(os, "O_NOFOLLOW"):
            flags = os.O_RDONLY | os.O_NOFOLLOW
            fd = os.open(str(p), flags)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    os.close(fd)
                    raise PermissionError("PathGuard REJECT: NOT_A_REGULAR_FILE")
                if hasattr(os, "LOCK_SH"):
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_SH)
                return os.fdopen(fd, mode)
            except Exception:
                os.close(fd)
                raise
        else:
            fd = os.open(str(p), os.O_RDONLY)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    os.close(fd)
                    raise PermissionError("PathGuard REJECT: NOT_A_REGULAR_FILE")
                return os.fdopen(fd, mode)
            except Exception:
                os.close(fd)
                raise

    def safe_read(self, path_str: str) -> bytes:
        """Read a file's full content with a check-then-use-then-verify
        TOCTOU sequence.
        """
        check = self.validate(path_str)
        if not check.valid:
            raise PermissionError(f"PathGuard REJECT: {check.reason}")

        with self.safe_open(path_str, "rb") as handle:
            data = handle.read()

        use = self.verify_no_toctou(path_str, check)
        if not use.valid:
            raise PermissionError(f"PathGuard TOCTOU REJECT: {use.reason}")

        return data

    def list_dir(self, path_str: str) -> list[str]:
        """List the names of regular files directly inside an allowed
        directory. Confined by the same allowlist/symlink checks as
        `validate` — `allow_dir=True` is used deliberately here.
        """
        check = self.validate(path_str, allow_dir=True)
        if not check.valid:
            raise PermissionError(f"PathGuard REJECT: {check.reason}")

        abs_path = self._lexical_absolute(path_str)
        if not abs_path.is_dir():
            raise PermissionError("PathGuard REJECT: NOT_A_DIRECTORY")

        names = []
        for entry in sorted(abs_path.iterdir()):
            if entry.is_symlink():
                continue
            if entry.is_file():
                names.append(entry.name)
        return names


class SecurityException(Exception):
    """Raised for a PathGuard security violation."""

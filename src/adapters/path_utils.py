"""Filesystem path security, traversal prevention, and symlink escape detection."""

from __future__ import annotations

import os
from pathlib import Path

from src.core.exceptions import PathTraversalError


def resolve_safe_path(root_dir: Path | str, relative_path: Path | str) -> Path:
    """
    Safely resolve a target path within a designated root directory.
    Strictly forbids path traversal, absolute path injection, null bytes, and symlink escapes.

    Args:
        root_dir: The allowed root boundary.
        relative_path: The untrusted subpath requested.

    Returns:
        Fully resolved, verified Path guaranteed to be inside root_dir.

    Raises:
        PathTraversalError: If path escapes or attempts to escape the root boundary.
    """
    path_str = str(relative_path).strip()
    if not path_str or "\0" in path_str:
        raise PathTraversalError("Invalid path: empty or contains null byte.")

    # Convert to Path
    root = Path(root_dir).resolve()

    # Reject absolute path strings that don't match root
    p = Path(path_str)
    if p.is_absolute():
        resolved_candidate = p.resolve()
        try:
            resolved_candidate.relative_to(root)
            candidate = resolved_candidate
        except ValueError:
            raise PathTraversalError(
                f"Absolute path escape attempt: '{path_str}' is outside sandbox root '{root}'."
            )
    else:
        # Check for explicit '..' traversal segments before resolution
        parts = p.parts
        if ".." in parts:
            # Check resolution
            candidate = (root / p).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                raise PathTraversalError(
                    f"Directory traversal escape attempt: '{path_str}' resolves outside sandbox root '{root}'."
                )
        else:
            candidate = (root / p).resolve()

    # Final containment verification
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PathTraversalError(
            f"Path containment violation: '{candidate}' is not inside '{root}'."
        )

    # Symlink escape verification (where symlinks are supported by filesystem)
    check_path = candidate
    while check_path != root and check_path != check_path.parent:
        if check_path.is_symlink():
            target = check_path.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                raise PathTraversalError(
                    f"Symlink escape attempt: '{check_path}' links outside sandbox root to '{target}'."
                )
        check_path = check_path.parent

    return candidate

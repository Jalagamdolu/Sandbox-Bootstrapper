"""SQLite database connection management and transaction context helpers."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from src.core.config import get_settings
from src.core.exceptions import DatabaseError


def configure_pragmas(conn: sqlite3.Connection, is_memory: bool = False) -> None:
    """Apply documented SQLite performance, concurrency, and integrity pragmas."""
    cursor = conn.cursor()
    try:
        # Enforce foreign key constraints strictly
        cursor.execute("PRAGMA foreign_keys = ON;")

        # Set busy timeout to 5000ms to handle concurrent lock contention on Windows
        cursor.execute("PRAGMA busy_timeout = 5000;")

        # Enable Write-Ahead Logging (WAL) mode for high read/write concurrency
        # In-memory databases do not support WAL mode
        if not is_memory:
            cursor.execute("PRAGMA journal_mode = WAL;")

        cursor.close()
    except sqlite3.Error as e:
        cursor.close()
        raise DatabaseError(f"Failed to configure SQLite PRAGMAs: {e}") from e


def resolve_db_path(db_path: Path | str | None = None) -> str:
    """Resolve database path string, defaulting to settings.database_path."""
    if db_path is None:
        return str(get_settings().database_path)
    return str(db_path)


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """
    Establish a connection to the SQLite database with configured PRAGMAs.

    Args:
        db_path: Optional explicit database path. If None, uses settings.database_path.

    Returns:
        Configured sqlite3.Connection instance with row_factory=sqlite3.Row.
    """
    target_path = resolve_db_path(db_path)

    is_memory = target_path == ":memory:"

    # Ensure parent directory exists for file-based database
    if not is_memory:
        parent_dir = Path(target_path).parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(target_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        configure_pragmas(conn, is_memory=is_memory)
        return conn
    except sqlite3.Error as e:
        raise DatabaseError(f"Could not connect to database '{target_path}': {e}") from e


@contextmanager
def transaction_scope(conn: sqlite3.Connection) -> Generator[sqlite3.Cursor, None, None]:
    """
    Context manager providing transactional execution with automatic rollback on failure.

    Yields:
        A database cursor within an active transaction.
    """
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise DatabaseError(f"Transaction aborted and rolled back due to error: {exc}") from exc
    finally:
        cursor.close()

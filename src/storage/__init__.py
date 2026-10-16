"""Developer Sandbox Bootstrapper - Storage Package."""

from src.storage.connection import get_connection, transaction_scope


def initialize_database(*args, **kwargs):
    from src.storage.db_init import initialize_database as _init

    return _init(*args, **kwargs)


__all__ = ["get_connection", "initialize_database", "transaction_scope"]

"""
Reference SQLite adapter for single-use TOTP consumption.

This is a small, dependency-free implementation of
:class:`pyotp.replay.TOTPConsumptionStore`. It demonstrates the real
transaction boundary that replay protection requires: the generation check,
the replay check and the counter update run as one atomic ``UPDATE``/
``INSERT`` inside a single database transaction, so two verifiers on separate
connections (and therefore separate processes or hosts sharing the file) can
consume the same OTP at most once.

The table stores only consumption state - the account identifier, the key
generation and the last consumed timecode. Plaintext TOTP secrets are never
written to it. A greater stored generation means the presented key is stale
(a rotated-out secret); a smaller stored generation records a key rotation and
resets the per-generation replay state.

Schema::

    CREATE TABLE totp_consumption (
        account_id        TEXT PRIMARY KEY,
        key_generation    INTEGER NOT NULL,
        last_timecode     INTEGER NOT NULL
    )

The adapter works with any DB-API 2.0 connection whose ``cursor().execute``
accepts ``?`` placeholders (the stdlib :mod:`sqlite3` module being the
obvious example). It does not hold Python locks: concurrency safety comes from
the database's own transactions.
"""

import sqlite3
from typing import Any, Optional

from ..replay import (
    ReplayedOTPError,
    StaleKeyGenerationError,
    TOTPStorageError,
)

#: Name of the table managed by this adapter.
DEFAULT_TABLE = "totp_consumption"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS {table} (
    account_id     TEXT PRIMARY KEY,
    key_generation INTEGER NOT NULL,
    last_timecode  INTEGER NOT NULL
)
"""

_SELECT_SQL = "SELECT key_generation, last_timecode FROM {table} WHERE account_id = ?"

_UPDATE_SQL = "UPDATE {table} SET last_timecode = ? WHERE account_id = ? AND key_generation = ? AND last_timecode < ?"

_ROTATE_SQL = "UPDATE {table} SET key_generation = ?, last_timecode = ? WHERE account_id = ? AND key_generation < ?"

_INSERT_SQL = "INSERT INTO {table} (account_id, key_generation, last_timecode) VALUES (?, ?, ?)"


class SQLiteTOTPStore:
    """
    SQLite-backed :class:`~pyotp.replay.TOTPConsumptionStore`.

    :param connection: an open :class:`sqlite3.Connection` (or compatible
        DB-API connection). Each verifier should use its own connection; the
        atomicity guarantee holds across connections and processes.
    :param table: table name holding consumption state. It is created on
        construction if it does not exist. Only identifiers controlled by the
        application are interpolated, never user input.
    :param busy_timeout: milliseconds SQLite waits on a locked database before
        raising ``OperationalError`` (defaults to 5 seconds).
    """

    def __init__(self, connection: Any, table: str = DEFAULT_TABLE, busy_timeout: int = 5000) -> None:
        self.connection = connection
        self.table = table
        # Identifier sanity check: the table name is concatenated into DDL/DML,
        # so it must be a plain identifier rather than arbitrary input.
        if not table.replace("_", "").isalnum():
            raise ValueError("table must be a simple SQL identifier")
        try:
            connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout)}")
            connection.execute(_CREATE_TABLE_SQL.format(table=self.table))
            connection.commit()
        except sqlite3.Error as exc:
            raise TOTPStorageError("failed to initialize TOTP consumption table") from exc

    def consume(self, account_id: str, key_generation: int, timecode: int) -> None:
        """
        Atomically confirm the generation and advance the consumed timecode.

        All checks and the write happen in a single transaction. With two
        connections racing over the same ``(account_id, key_generation)``,
        SQLite serializes the writes: the first transaction commits the new
        timecode, the second sees ``last_timecode >= timecode`` and raises
        :class:`~pyotp.replay.ReplayedOTPError`. A rolled-back or failed
        transaction raises :class:`~pyotp.replay.TOTPStorageError` and can
        never report success.
        """
        try:
            # BEGIN a transaction explicitly. sqlite3 in default (deferred)
            # mode opens the write transaction on the first DML statement;
            # committing or rolling back here keeps the whole check-and-update
            # sequence atomic regardless of the connection's isolation setup.
            self.connection.execute("BEGIN IMMEDIATE")
            cursor = self.connection.execute(_SELECT_SQL.format(table=self.table), (account_id,))
            row: Optional[tuple] = cursor.fetchone()

            if row is None:
                # First time this account consumes anything: record the state.
                self.connection.execute(_INSERT_SQL.format(table=self.table), (account_id, key_generation, timecode))
            else:
                stored_generation, last_timecode = row
                if stored_generation > key_generation:
                    # The presented secret generation has been rotated out.
                    self.connection.rollback()
                    raise StaleKeyGenerationError(account_id, key_generation, timecode, stored_generation)
                if stored_generation == key_generation:
                    if last_timecode >= timecode:
                        # An equal or later timecode was already consumed: replay.
                        self.connection.rollback()
                        raise ReplayedOTPError(account_id, key_generation, timecode)

                    # Conditional update: even if another transaction
                    # interleaved between the SELECT and the UPDATE, the WHERE
                    # clause rechecks generation and monotonicity at write
                    # time. rowcount == 0 means we lost that race and must
                    # treat it as a replay.
                    cursor = self.connection.execute(
                        _UPDATE_SQL.format(table=self.table),
                        (timecode, account_id, key_generation, timecode),
                    )
                    if cursor.rowcount != 1:
                        self.connection.rollback()
                        raise ReplayedOTPError(account_id, key_generation, timecode)
                else:
                    # A newer, monotonically greater generation: rotate the key
                    # generation and reset the consumed timecode in one guarded
                    # UPDATE. The WHERE clause makes a concurrent rotation a
                    # no-op rather than a blind overwrite.
                    cursor = self.connection.execute(
                        _ROTATE_SQL.format(table=self.table),
                        (key_generation, timecode, account_id, key_generation),
                    )
                    if cursor.rowcount != 1:
                        self.connection.rollback()
                        raise StaleKeyGenerationError(account_id, key_generation, timecode, stored_generation)

            self.connection.commit()
        except (ReplayedOTPError, StaleKeyGenerationError):
            raise
        except sqlite3.Error as exc:
            try:
                self.connection.rollback()
            except sqlite3.Error:
                pass
            raise TOTPStorageError(
                "SQLite transaction failed while recording TOTP consumption",
                account_id=account_id,
                key_generation=key_generation,
                timecode=timecode,
            ) from exc

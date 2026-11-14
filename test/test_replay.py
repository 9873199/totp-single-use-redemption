#!/usr/bin/env python
"""
Tests for single-use TOTP consumption (pyotp.replay) and the SQLite adapter.
"""

import datetime
import logging
import os
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pyotp  # noqa
from pyotp import replay as replay_mod  # noqa
from pyotp.contrib.sqlite_store import DEFAULT_TABLE, SQLiteTOTPStore  # noqa
from pyotp.replay import (  # noqa
    InvalidOTPError,
    ReplayedOTPError,
    StaleKeyGenerationError,
    TOTPConsumeError,
    TOTPError,
    TOTPStorageError,
    consume_totp,
)

# Deterministic fixture: for this secret, timecodes 5 and 6 produce the same
# 6-digit short code (found with a seeded search, not by chance at runtime).
COLLISION_SECRET = "IRLPMGD2P5MDHFBUD3WESJGNJTQT3RHL"
COLLISION_CODE = "703699"  # valid at both timecode 5 and timecode 6

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class InMemoryStore:
    """Minimal TOTPConsumptionStore for single-threaded unit tests (no locks)."""

    def __init__(self):
        self.state = {}  # account_id -> (key_generation, last_timecode)
        self.calls = []

    def consume(self, account_id, key_generation, timecode):
        self.calls.append((account_id, key_generation, timecode))
        if account_id not in self.state:
            self.state[account_id] = (key_generation, timecode)
            return
        stored_generation, last_timecode = self.state[account_id]
        if stored_generation > key_generation:
            raise StaleKeyGenerationError(account_id, key_generation, timecode, stored_generation)
        if stored_generation == key_generation:
            if last_timecode >= timecode:
                raise ReplayedOTPError(account_id, key_generation, timecode)
            self.state[account_id] = (key_generation, timecode)
            return
        # Newer generation: key rotation resets the replay state.
        self.state[account_id] = (key_generation, timecode)


class ExplodingStore:
    """Store that fails the test if the library touches it."""

    def consume(self, account_id, key_generation, timecode):
        raise AssertionError("storage must not be contacted when the OTP does not match")


class FailingStore:
    """Store whose backend raises an arbitrary, non-domain exception."""

    def __init__(self, exc):
        self.exc = exc

    def consume(self, account_id, key_generation, timecode):
        raise self.exc


class RecordingTOTP(pyotp.TOTP):
    """TOTP subclass recording every counter handed to generate_otp."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.generated_counters = []

    def generate_otp(self, input):
        self.generated_counters.append(input)
        return super().generate_otp(input)


class _CursorWrapper:
    """Cursor exposing a settable rowcount while delegating result access."""

    def __init__(self, cursor, rowcount=None):
        self._cursor = cursor
        self._rowcount = cursor.rowcount if rowcount is None else rowcount

    @property
    def rowcount(self):
        return self._rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class _ZeroRowcountConnection:
    """
    Connection wrapper that reports rowcount 0 for a specific UPDATE.

    This simulates losing the write race: the guarded UPDATE's WHERE clause no
    longer matches because another transaction advanced the row first. All
    other statements behave exactly like the wrapped connection.
    """

    def __init__(self, inner, update_fragment):
        self.inner = inner
        self.update_fragment = update_fragment

    def execute(self, sql, params=()):
        cursor = self.inner.execute(sql, params)
        if isinstance(sql, str) and self.update_fragment in sql:
            return _CursorWrapper(cursor, rowcount=0)
        return cursor

    def commit(self):
        return self.inner.commit()

    def rollback(self):
        return self.inner.rollback()


class ConsumeTOTPUnitTest(unittest.TestCase):
    def setUp(self):
        self.totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        self.for_time = datetime.datetime.fromtimestamp(1297553958)
        # OTP valid at that frozen time (see the existing TOTP test fixtures).
        self.good_otp = self.totp.at(self.for_time)

    def test_success_returns_matched_timecode_and_persists(self):
        store = InMemoryStore()
        result = consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        expected = self.totp.timecode(self.for_time)
        self.assertEqual(result, expected)
        self.assertEqual(store.state["alice"], (0, expected))
        self.assertEqual(store.calls, [("alice", 0, expected)])

    def test_invalid_otp_raises_and_never_touches_store(self):
        with self.assertRaises(InvalidOTPError) as cm:
            consume_totp(self.totp, "000000", "alice", 0, ExplodingStore(), for_time=self.for_time)
        self.assertEqual(cm.exception.code, TOTPError.INVALID_OTP)
        self.assertEqual(cm.exception.account_id, "alice")
        self.assertIsNone(cm.exception.timecode)

    def test_replay_within_same_generation(self):
        store = InMemoryStore()
        consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        with self.assertRaises(ReplayedOTPError) as cm:
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        self.assertEqual(cm.exception.code, TOTPError.REPLAYED_OTP)
        self.assertEqual(cm.exception.account_id, "alice")
        self.assertEqual(cm.exception.key_generation, 0)
        self.assertEqual(cm.exception.timecode, self.totp.timecode(self.for_time))
        # State must be unchanged after the rejected attempt.
        self.assertEqual(store.state["alice"], (0, self.totp.timecode(self.for_time)))

    def test_later_timecode_same_generation_consumes(self):
        store = InMemoryStore()
        first = self.for_time
        later = self.for_time + datetime.timedelta(seconds=self.totp.interval)
        consume_totp(self.totp, self.totp.at(first), "alice", 0, store, for_time=first)
        result = consume_totp(self.totp, self.totp.at(later), "alice", 0, store, for_time=later)
        self.assertEqual(result, self.totp.timecode(later))

    def test_clock_rollback_is_replay(self):
        # Clock moving backwards must not allow an older timecode to be
        # consumed after a newer one was already recorded.
        store = InMemoryStore()
        later = self.for_time + datetime.timedelta(seconds=self.totp.interval)
        consume_totp(self.totp, self.totp.at(later), "alice", 0, store, for_time=later)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)

    def test_key_rotation_accepts_new_generation_and_rejects_old_one(self):
        store = InMemoryStore()
        new_secret = pyotp.random_base32()
        new_totp = pyotp.TOTP(new_secret)

        # Generation 0 authenticates with the old key.
        consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)

        # Rotation: the same account presents generation 1 with the new key.
        rotated_otp = new_totp.at(self.for_time)
        consume_totp(new_totp, rotated_otp, "alice", 1, store, for_time=self.for_time)
        self.assertEqual(store.state["alice"], (1, new_totp.timecode(self.for_time)))

        # An old key (generation 0) is now stale even if its OTP is valid.
        with self.assertRaises(StaleKeyGenerationError) as cm:
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        self.assertEqual(cm.exception.code, TOTPError.KEY_GENERATION_STALE)
        self.assertEqual(cm.exception.stored_generation, 1)

    def test_stale_generation_from_first_contact(self):
        store = InMemoryStore()
        store.state["alice"] = (3, 50)
        with self.assertRaises(StaleKeyGenerationError):
            consume_totp(self.totp, self.good_otp, "alice", 2, store, for_time=self.for_time)
        self.assertEqual(store.state["alice"], (3, 50))

    def test_window_collision_selects_highest_timecode_single_consume(self):
        # The same short code is valid at timecodes 5 and 6. With the window
        # centered on timecode 6, both match; the highest (6) must be consumed
        # in a single store call rather than trying 5 first.
        totp = pyotp.TOTP(COLLISION_SECRET)
        store = InMemoryStore()
        for_time = datetime.datetime.fromtimestamp(6 * totp.interval)
        result = consume_totp(totp, COLLISION_CODE, "alice", 0, store, for_time=for_time, valid_window=1)
        self.assertEqual(result, 6)
        self.assertEqual(store.calls, [("alice", 0, 6)])

        # Re-presenting the same code at the lower timecode is now a replay:
        # 5 < 6 was implicitly consumed as well.
        for_time_5 = datetime.datetime.fromtimestamp(5 * totp.interval)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(totp, COLLISION_CODE, "alice", 0, store, for_time=for_time_5)

    def test_no_sequential_fallback_to_older_counter(self):
        # If the store rejects timecode 6 as a replay, the library must not
        # then attempt timecode 5 against the store to find one it accepts.
        totp = pyotp.TOTP(COLLISION_SECRET)
        store = InMemoryStore()
        store.state["alice"] = (0, 6)  # timecode 6 already consumed
        for_time = datetime.datetime.fromtimestamp(6 * totp.interval)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(totp, COLLISION_CODE, "alice", 0, store, for_time=for_time, valid_window=1)
        self.assertEqual(store.calls, [("alice", 0, 6)])  # exactly one attempt, at 6

    def test_negative_counters_skipped_but_timecode_zero_is_valid(self):
        totp = RecordingTOTP(RFC_SECRET)
        store = InMemoryStore()
        epoch = datetime.datetime.fromtimestamp(0)
        code_at_zero = pyotp.TOTP(RFC_SECRET).generate_otp(0)

        result = consume_totp(totp, code_at_zero, "alice", 0, store, for_time=epoch, valid_window=1)
        self.assertEqual(result, 0)
        # 0 is a real consumed counter, distinguishable from False/None.
        self.assertIsInstance(result, int)
        self.assertFalse(result is False)
        self.assertEqual(store.state["alice"], (0, 0))
        # The window spans -1, 0, 1; -1 must never reach OTP generation.
        self.assertNotIn(-1, totp.generated_counters)
        self.assertIn(0, totp.generated_counters)

    def test_negative_counter_skipped_on_full_window_scan(self):
        # With an invalid code at the epoch, the whole window (-1, 0, 1) is
        # scanned before giving up; the negative candidate must be skipped
        # rather than passed to OTP generation, and no store call happens.
        totp = RecordingTOTP(RFC_SECRET)
        epoch = datetime.datetime.fromtimestamp(0)
        with self.assertRaises(InvalidOTPError):
            consume_totp(totp, "000000", "alice", 0, ExplodingStore(), for_time=epoch, valid_window=1)
        self.assertNotIn(-1, totp.generated_counters)
        self.assertEqual(sorted(totp.generated_counters), [0, 1])

    def test_default_for_time_uses_current_clock(self):
        store = InMemoryStore()
        result = consume_totp(self.totp, self.totp.now(), "alice", 0, store)
        self.assertEqual(result, self.totp.timecode(datetime.datetime.now()))

    def test_integer_unix_timestamp_for_time(self):
        store = InMemoryStore()
        timestamp = 1297553958
        result = consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=timestamp)
        self.assertEqual(result, self.totp.timecode(datetime.datetime.fromtimestamp(timestamp)))

    def test_timecode_zero_replay_is_detected(self):
        totp = pyotp.TOTP(RFC_SECRET)
        store = InMemoryStore()
        epoch = datetime.datetime.fromtimestamp(0)
        code_at_zero = totp.generate_otp(0)
        consume_totp(totp, code_at_zero, "alice", 0, store, for_time=epoch)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(totp, code_at_zero, "alice", 0, store, for_time=epoch)

    def test_accounts_are_independent(self):
        store = InMemoryStore()
        consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        # Same OTP value against a different account is a fresh consumption.
        result = consume_totp(self.totp, self.good_otp, "bob", 0, store, for_time=self.for_time)
        self.assertEqual(result, self.totp.timecode(self.for_time))
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        # Bob's state is untouched by Alice's replay.
        self.assertEqual(store.state["bob"], (0, self.totp.timecode(self.for_time)))

    def test_unexpected_store_exception_becomes_storage_error(self):
        store = FailingStore(RuntimeError("backend down"))
        with self.assertRaises(TOTPStorageError) as cm:
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        self.assertEqual(cm.exception.code, TOTPError.STORAGE_FAILURE)
        self.assertIsInstance(cm.exception.__cause__, RuntimeError)
        # A storage failure must never be reported as success.
        self.assertIsInstance(cm.exception, TOTPConsumeError)

    def test_domain_errors_from_store_pass_through(self):
        store = FailingStore(ReplayedOTPError("alice", 0, 1))
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)

    def test_storage_error_passes_through(self):
        store = FailingStore(TOTPStorageError("commit failed"))
        with self.assertRaises(TOTPStorageError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)

    def test_argument_validation(self):
        store = InMemoryStore()
        with self.assertRaises(ValueError):
            consume_totp(self.totp, self.good_otp, "", 0, store, for_time=self.for_time)
        with self.assertRaises(ValueError):
            consume_totp(self.totp, self.good_otp, "alice", -1, store, for_time=self.for_time)
        with self.assertRaises(ValueError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time, valid_window=-1)

    def test_uses_constant_time_comparison(self):
        calls = []
        original = replay_mod.utils.strings_equal

        def spy(s1, s2):
            calls.append((s1, s2))
            return original(s1, s2)

        replay_mod.utils.strings_equal = spy
        try:
            consume_totp(self.totp, self.good_otp, "alice", 0, InMemoryStore(), for_time=self.for_time)
        finally:
            replay_mod.utils.strings_equal = original
        self.assertTrue(calls)
        for s1, s2 in calls:
            self.assertIsInstance(s1, str)
            self.assertIsInstance(s2, str)

    def test_no_secret_or_otp_in_logs(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Capture()
        logger = logging.getLogger("pyotp")
        logger.addHandler(handler)
        try:
            store = InMemoryStore()
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
            with self.assertRaises(InvalidOTPError):
                consume_totp(self.totp, "000000", "alice", 0, ExplodingStore(), for_time=self.for_time)
        finally:
            logger.removeHandler(handler)
        for record in records:
            rendered = record.getMessage()
            self.assertNotIn(self.good_otp, rendered)
            self.assertNotIn(self.totp.secret, rendered)

    def test_existing_verify_semantics_unchanged(self):
        # verify() remains a pure cryptographic check: it still succeeds on
        # repeat and never consumes anything through the replay machinery.
        self.assertTrue(self.totp.verify(self.good_otp, self.for_time))
        self.assertTrue(self.totp.verify(self.good_otp, self.for_time))
        self.assertFalse(self.totp.verify("000000", self.for_time))
        self.assertEqual(
            self.totp.verify_and_get_timecode(self.good_otp, self.for_time), self.totp.timecode(self.for_time)
        )
        self.assertFalse(self.totp.verify_and_get_timecode("000000", self.for_time))


class SQLiteStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "totp_test.db")
        # check_same_thread=False so the independent connections can be driven
        # from worker threads; each verifier still has its own connection.
        self.conn_a = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn_b = sqlite3.connect(self.db_path, check_same_thread=False)
        self.store_a = SQLiteTOTPStore(self.conn_a, busy_timeout=5000)
        self.store_b = SQLiteTOTPStore(self.conn_b, busy_timeout=5000)
        self.totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        self.for_time = datetime.datetime.fromtimestamp(1297553958)
        self.good_otp = self.totp.at(self.for_time)
        self.timecode = self.totp.timecode(self.for_time)

    def tearDown(self):
        self.conn_a.close()
        self.conn_b.close()
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _row(self, conn, account_id="alice"):
        return conn.execute(
            f"SELECT account_id, key_generation, last_timecode FROM {DEFAULT_TABLE} WHERE account_id = ?",
            (account_id,),
        ).fetchone()

    def test_first_consume_inserts_state(self):
        result = consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        self.assertEqual(result, self.timecode)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode))

    def test_table_never_stores_secret_or_otp(self):
        consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        rows = self.conn_a.execute(f"SELECT * FROM {DEFAULT_TABLE}").fetchall()
        columns = {row[1] for row in self.conn_a.execute(f"PRAGMA table_info({DEFAULT_TABLE})").fetchall()}
        self.assertEqual(columns, {"account_id", "key_generation", "last_timecode"})
        for row in rows:
            joined = "|".join(str(value) for value in row)
            self.assertNotIn(self.totp.secret, joined)
            self.assertNotIn(self.good_otp, joined)

    def test_deterministic_race_two_connections_one_success(self):
        # Verifier A opens its write transaction and records the consumption
        # but has not committed yet while verifier B attempts the same OTP on
        # an independent connection. A short busy timeout keeps the lock wait
        # deterministic and fast instead of blocking for seconds.
        store_b = SQLiteTOTPStore(self.conn_b, busy_timeout=100)
        self.conn_a.execute("BEGIN IMMEDIATE")
        self.conn_a.execute(
            f"INSERT INTO {DEFAULT_TABLE} (account_id, key_generation, last_timecode) VALUES (?, ?, ?)",
            ("alice", 0, self.timecode),
        )

        # B cannot acquire the write lock: this is a storage failure, never a
        # success, and B writes nothing.
        with self.assertRaises(TOTPStorageError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store_b, for_time=self.for_time)
        self.assertIsNone(self._row(self.conn_b))

        # A commits: exactly one verifier has consumed the OTP. When B retries,
        # the atomic check finds last_timecode >= its timecode: replay.
        self.conn_a.commit()
        with self.assertRaises(ReplayedOTPError) as cm:
            consume_totp(self.totp, self.good_otp, "alice", 0, store_b, for_time=self.for_time)
        self.assertEqual(cm.exception.code, TOTPError.REPLAYED_OTP)
        self.assertEqual(self._row(self.conn_b), ("alice", 0, self.timecode))

    def test_concurrent_consumers_exactly_one_wins(self):
        # Invariant under real concurrency: across many attempts on separate
        # connections, the same OTP yields exactly one success.
        outcomes = []
        barrier = threading.Barrier(2)

        def verifier(store):
            barrier.wait()
            try:
                consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
                outcomes.append("ok")
            except ReplayedOTPError:
                outcomes.append("replay")
            except TOTPStorageError:
                outcomes.append("storage")

        for _ in range(10):
            outcomes.clear()
            # Fresh state every round so each pair genuinely races to insert.
            self.conn_a.execute(f"DELETE FROM {DEFAULT_TABLE} WHERE account_id = ?", ("alice",))
            self.conn_a.commit()
            t1 = threading.Thread(target=verifier, args=(self.store_a,))
            t2 = threading.Thread(target=verifier, args=(self.store_b,))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            self.assertEqual(sorted(outcomes).count("ok"), 1, outcomes)
            self.assertEqual(sorted(outcomes).count("replay"), 1, outcomes)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode))

    def test_replay_on_committed_row(self):
        consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, self.store_b, for_time=self.for_time)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode))

    def test_same_generation_advances_timecode_with_guarded_update(self):
        # Pre-existing row on the same generation with a smaller timecode:
        # consumption succeeds via the guarded UPDATE (rowcount == 1).
        self.conn_a.execute(
            f"INSERT INTO {DEFAULT_TABLE} (account_id, key_generation, last_timecode) VALUES (?, ?, ?)",
            ("alice", 0, self.timecode - 2),
        )
        self.conn_a.commit()
        result = consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        self.assertEqual(result, self.timecode)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode))
        # Advancing again with an older timecode is a replay.
        older = self.for_time - datetime.timedelta(seconds=self.totp.interval)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.totp.at(older), "alice", 0, self.store_b, for_time=older)

    def test_clock_rollback_rejected(self):
        later = self.for_time + datetime.timedelta(seconds=self.totp.interval)
        consume_totp(self.totp, self.totp.at(later), "alice", 0, self.store_a, for_time=later)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, self.store_b, for_time=self.for_time)

    def test_key_rotation_and_stale_generation(self):
        consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        new_totp = pyotp.TOTP(pyotp.random_base32())
        rotated_otp = new_totp.at(self.for_time)
        consume_totp(new_totp, rotated_otp, "alice", 1, self.store_b, for_time=self.for_time)
        self.assertEqual(self._row(self.conn_a), ("alice", 1, new_totp.timecode(self.for_time)))

        with self.assertRaises(StaleKeyGenerationError) as cm:
            consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        self.assertEqual(cm.exception.stored_generation, 1)
        # The rejected attempt must not have changed the row.
        self.assertEqual(self._row(self.conn_b), ("alice", 1, new_totp.timecode(self.for_time)))

    def test_window_collision_consumes_highest_timecode(self):
        totp = pyotp.TOTP(COLLISION_SECRET)
        for_time = datetime.datetime.fromtimestamp(6 * totp.interval)
        result = consume_totp(totp, COLLISION_CODE, "alice", 0, self.store_a, for_time=for_time, valid_window=1)
        self.assertEqual(result, 6)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, 6))
        for_time_5 = datetime.datetime.fromtimestamp(5 * totp.interval)
        with self.assertRaises(ReplayedOTPError):
            consume_totp(totp, COLLISION_CODE, "alice", 0, self.store_b, for_time=for_time_5)

    def test_commit_failure_is_storage_error_and_not_success(self):
        # Simulate a backend that fails while the transaction is in flight.
        class BrokenConnection:
            def __init__(self, inner):
                self.inner = inner
                # Construction commits (table creation) must still succeed;
                # the failure is armed only once the verifier starts running.
                self.fail_commit = False

            def execute(self, sql, params=()):
                return self.inner.execute(sql, params)

            def commit(self):
                if self.fail_commit:
                    raise sqlite3.OperationalError("disk I/O error")
                return self.inner.commit()

            def rollback(self):
                return self.inner.rollback()

        broken = BrokenConnection(self.conn_a)
        store = SQLiteTOTPStore(broken, busy_timeout=5000)
        broken.fail_commit = True
        with self.assertRaises(TOTPStorageError):
            consume_totp(self.totp, self.good_otp, "carol", 0, store, for_time=self.for_time)
        # Nothing durably consumed: a retry on a healthy connection succeeds.
        result = consume_totp(self.totp, self.good_otp, "carol", 0, self.store_b, for_time=self.for_time)
        self.assertEqual(result, self.timecode)

    def test_closed_connection_is_storage_error(self):
        conn = sqlite3.connect(self.db_path)
        store = SQLiteTOTPStore(conn)
        conn.close()
        with self.assertRaises(TOTPStorageError):
            consume_totp(self.totp, self.good_otp, "dave", 0, store, for_time=self.for_time)

    def test_table_name_must_be_simple_identifier(self):
        for bad_name in ["bad name", "table;DROP TABLE x", "totp-consumption"]:
            with self.assertRaises(ValueError):
                SQLiteTOTPStore(self.conn_a, table=bad_name)

    def test_table_initialization_failure_is_storage_error(self):
        class FailingInitConnection:
            def __init__(self, inner):
                self.inner = inner

            def execute(self, sql, params=()):
                if sql.lstrip().upper().startswith("CREATE TABLE"):
                    raise sqlite3.OperationalError("cannot create table")
                return self.inner.execute(sql, params)

            def commit(self):
                return self.inner.commit()

            def rollback(self):
                return self.inner.rollback()

        with self.assertRaises(TOTPStorageError):
            SQLiteTOTPStore(FailingInitConnection(self.conn_a))

    def test_lost_update_race_on_same_generation_is_replay(self):
        # If the guarded UPDATE matches no row (a concurrent transaction won
        # the write), the adapter must treat it as a replay rather than
        # success, and roll the transaction back.
        self.conn_a.execute(
            f"INSERT INTO {DEFAULT_TABLE} (account_id, key_generation, last_timecode) VALUES (?, ?, ?)",
            ("alice", 0, self.timecode - 1),
        )
        self.conn_a.commit()

        store = SQLiteTOTPStore(_ZeroRowcountConnection(self.conn_a, "SET last_timecode"))
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, store, for_time=self.for_time)
        # The rolled-back attempt leaves the original row untouched.
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode - 1))

    def test_lost_rotation_race_is_stale_generation(self):
        # A guarded rotation UPDATE matching no row means another rotation won;
        # the adapter reports a stale generation and rolls back.
        self.conn_a.execute(
            f"INSERT INTO {DEFAULT_TABLE} (account_id, key_generation, last_timecode) VALUES (?, ?, ?)",
            ("alice", 0, self.timecode),
        )
        self.conn_a.commit()

        new_totp = pyotp.TOTP(pyotp.random_base32())
        store = SQLiteTOTPStore(_ZeroRowcountConnection(self.conn_a, "SET key_generation"))
        with self.assertRaises(StaleKeyGenerationError):
            consume_totp(new_totp, new_totp.at(self.for_time), "alice", 1, store, for_time=self.for_time)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, self.timecode))

    def test_different_accounts_do_not_interfere(self):
        consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        consume_totp(self.totp, self.good_otp, "bob", 0, self.store_b, for_time=self.for_time)
        self.assertEqual(self._row(self.conn_a, "alice"), ("alice", 0, self.timecode))
        self.assertEqual(self._row(self.conn_a, "bob"), ("bob", 0, self.timecode))
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "alice", 0, self.store_a, for_time=self.for_time)
        # Bob's identical OTP remains consumable exactly once on its own row.
        with self.assertRaises(ReplayedOTPError):
            consume_totp(self.totp, self.good_otp, "bob", 0, self.store_b, for_time=self.for_time)

    def test_epoch_timecode_zero_roundtrip(self):
        totp = pyotp.TOTP(RFC_SECRET)
        epoch = datetime.datetime.fromtimestamp(0)
        code = totp.generate_otp(0)
        result = consume_totp(totp, code, "alice", 0, self.store_a, for_time=epoch, valid_window=1)
        self.assertEqual(result, 0)
        self.assertEqual(self._row(self.conn_a), ("alice", 0, 0))
        with self.assertRaises(ReplayedOTPError):
            consume_totp(totp, code, "alice", 0, self.store_b, for_time=epoch, valid_window=1)

    def test_invalid_otp_does_not_open_store_transaction(self):
        with self.assertRaises(InvalidOTPError):
            consume_totp(self.totp, "000000", "alice", 0, self.store_a, for_time=self.for_time)
        self.assertIsNone(self._row(self.conn_b))


if __name__ == "__main__":
    unittest.main()

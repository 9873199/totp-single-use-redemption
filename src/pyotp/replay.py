"""
Single-use (replay-protected) TOTP verification.

``TOTP.verify`` and ``TOTP.verify_and_get_timecode`` only prove that an OTP
value is cryptographically correct for some timecode. They do not consume the
OTP: if the same value is submitted against two login services at the same
time, both services see a valid value and both may accept it. Closing that gap
requires an atomic compare-and-update in a shared store.

This module provides that boundary as :func:`consume_totp`. The library keeps
no account dictionary and holds no locks of its own: a Python lock cannot
synchronize separate processes or machines. Instead, the caller supplies a
:class:`TOTPConsumptionStore` backed by a real transactional system (a
database, a compare-and-swap key-value store, etc.). The store is only touched
*after* the OTP has matched cryptographically, and it must atomically confirm
that the key generation is still the active one and that the matching
timecode is strictly greater than the last consumed timecode before recording
it. Any storage failure is surfaced as an error, never as a success.

Error taxonomy (see :class:`TOTPError`):

* :class:`InvalidOTPError` - the value did not match any timecode in the
  validity window. The store is not called.
* :class:`ReplayedOTPError` - the value matched, but an equal or higher
  timecode for this account and key generation was already consumed.
* :class:`StaleKeyGenerationError` - the value matched, but the presented key
  generation is not the generation the store currently holds for the account
  (a rotated or otherwise superseded key).
* :class:`TOTPStorageError` - the store could not complete the atomic
  consumption. Authentication must be treated as failed/unknown, never
  successful.

This module never logs secrets or OTP values, and all OTP comparisons go
through :func:`pyotp.utils.strings_equal`, which uses constant-time comparison.
"""

import datetime
from enum import Enum
from typing import Optional, Protocol, Union, runtime_checkable

from . import utils
from .totp import TOTP


class TOTPError(Enum):
    """Machine-readable error codes for single-use TOTP consumption."""

    #: The OTP did not match any timecode inside the validity window.
    INVALID_OTP = "invalid_otp"
    #: A matching OTP was already consumed for this account/key generation.
    REPLAYED_OTP = "replayed_otp"
    #: The presented key generation is not the one currently held by the store.
    KEY_GENERATION_STALE = "key_generation_stale"
    #: The store failed to atomically record the consumption.
    STORAGE_FAILURE = "storage_failure"


class TOTPConsumeError(Exception):
    """
    Base class for failures raised by :func:`consume_totp`.

    :ivar code: machine-readable :class:`TOTPError` discriminator
    :ivar account_id: account identifier supplied by the caller, when available
    :ivar key_generation: key generation supplied by the caller, when available
    :ivar timecode: the matched timecode, when cryptographic matching had
        succeeded (never set for :class:`InvalidOTPError`)
    """

    def __init__(
        self,
        code: TOTPError,
        message: str,
        *,
        account_id: Optional[str] = None,
        key_generation: Optional[int] = None,
        timecode: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.account_id = account_id
        self.key_generation = key_generation
        self.timecode = timecode


class InvalidOTPError(TOTPConsumeError):
    """The submitted value is not a valid OTP for any timecode in the window."""

    def __init__(self, account_id: Optional[str] = None) -> None:
        super().__init__(
            TOTPError.INVALID_OTP,
            "OTP did not match any timecode in the validity window",
            account_id=account_id,
        )


class ReplayedOTPError(TOTPConsumeError):
    """A matching OTP for an equal or later timecode was already consumed."""

    def __init__(self, account_id: str, key_generation: int, timecode: int) -> None:
        super().__init__(
            TOTPError.REPLAYED_OTP,
            "OTP has already been consumed for this account and key generation",
            account_id=account_id,
            key_generation=key_generation,
            timecode=timecode,
        )


class StaleKeyGenerationError(TOTPConsumeError):
    """The presented key generation does not match the stored generation."""

    def __init__(self, account_id: str, key_generation: int, timecode: int, stored_generation: int) -> None:
        super().__init__(
            TOTPError.KEY_GENERATION_STALE,
            "Key generation is not the active generation for this account",
            account_id=account_id,
            key_generation=key_generation,
            timecode=timecode,
        )
        #: Generation currently recorded for the account in the store.
        self.stored_generation = stored_generation


class TOTPStorageError(TOTPConsumeError):
    """
    The store could not atomically record the consumption.

    The authentication outcome is unknown at best; callers must never treat it
    as a success.
    """

    def __init__(
        self,
        message: str,
        *,
        account_id: Optional[str] = None,
        key_generation: Optional[int] = None,
        timecode: Optional[int] = None,
    ) -> None:
        super().__init__(
            TOTPError.STORAGE_FAILURE,
            message,
            account_id=account_id,
            key_generation=key_generation,
            timecode=timecode,
        )


@runtime_checkable
class TOTPConsumptionStore(Protocol):
    """
    Storage contract for single-use TOTP consumption.

    Implementations back the per-account consumption state with a real
    transactional system. They must not keep plaintext OTP secrets; only the
    account identifier, the key generation and the last consumed timecode are
    needed. In-process locks are not an acceptable implementation because they
    do not coordinate separate processes or hosts.

    The method must complete the following as one atomic, durable operation:

    1. If no state exists for ``account_id``, record
       ``(key_generation, timecode)`` and return.
    2. If the stored key generation is greater than ``key_generation``, raise
       :class:`StaleKeyGenerationError` without modifying the state.
    3. If the stored key generation equals ``key_generation`` and the stored
       timecode is greater than or equal to ``timecode``, raise
       :class:`ReplayedOTPError` without modifying the state.
    4. If the stored key generation equals ``key_generation`` and the stored
       timecode is smaller, store ``timecode`` and return.
    5. If the stored key generation is smaller than ``key_generation``, the
       secret was rotated: record the new generation and timecode, resetting
       the per-generation replay state, and return.

    Any failure to perform that atomically must be raised as an exception
    (preferably :class:`TOTPStorageError`); returning normally means the
    consumption was durably committed.
    """

    def consume(self, account_id: str, key_generation: int, timecode: int) -> None: ...


def _match_highest_timecode(totp: TOTP, otp: str, for_time: datetime.datetime, valid_window: int) -> Optional[int]:
    """
    Return the highest timecode in the window whose OTP matches ``otp``.

    Candidates are scanned from the highest counter downwards so that, when two
    counters in the window happen to produce the same short code, the largest
    matching counter is selected and the store is touched exactly once.

    Negative timecodes are skipped: near the Unix epoch the window can extend
    below zero, but a negative counter is not a valid TOTP input. Timecode 0
    itself is valid and must be distinguishable from ``False``/``None``.
    """
    base_timecode = totp.timecode(for_time)
    for offset in range(valid_window, -valid_window - 1, -1):
        candidate = base_timecode + offset
        if candidate < 0:
            continue
        if utils.strings_equal(str(otp), str(totp.generate_otp(candidate))):
            return candidate
    return None


def consume_totp(
    totp: TOTP,
    otp: str,
    account_id: str,
    key_generation: int,
    store: TOTPConsumptionStore,
    for_time: Optional[Union[int, datetime.datetime]] = None,
    valid_window: int = 0,
) -> int:
    """
    Verify a TOTP value and consume it exactly once.

    The OTP is first checked cryptographically over the validity window using
    constant-time comparison. Only when a match is found is ``store`` asked to
    atomically record the consumption for ``(account_id, key_generation)``.

    :param totp: the :class:`~pyotp.totp.TOTP` object for the account's
        current key generation
    :param otp: the OTP value submitted by the user
    :param account_id: stable account identifier used as the storage key
    :param key_generation: monotonically increasing generation of the account's
        TOTP secret; bump it whenever the secret is rotated
    :param store: :class:`TOTPConsumptionStore` implementation
    :param for_time: time to verify at (defaults to now); accepts a datetime or
        a Unix timestamp, mirroring
        :meth:`~pyotp.totp.TOTP.verify_and_get_timecode`
    :param valid_window: extends the accepted counters to this many ticks
        before and after the current one
    :returns: the timecode that was matched and consumed
    :raises InvalidOTPError: if no timecode in the window matches
    :raises ReplayedOTPError: if an equal or higher timecode was already
        consumed for this account and key generation
    :raises StaleKeyGenerationError: if ``key_generation`` does not match the
        generation held by the store for this account
    :raises TOTPStorageError: if the store could not commit the consumption;
        this is never reported as success
    """
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("account_id must be a non-empty string")
    if not isinstance(key_generation, int) or key_generation < 0:
        raise ValueError("key_generation must be a non-negative integer")
    if valid_window < 0:
        raise ValueError("valid_window cannot be negative")

    if for_time is None:
        for_time = datetime.datetime.now()
    elif isinstance(for_time, (float, int)):
        for_time = datetime.datetime.fromtimestamp(int(for_time))

    matched_timecode = _match_highest_timecode(totp, otp, for_time, valid_window)
    if matched_timecode is None:
        # Cryptographic failure: do not touch the store.
        raise InvalidOTPError(account_id=account_id)

    try:
        store.consume(account_id, key_generation, matched_timecode)
    except TOTPConsumeError:
        # Domain errors (replay, stale generation, pre-wrapped storage errors)
        # carry the exact semantics; pass them through unchanged.
        raise
    except Exception as exc:
        # A store that raises an unexpected exception must never look like a
        # successful authentication.
        raise TOTPStorageError(
            "TOTP consumption storage failed; the authentication must not be treated as successful",
            account_id=account_id,
            key_generation=key_generation,
            timecode=matched_timecode,
        ) from exc

    return matched_timecode

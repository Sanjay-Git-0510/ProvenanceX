"""Ownership of a running scan: claim tokens, write fencing and heartbeats (audit finding M2).

A runner that claims a scan gets a fresh `claim_token`. While it runs the scan:

* Every commit its session makes is fenced: `before_commit` re-reads the scan row with
  SELECT ... FOR UPDATE and aborts the commit with `ClaimLost` unless the stored token is still
  this runner's. The row lock serializes the check against stale recovery, which replaces the
  token in its own locked transaction, so a write either lands before recovery or not at all.
  This covers every write the pipeline makes (stage updates, provenance, risk decision,
  sandbox run records, mark_completed, record_failure and the blockchain reservation that
  precedes any chain send) without each stage having to remember a check.
* A heartbeat thread renews `heartbeat_at` with a conditional UPDATE on the token. If the
  update matches no row, the claim was replaced: the heartbeat sets `lost`, analyzer runs stop
  (app/analysis/docker_analyzer.py polls it) and the next commit fails.
* Lifecycle transitions are additionally conditional UPDATEs (`... WHERE claim_token = :token
  AND status = 'running'`), so a terminal state can be written once, by the current owner.

`ClaimLost` is sticky: once seen, every later commit on that session fails without a query.
Sessions without a bound claim (the API, tests that call a pipeline directly) are unaffected.
"""

import contextvars
import logging
import socket
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import event, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Scan, ScanStatus, utcnow

logger = logging.getLogger(__name__)

_FENCE_KEY = "provenancex_scan_claim"


class ClaimLost(Exception):  # noqa: N818 - a state, not an error condition of the caller
    """This runner no longer owns the scan. Nothing it does may change the scan any more."""

    def __init__(self, scan_id: UUID) -> None:
        super().__init__(f"Claim on scan {scan_id} was lost or replaced")
        self.scan_id = scan_id


@dataclass
class ScanClaim:
    """One runner's ownership of one scan. `lost` is set once the claim is known to be gone."""

    scan_id: UUID
    token: UUID
    runner_id: str = ""
    lost: threading.Event = field(default_factory=threading.Event, compare=False, repr=False)

    def mark_lost(self) -> None:
        if not self.lost.is_set():
            logger.warning(
                "Scan %s: claim %s lost; this runner stops writing", self.scan_id, self.token
            )
        self.lost.set()


def new_token() -> UUID:
    return uuid.uuid4()


def default_runner_id(configured: str = "") -> str:
    return (configured or socket.gethostname() or "runner")[:128]


# The claim of the scan the current thread is running. The analyzer reads it to label its
# containers with the claim token and to stop a run once the claim is lost.
_current: contextvars.ContextVar[ScanClaim | None] = contextvars.ContextVar(
    "provenancex_current_claim", default=None
)


def current_claim() -> ScanClaim | None:
    return _current.get()


@contextmanager
def claim_context(claim: ScanClaim | None) -> Iterator[None]:
    reset = _current.set(claim)
    try:
        yield
    finally:
        _current.reset(reset)


# ----------------------------------------------------------------------------- fencing
def _check_claim(session: Session) -> None:
    claim: ScanClaim | None = session.info.get(_FENCE_KEY)
    if claim is None:
        return
    if claim.lost.is_set():
        raise ClaimLost(claim.scan_id)
    # Autoflushes the pending writes first, then locks the scan row until this commit ends.
    stored = session.execute(
        select(Scan.claim_token).where(Scan.id == claim.scan_id).with_for_update()
    ).first()
    if stored is None or stored[0] != claim.token:
        claim.mark_lost()
        raise ClaimLost(claim.scan_id)


def bind_claim(session: Session, claim: ScanClaim) -> None:
    """Fence every later commit of `session` on `claim`."""
    session.info[_FENCE_KEY] = claim
    if not event.contains(session, "before_commit", _check_claim):
        event.listen(session, "before_commit", _check_claim)


def unbind_claim(session: Session) -> None:
    session.info.pop(_FENCE_KEY, None)
    if event.contains(session, "before_commit", _check_claim):
        event.remove(session, "before_commit", _check_claim)


def assert_owned(session: Session) -> None:
    """Explicit check (for example before an external side effect). Raises ClaimLost."""
    _check_claim(session)


# ----------------------------------------------------------------------------- transitions
def _owned_running(claim: ScanClaim):  # noqa: ANN202 - SQLAlchemy where clause
    return (
        Scan.id == claim.scan_id,
        Scan.claim_token == claim.token,
        Scan.status == ScanStatus.RUNNING,
    )


def transition(session: Session, claim: ScanClaim, **values: object) -> None:
    """Conditional UPDATE of a RUNNING scan this claim owns, committed. Raises ClaimLost."""
    if claim.lost.is_set():
        raise ClaimLost(claim.scan_id)
    done = session.execute(
        update(Scan)
        .where(*_owned_running(claim))
        .values(**values)
        .execution_options(synchronize_session="fetch")
    )
    if done.rowcount != 1:
        session.rollback()
        claim.mark_lost()
        raise ClaimLost(claim.scan_id)
    session.commit()


# ----------------------------------------------------------------------------- heartbeat
def renew(session: Session, claim: ScanClaim) -> bool:
    """Renew the heartbeat. Returns False (and marks the claim lost) if it was replaced."""
    done = session.execute(
        update(Scan)
        .where(Scan.id == claim.scan_id, Scan.claim_token == claim.token)
        .values(heartbeat_at=utcnow())
    )
    session.commit()
    if done.rowcount != 1:
        claim.mark_lost()
        return False
    return True


class Heartbeat:
    """Background renewal of one claim's heartbeat, on its own database session.

    A database error does not mark the claim lost (the runner may still own it); renewal is
    retried on the next tick, and if it keeps failing the claim simply goes stale and is
    recovered elsewhere, after which the fence stops this runner's writes.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        claim: ScanClaim,
        interval_seconds: float,
    ) -> None:
        self.session_factory = session_factory
        self.claim = claim
        self.interval = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"heartbeat-{claim.scan_id}", daemon=True
        )

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                with self.session_factory() as session:
                    if not renew(session, self.claim):
                        return
            except SQLAlchemyError:
                logger.exception("Heartbeat for scan %s failed; retrying", self.claim.scan_id)

    def __enter__(self) -> "Heartbeat":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=max(5.0, self.interval * 2))

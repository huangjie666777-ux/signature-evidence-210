"""SQLite persistence for issued receipts.

Stores unique positive serial numbers, the UTC genTime of each token and
the original DER receipt. A process-wide lock plus IMMEDIATE transactions
guarantee no duplicate serials under concurrency and across restarts.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ClockRollbackError(RuntimeError):
    """System clock is earlier than the most recent issued timestamp."""


class ReceiptStore:
    def __init__(self, db_path: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            " serial INTEGER PRIMARY KEY CHECK (serial > 0),"
            " gen_time TEXT NOT NULL,"
            " receipt BLOB NOT NULL)"
        )
        self._conn.commit()

    def lock(self) -> threading.Lock:
        return self._lock

    def next_serial(self) -> int:
        row = self._conn.execute("SELECT COALESCE(MAX(serial), 0) + 1 FROM receipts").fetchone()
        return int(row[0])

    def last_gen_time(self) -> Optional[datetime]:
        row = self._conn.execute(
            "SELECT gen_time FROM receipts ORDER BY serial DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return datetime.fromisoformat(row[0])

    def check_clock(self, now: Optional[datetime] = None) -> None:
        now = now or datetime.now(timezone.utc)
        last = self.last_gen_time()
        if last is not None and now < last:
            raise ClockRollbackError(
                f"system clock {now.isoformat()} is before last issued timestamp {last.isoformat()}"
            )

    def record(self, serial: int, gen_time: datetime, receipt: bytes) -> None:
        if serial <= 0:
            raise ValueError("serial must be positive")
        if gen_time.tzinfo is None:
            raise ValueError("gen_time must be timezone-aware UTC")
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO receipts (serial, gen_time, receipt) VALUES (?, ?, ?)",
                    (serial, gen_time.astimezone(timezone.utc).isoformat(), receipt),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"duplicate serial {serial}") from exc

    def get_receipt(self, serial: int) -> Optional[bytes]:
        row = self._conn.execute(
            "SELECT receipt FROM receipts WHERE serial = ?", (serial,)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def close(self) -> None:
        self._conn.close()


"""Persistent peer address book with bounded, failure-aware selection."""

from __future__ import annotations

import ipaddress
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from bitcoin_core.network.version import NetworkAddress

MAX_ADDRESS_AGE = 30 * 24 * 60 * 60
RECENT_ADDRESS_AGE = 3 * 60 * 60


@dataclass(frozen=True, slots=True)
class AddressRecord:
    address: NetworkAddress
    timestamp: int
    last_try: int = 0
    last_success: int = 0
    failures: int = 0


class AddressBook:
    """Store peer addresses and select candidates without repeating failures."""

    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS addresses (
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                services TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                last_try INTEGER NOT NULL DEFAULT 0,
                last_success INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(ip, port)
            )"""
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def add(
        self,
        address: NetworkAddress,
        *,
        timestamp: int | None = None,
        source: str = "",
        now: int | None = None,
    ) -> bool:
        """Insert a reachable address, bounding its advertised age and clock skew."""
        current = int(time.time()) if now is None else now
        instant = current if timestamp is None else timestamp
        try:
            ip = ipaddress.ip_address(address.ip)
        except ValueError:
            return False
        if ip.is_unspecified or ip.is_multicast or not 1 <= address.port <= 65535:
            return False
        instant = min(instant, current + 10 * 60)
        instant = max(instant, current - MAX_ADDRESS_AGE)
        with self._db:
            self._db.execute(
                """INSERT INTO addresses(ip, port, services, timestamp, source)
                   VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(ip, port) DO UPDATE SET
                     services=excluded.services,
                     timestamp=MAX(addresses.timestamp, excluded.timestamp),
                     source=CASE WHEN excluded.source='' THEN addresses.source ELSE excluded.source END""",
                (str(ip), address.port, str(address.services), instant, source),
            )
        return True

    def add_many(
        self,
        entries,
        *,
        source: str = "",
        now: int | None = None,
    ) -> int:
        accepted = 0
        for entry in entries:
            accepted += self.add(entry.address, timestamp=entry.timestamp, source=source, now=now)
        return accepted

    def mark_attempt(self, address: NetworkAddress, *, now: int | None = None) -> None:
        instant = int(time.time()) if now is None else now
        with self._db:
            self._db.execute(
                "UPDATE addresses SET last_try=?, failures=MIN(failures+1, 100) WHERE ip=? AND port=?",
                (instant, str(address.ip), address.port),
            )

    def mark_success(self, address: NetworkAddress, *, now: int | None = None) -> None:
        instant = int(time.time()) if now is None else now
        with self._db:
            self._db.execute(
                "UPDATE addresses SET timestamp=?, last_success=?, failures=0 WHERE ip=? AND port=?",
                (instant, instant, str(address.ip), address.port),
            )

    def prune(self, *, now: int | None = None) -> int:
        """Remove expired peer records and return the number removed."""
        current = int(time.time()) if now is None else now
        with self._db:
            cursor = self._db.execute(
                "DELETE FROM addresses WHERE timestamp < ?",
                (current - MAX_ADDRESS_AGE,),
            )
            return cursor.rowcount

    def select(self, count: int = 1, *, now: int | None = None) -> tuple[AddressRecord, ...]:
        if count <= 0:
            return ()
        current = int(time.time()) if now is None else now
        rows = self._db.execute(
            """SELECT ip, port, services, timestamp, last_try, last_success, failures
               FROM addresses WHERE timestamp >= ? ORDER BY failures ASC, last_try ASC, random() LIMIT ?""",
            (current - MAX_ADDRESS_AGE, count),
        ).fetchall()
        records = []
        for host, port, services, timestamp, last_try, last_success, failures in rows:
            records.append(
                AddressRecord(
                    NetworkAddress(int(services), ipaddress.ip_address(host), port),
                    timestamp,
                    last_try,
                    last_success,
                    failures,
                )
            )
        return tuple(records)

    def recent(self, count: int = 1_000, *, now: int | None = None) -> tuple[AddressRecord, ...]:
        current = int(time.time()) if now is None else now
        rows = self._db.execute(
            """SELECT ip, port, services, timestamp, last_try, last_success, failures
               FROM addresses WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?""",
            (current - RECENT_ADDRESS_AGE, min(max(count, 0), 1_000)),
        ).fetchall()
        return tuple(
            AddressRecord(
                NetworkAddress(int(services), ipaddress.ip_address(host), port),
                timestamp,
                last_try,
                last_success,
                failures,
            )
            for host, port, services, timestamp, last_try, last_success, failures in rows
        )


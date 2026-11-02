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
    address: NetworkAddress | None
    timestamp: int
    last_try: int = 0
    last_success: int = 0
    failures: int = 0
    network_id: int = 1
    address_bytes: bytes = b""
    port: int = 0
    services: int = 0


class AddressBook:
    """Store peer addresses and select candidates without repeating failures."""

    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._initialize_schema()
        self._db.commit()

    def _initialize_schema(self) -> None:
        """Create the network-agnostic schema and migrate the earlier IP table."""
        columns = {
            row[1] for row in self._db.execute("PRAGMA table_info(addresses)").fetchall()
        }
        if columns and "network_id" not in columns:
            old_rows = self._db.execute(
                """SELECT ip, port, services, timestamp, source, last_try, last_success, failures
                   FROM addresses"""
            ).fetchall()
            self._db.execute("ALTER TABLE addresses RENAME TO addresses_ip_legacy")
            self._create_table()
            for ip, port, services, timestamp, source, last_try, last_success, failures in old_rows:
                parsed = ipaddress.ip_address(ip)
                self._db.execute(
                    """INSERT OR IGNORE INTO addresses
                       (network_id, address, port, services, timestamp, source, last_try, last_success, failures)
                       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        1 if parsed.version == 4 else 2,
                        parsed.packed,
                        port,
                        services,
                        timestamp,
                        source,
                        last_try,
                        last_success,
                        failures,
                    ),
                )
            self._db.execute("DROP TABLE addresses_ip_legacy")
        else:
            self._create_table()

    def _create_table(self) -> None:
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS addresses (
                network_id INTEGER NOT NULL,
                address BLOB NOT NULL,
                port INTEGER NOT NULL,
                services TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                last_try INTEGER NOT NULL DEFAULT 0,
                last_success INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(network_id, address, port)
            )"""
        )

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
                """INSERT INTO addresses(network_id, address, port, services, timestamp, source)
                   VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(network_id, address, port) DO UPDATE SET
                     services=excluded.services,
                     timestamp=MAX(addresses.timestamp, excluded.timestamp),
                     source=CASE WHEN excluded.source='' THEN addresses.source ELSE excluded.source END""",
                (
                    1 if ip.version == 4 else 2,
                    ip.packed,
                    address.port,
                    str(address.services),
                    instant,
                    source,
                ),
            )
        return True

    def add_v2(self, entry, *, source: str = "", now: int | None = None) -> bool:
        """Store valid BIP155 network records, including Tor v3 and I2P."""
        expected_lengths = {1: 4, 2: 16, 4: 32, 5: 32, 6: 16}
        if len(entry.address) != expected_lengths.get(entry.network_id, -1):
            return False
        if entry.network_id == 6 and entry.address[0] != 0xFC:
            return False
        if not 1 <= entry.port <= 65535:
            return False
        current = int(time.time()) if now is None else now
        instant = min(entry.timestamp, current + 10 * 60)
        instant = max(instant, current - MAX_ADDRESS_AGE)
        with self._db:
            self._db.execute(
                """INSERT INTO addresses(network_id, address, port, services, timestamp, source)
                   VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(network_id, address, port) DO UPDATE SET
                     services=excluded.services,
                     timestamp=MAX(addresses.timestamp, excluded.timestamp),
                     source=CASE WHEN excluded.source='' THEN addresses.source ELSE excluded.source END""",
                (
                    entry.network_id,
                    entry.address,
                    entry.port,
                    str(entry.services),
                    instant,
                    source,
                ),
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
            if hasattr(entry, "network_id"):
                accepted += self.add_v2(entry, source=source, now=now)
            else:
                accepted += self.add(entry.address, timestamp=entry.timestamp, source=source, now=now)
        return accepted

    def mark_attempt(self, address: NetworkAddress, *, now: int | None = None) -> None:
        instant = int(time.time()) if now is None else now
        with self._db:
            self._db.execute(
                "UPDATE addresses SET last_try=?, failures=MIN(failures+1, 100) WHERE network_id=? AND address=? AND port=?",
                (instant, 1 if address.ip.version == 4 else 2, address.ip.packed, address.port),
            )

    def mark_success(self, address: NetworkAddress, *, now: int | None = None) -> None:
        instant = int(time.time()) if now is None else now
        with self._db:
            self._db.execute(
                "UPDATE addresses SET timestamp=?, last_success=?, failures=0 WHERE network_id=? AND address=? AND port=?",
                (instant, instant, 1 if address.ip.version == 4 else 2, address.ip.packed, address.port),
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
            """SELECT network_id, address, port, services, timestamp, last_try, last_success, failures
               FROM addresses WHERE timestamp >= ? AND network_id IN (1, 2)
               ORDER BY failures ASC, last_try ASC, random() LIMIT ?""",
            (current - MAX_ADDRESS_AGE, count),
        ).fetchall()
        records = []
        for network_id, address, port, services, timestamp, last_try, last_success, failures in rows:
            ip = ipaddress.ip_address(address)
            records.append(
                AddressRecord(
                    NetworkAddress(int(services), ip, port),
                    timestamp,
                    last_try,
                    last_success,
                    failures,
                    network_id,
                    address,
                    port,
                    int(services),
                )
            )
        return tuple(records)

    def recent(self, count: int = 1_000, *, now: int | None = None) -> tuple[AddressRecord, ...]:
        current = int(time.time()) if now is None else now
        rows = self._db.execute(
            """SELECT network_id, address, port, services, timestamp, last_try, last_success, failures
               FROM addresses WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?""",
            (current - RECENT_ADDRESS_AGE, min(max(count, 0), 1_000)),
        ).fetchall()
        return tuple(
            self._record_from_row(row) for row in rows
        )

    def known(
        self,
        count: int = 0,
        *,
        network_id: int | None = None,
        now: int | None = None,
    ) -> tuple[AddressRecord, ...]:
        """Return shuffled, unexpired records, optionally restricted by network."""
        current = int(time.time()) if now is None else now
        query = """SELECT network_id, address, port, services, timestamp, last_try, last_success, failures
                   FROM addresses WHERE timestamp >= ?"""
        values: list[int] = [current - MAX_ADDRESS_AGE]
        if network_id is not None:
            query += " AND network_id=?"
            values.append(network_id)
        query += " ORDER BY random()"
        if count > 0:
            query += " LIMIT ?"
            values.append(count)
        rows = self._db.execute(query, values).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    @staticmethod
    def _record_from_row(row) -> AddressRecord:
        network_id, address, port, services, timestamp, last_try, last_success, failures = row
        parsed = None
        if network_id == 1 and len(address) == 4:
            parsed = ipaddress.IPv4Address(address)
        elif network_id == 2 and len(address) == 16:
            parsed = ipaddress.IPv6Address(address)
        network_address = (
            NetworkAddress(int(services), parsed, port) if parsed is not None else None
        )
        return AddressRecord(
            network_address,
            timestamp,
            last_try,
            last_success,
            failures,
            network_id,
            address,
            port,
            int(services),
        )


"""Persistent IP and subnet bans for the P2P connection manager."""

from __future__ import annotations

import ipaddress
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BAN_TIME = 24 * 60 * 60


@dataclass(frozen=True, slots=True)
class BanRecord:
    subnet: ipaddress.IPv4Network | ipaddress.IPv6Network
    created_at: int
    banned_until: int

    def to_rpc(self, now: int) -> dict[str, int | str]:
        return {
            "address": str(self.subnet),
            "ban_created": self.created_at,
            "banned_until": self.banned_until,
            "ban_duration": self.banned_until - self.created_at,
            "time_remaining": self.banned_until - now,
        }


def parse_subnet(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse an IP address or subnet, normalizing host addresses to full masks."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Invalid IP/Subnet")
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        address = ipaddress.ip_address(value)
        return ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)
    except ValueError as exc:
        raise ValueError("Invalid IP/Subnet") from exc


class BanManager:
    """Persist manual IP bans and query them for incoming/outgoing connections."""

    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS bans (
                subnet TEXT PRIMARY KEY NOT NULL,
                created_at INTEGER NOT NULL,
                banned_until INTEGER NOT NULL
            )"""
        )
        self._db.commit()
        self.prune()

    def close(self) -> None:
        self._db.close()

    def ban(
        self,
        subnet: ipaddress.IPv4Network | ipaddress.IPv6Network,
        bantime: int = 0,
        *,
        absolute: bool = False,
        now: int | None = None,
    ) -> BanRecord:
        current = int(time.time()) if now is None else now
        if isinstance(bantime, bool) or not isinstance(bantime, int) or bantime < 0:
            raise ValueError("bantime must be a non-negative integer")
        if absolute:
            if bantime < current:
                raise ValueError("Absolute timestamp is in the past")
            banned_until = bantime
        else:
            banned_until = current + (bantime or DEFAULT_BAN_TIME)
        record = BanRecord(subnet, current, banned_until)
        with self._db:
            self._db.execute(
                """INSERT INTO bans(subnet, created_at, banned_until) VALUES(?, ?, ?)
                   ON CONFLICT(subnet) DO UPDATE SET
                     created_at=excluded.created_at, banned_until=excluded.banned_until""",
                (str(subnet), current, banned_until),
            )
        return record

    def unban(
        self,
        subnet: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        with self._db:
            cursor = self._db.execute("DELETE FROM bans WHERE subnet=?", (str(subnet),))
            return cursor.rowcount > 0

    def clear(self) -> None:
        with self._db:
            self._db.execute("DELETE FROM bans")

    def prune(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else now
        with self._db:
            cursor = self._db.execute("DELETE FROM bans WHERE banned_until <= ?", (current,))
            return cursor.rowcount

    def list(self, *, now: int | None = None) -> tuple[BanRecord, ...]:
        current = int(time.time()) if now is None else now
        self.prune(now=current)
        rows = self._db.execute(
            "SELECT subnet, created_at, banned_until FROM bans ORDER BY subnet"
        ).fetchall()
        return tuple(
            BanRecord(ipaddress.ip_network(subnet), created_at, banned_until)
            for subnet, created_at, banned_until in rows
        )

    def is_banned(self, address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        current = int(time.time())
        self.prune(now=current)
        return any(ip.version == subnet.version and ip in subnet for subnet in (
            ipaddress.ip_network(row[0])
            for row in self._db.execute("SELECT subnet FROM bans").fetchall()
        ))

"""BIP9 version-bits deployment state and signalling calculations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin_core.node.chain import BlockIndex

VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_TOP_MASK = 0xE0000000
VERSIONBITS_NUM_BITS = 5
ALWAYS_ACTIVE = -1
NEVER_ACTIVE = -2


class ThresholdState(StrEnum):
    DEFINED = "defined"
    STARTED = "started"
    LOCKED_IN = "locked_in"
    ACTIVE = "active"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Deployment:
    """Parameters for one BIP9 deployment."""

    bit: int
    start_time: int
    timeout: int
    period: int = 2016
    threshold: int = 1815
    min_activation_height: int = 0
    gbt_optional_rule: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.bit <= 28:
            raise ValueError("deployment bit must be between 0 and 28")
        if self.period <= 0 or not 0 <= self.threshold <= self.period:
            raise ValueError("deployment threshold must fit a positive period")
        if self.min_activation_height < 0:
            raise ValueError("minimum activation height cannot be negative")
        if not isinstance(self.gbt_optional_rule, bool):
            raise ValueError("GBT optional-rule flag must be boolean")
        if self.start_time not in (ALWAYS_ACTIVE, NEVER_ACTIVE) and self.timeout < self.start_time:
            raise ValueError("deployment timeout cannot precede its start time")

    @property
    def mask(self) -> int:
        return 1 << self.bit

    def signals(self, block: BlockIndex) -> bool:
        version = block.header.version & 0xFFFFFFFF
        return (version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS and bool(version & self.mask)


@dataclass(frozen=True, slots=True)
class DeploymentStatistics:
    period: int
    threshold: int
    elapsed: int
    count: int
    possible: bool
    signalling_blocks: tuple[bool, ...]


@dataclass(frozen=True, slots=True)
class DeploymentInfo:
    since: int
    current_state: ThresholdState
    next_state: ThresholdState
    stats: DeploymentStatistics | None
    active_since: int | None


@dataclass(slots=True)
class VersionBits:
    """Evaluate BIP9 states on competing branches with a period-boundary cache."""

    deployment: Deployment
    _cache: dict[bytes | None, ThresholdState] = field(default_factory=dict, init=False)

    def clear(self) -> None:
        self._cache.clear()

    def state_for(self, previous: BlockIndex | None) -> ThresholdState:
        """Return deployment state for the block immediately after ``previous``."""
        dep = self.deployment
        if dep.start_time == ALWAYS_ACTIVE:
            return ThresholdState.ACTIVE
        if dep.start_time == NEVER_ACTIVE:
            return ThresholdState.FAILED

        if previous is not None:
            boundary_height = previous.height - ((previous.height + 1) % dep.period)
            previous = previous.ancestor(boundary_height)

        pending: list[BlockIndex] = []
        cursor = previous
        while cursor is not None and cursor.block_hash not in self._cache:
            if cursor.median_time_past < dep.start_time:
                self._cache[cursor.block_hash] = ThresholdState.DEFINED
                break
            pending.append(cursor)
            cursor = cursor.ancestor(cursor.height - dep.period)

        state = self._cache.get(None if cursor is None else cursor.block_hash)
        if state is None:
            # A period before genesis is defined by construction.
            self._cache[None] = ThresholdState.DEFINED
            state = ThresholdState.DEFINED

        while pending:
            period_end = pending.pop()
            next_state = state
            if state is ThresholdState.DEFINED:
                if period_end.median_time_past >= dep.start_time:
                    next_state = ThresholdState.STARTED
            elif state is ThresholdState.STARTED:
                count = 0
                block: BlockIndex | None = period_end
                for _ in range(dep.period):
                    if block is None:
                        break
                    count += dep.signals(block)
                    block = block.previous
                if count >= dep.threshold:
                    next_state = ThresholdState.LOCKED_IN
                elif period_end.median_time_past >= dep.timeout:
                    next_state = ThresholdState.FAILED
            elif state is ThresholdState.LOCKED_IN:
                if period_end.height + 1 >= dep.min_activation_height:
                    next_state = ThresholdState.ACTIVE
            # ACTIVE and FAILED are terminal states.
            self._cache[period_end.block_hash] = next_state
            state = next_state
        return state

    def state_since_height(self, previous: BlockIndex | None) -> int:
        """Return the first height whose next-block state equals current state."""
        if self.deployment.start_time in (ALWAYS_ACTIVE, NEVER_ACTIVE):
            return 0
        state = self.state_for(previous)
        if state is ThresholdState.DEFINED or previous is None:
            return 0
        dep = self.deployment
        boundary_height = previous.height - ((previous.height + 1) % dep.period)
        boundary = previous.ancestor(boundary_height)
        if boundary is None:
            return 0
        period_parent = boundary.ancestor(boundary.height - dep.period)
        while period_parent is not None and self.state_for(period_parent) is state:
            boundary = period_parent
            period_parent = boundary.ancestor(boundary.height - dep.period)
        return boundary.height + 1

    def statistics_for(self, block: BlockIndex) -> DeploymentStatistics:
        """Count signalling blocks from the current period through ``block``."""
        dep = self.deployment
        elapsed = block.height % dep.period + 1
        start_height = block.height - elapsed + 1
        cursor: BlockIndex | None = block
        flags = [False] * elapsed
        count = 0
        while cursor is not None and cursor.height >= start_height:
            signalled = dep.signals(cursor)
            flags[cursor.height - start_height] = signalled
            count += signalled
            cursor = cursor.previous
        return DeploymentStatistics(
            dep.period,
            dep.threshold,
            elapsed,
            count,
            dep.period - dep.threshold >= elapsed - count,
            tuple(flags),
        )

    def info(self, block: BlockIndex) -> DeploymentInfo:
        """Return current/next states, signalling progress and activation height."""
        current = self.state_for(block.previous)
        following = self.state_for(block)
        stats = self.statistics_for(block) if current in (ThresholdState.STARTED, ThresholdState.LOCKED_IN) else None
        if current is ThresholdState.LOCKED_IN and stats is not None:
            stats = DeploymentStatistics(
                stats.period, 0, stats.elapsed, stats.count, False, stats.signalling_blocks
            )
        since = self.state_since_height(block.previous)
        if current is ThresholdState.ACTIVE:
            active_since = since
        elif following is ThresholdState.ACTIVE:
            active_since = block.height + 1
        else:
            active_since = None
        return DeploymentInfo(since, current, following, stats, active_since)


def compute_block_version(previous: BlockIndex | None, deployments: tuple[Deployment, ...]) -> int:
    """Build a versionbits block version from started and locked-in deployments."""
    version = VERSIONBITS_TOP_BITS
    for deployment in deployments:
        if VersionBits(deployment).state_for(previous) in (
            ThresholdState.STARTED,
            ThresholdState.LOCKED_IN,
        ):
            version |= deployment.mask
    return version

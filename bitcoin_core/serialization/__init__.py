"""Bitcoin wire serialization primitives."""

from .compact_size import read_compact_size, write_compact_size

__all__ = ["read_compact_size", "write_compact_size"]

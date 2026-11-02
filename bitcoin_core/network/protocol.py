"""Bitcoin P2P message framing and incremental stream parsing."""

from __future__ import annotations

from dataclasses import dataclass, field

from bitcoin_core.crypto.hashes import hash256

MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
TESTNET_MAGIC = bytes.fromhex("0b110907")
SIGNET_MAGIC = bytes.fromhex("0a03cf40")
REGTEST_MAGIC = bytes.fromhex("fabfb5da")
TESTNET4_MAGIC = bytes.fromhex("1c163f28")
HEADER_SIZE = 24
DEFAULT_MAX_PAYLOAD = 32 * 1024 * 1024


class InvalidMessage(ValueError):
    """Raised for invalid P2P headers, lengths, or checksums."""


@dataclass(frozen=True, slots=True)
class Message:
    command: str
    payload: bytes
    wire_size: int = field(default=0, compare=False)


def _validate_magic(magic: bytes) -> None:
    if len(magic) != 4:
        raise ValueError("network magic must contain exactly four bytes")


def _encode_command(command: str) -> bytes:
    try:
        encoded = command.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("P2P command must be ASCII") from exc
    if not encoded or len(encoded) > 12 or any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError("P2P command must contain 1 to 12 printable ASCII characters")
    return encoded.ljust(12, b"\0")


def _decode_command(encoded: bytes) -> str:
    if len(encoded) != 12:
        raise InvalidMessage("command field must contain 12 bytes")
    name = encoded.split(b"\0", 1)[0]
    if not name or any(byte < 0x20 or byte > 0x7E for byte in name):
        raise InvalidMessage("invalid P2P command field")
    if encoded != name.ljust(12, b"\0"):
        raise InvalidMessage("P2P command has non-zero padding")
    return name.decode("ascii")


def encode_message(command: str, payload: bytes, magic: bytes = MAINNET_MAGIC) -> bytes:
    """Serialize a complete 24-byte-header P2P message."""
    _validate_magic(magic)
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("P2P payload length exceeds uint32")
    return (
        magic
        + _encode_command(command)
        + len(payload).to_bytes(4, "little")
        + hash256(payload)[:4]
        + payload
    )


def decode_message(raw: bytes, magic: bytes = MAINNET_MAGIC, *, max_payload: int = DEFAULT_MAX_PAYLOAD) -> Message:
    """Decode exactly one framed message and verify its checksum."""
    _validate_magic(magic)
    if len(raw) < HEADER_SIZE:
        raise InvalidMessage("truncated P2P message header")
    if raw[:4] != magic:
        raise InvalidMessage("network magic mismatch")
    command = _decode_command(raw[4:16])
    payload_size = int.from_bytes(raw[16:20], "little")
    if payload_size > max_payload:
        raise InvalidMessage("P2P payload exceeds configured limit")
    if len(raw) != HEADER_SIZE + payload_size:
        raise InvalidMessage("P2P message length does not match header")
    payload = raw[HEADER_SIZE:]
    if hash256(payload)[:4] != raw[20:24]:
        raise InvalidMessage("P2P payload checksum mismatch")
    return Message(command, payload, len(raw))


class MessageParser:
    """Incremental parser for arbitrary TCP chunks and multiple P2P messages."""

    def __init__(self, magic: bytes = MAINNET_MAGIC, *, max_payload: int = DEFAULT_MAX_PAYLOAD):
        _validate_magic(magic)
        if max_payload < 0:
            raise ValueError("maximum payload cannot be negative")
        self.magic = magic
        self.max_payload = max_payload
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, chunk: bytes) -> list[Message]:
        """Append received bytes and return every complete validated message."""
        self._buffer.extend(chunk)
        messages: list[Message] = []
        while True:
            start = self._buffer.find(self.magic)
            if start < 0:
                keep = min(len(self._buffer), len(self.magic) - 1)
                if keep:
                    self._buffer[:] = self._buffer[-keep:]
                else:
                    self._buffer.clear()
                break
            if start:
                del self._buffer[:start]
            if len(self._buffer) < HEADER_SIZE:
                break
            try:
                command = _decode_command(bytes(self._buffer[4:16]))
            except InvalidMessage:
                del self._buffer[0]
                continue
            payload_size = int.from_bytes(self._buffer[16:20], "little")
            if payload_size > self.max_payload:
                raise InvalidMessage("P2P payload exceeds configured limit")
            message_size = HEADER_SIZE + payload_size
            if len(self._buffer) < message_size:
                break
            frame = bytes(self._buffer[:message_size])
            del self._buffer[:message_size]
            messages.append(decode_message(frame, self.magic, max_payload=self.max_payload))
        return messages

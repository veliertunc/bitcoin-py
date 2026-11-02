"""Human-readable script disassembly, output classification, and addresses."""

from __future__ import annotations

from bitcoin_core.crypto.hashes import hash160
from bitcoin_core.crypto.secp256k1 import parse_public_key
from bitcoin_core.encoding.base58 import encode_base58_check
from bitcoin_core.encoding.bech32 import encode_segwit_address
from bitcoin_core.policy.standard import is_standard_script
from bitcoin_core.script import opcodes as op
from bitcoin_core.script.witness import get_witness_program

_OPCODE_NAMES = {
    value: name
    for name, value in vars(op).items()
    if name.startswith("OP_") and isinstance(value, int)
}


def script_to_asm(script: bytes) -> str:
    """Disassemble a script using Bitcoin Core's opcode and pushed-data form."""
    result: list[str] = []
    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        if opcode == op.OP_0:
            result.append("0")
            continue
        if opcode == op.OP_1NEGATE:
            result.append("-1")
            continue
        if op.OP_1 <= opcode <= op.OP_16:
            result.append(str(opcode - op.OP_1 + 1))
            continue

        if opcode <= 75:
            size = opcode
        elif opcode == op.OP_PUSHDATA1:
            if position >= len(script):
                result.append("OP_PUSHDATA1")
                break
            size = script[position]
            position += 1
        elif opcode == op.OP_PUSHDATA2:
            if position + 2 > len(script):
                result.append("OP_PUSHDATA2")
                break
            size = int.from_bytes(script[position : position + 2], "little")
            position += 2
        elif opcode == op.OP_PUSHDATA4:
            if position + 4 > len(script):
                result.append("OP_PUSHDATA4")
                break
            size = int.from_bytes(script[position : position + 4], "little")
            position += 4
        else:
            result.append(_OPCODE_NAMES.get(opcode, f"OP_UNKNOWN_{opcode:02x}"))
            continue

        end = position + size
        if end > len(script):
            result.append(script[position:].hex())
            break
        result.append(script[position:end].hex())
        position = end
    return " ".join(result)


def script_pubkey_json(script: bytes, network: str = "main") -> dict[str, str]:
    """Return RPC-style scriptPubKey asm, type, hex, and address when known."""
    _standard, kind = is_standard_script(script)
    result = {"asm": script_to_asm(script), "hex": script.hex(), "type": kind}
    p2pkh_version, p2sh_version, hrp = _network_address_params(network)

    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        result["address"] = encode_base58_check(bytes((p2pkh_version,)) + script[3:23])
    elif len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1] == op.OP_EQUAL:
        result["address"] = encode_base58_check(bytes((p2sh_version,)) + script[2:22])
    else:
        witness = get_witness_program(script)
        if witness is not None:
            version, program = witness
            if version == 0 and len(program) == 20:
                result["type"] = "witness_v0_keyhash"
            elif version == 0 and len(program) == 32:
                result["type"] = "witness_v0_scripthash"
            elif version == 1 and len(program) == 32:
                result["type"] = "witness_v1_taproot"
            else:
                result["type"] = "witness_unknown"
            result["address"] = encode_segwit_address(hrp, version, program)
        elif len(script) in (35, 67) and script[-1] == op.OP_CHECKSIG and script[0] == len(script) - 2:
            public_key = script[1:-1]
            try:
                parse_public_key(public_key)
            except ValueError:
                pass
            else:
                result["address"] = encode_base58_check(
                    bytes((p2pkh_version,)) + hash160(public_key)
                )
    return result


def _network_address_params(network: str) -> tuple[int, int, str]:
    normalized = network.lower()
    if normalized == "main":
        return 0, 5, "bc"
    if normalized == "regtest":
        return 111, 196, "bcrt"
    if normalized in {"test", "testnet", "testnet4", "signet"}:
        return 111, 196, "tb"
    raise ValueError(f"unknown Bitcoin network: {network}")

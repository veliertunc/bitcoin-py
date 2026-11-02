"""Built-in network parameters and genesis blocks."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_core.consensus.params import ConsensusParams, MAINNET, REGTEST, TESTNET
from bitcoin_core.primitives.block import Block, BlockHeader
from bitcoin_core.primitives.transaction import OutPoint, Transaction, TxInput, TxOutput
from bitcoin_core.script.interpreter import encode_script_num

COIN = 100_000_000
_MAINNET_LIMIT = MAINNET.pow_limit


@dataclass(frozen=True, slots=True)
class ChainParams:
    """Configuration needed to initialize one Bitcoin network."""

    name: str
    message_start: bytes
    default_port: int
    rpc_port: int
    consensus: ConsensusParams
    genesis: Block
    dns_seeds: tuple[str, ...] = ()


def _push_data(data: bytes) -> bytes:
    size = len(data)
    if size <= 75:
        return bytes((size,)) + data
    if size <= 0xFF:
        return b"\x4c" + bytes((size,)) + data
    if size <= 0xFFFF:
        return b"\x4d" + size.to_bytes(2, "little") + data
    return b"\x4e" + size.to_bytes(4, "little") + data


def _genesis(network: str) -> Block:
    if network == "testnet4":
        timestamp_text = b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
        output_script = b"\x20" + bytes(32) + b"\xac"
        timestamp, nonce, bits = 1_714_777_860, 393_743_547, 0x1D00FFFF
    else:
        timestamp_text = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
        public_key = bytes.fromhex(
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        output_script = _push_data(public_key) + b"\xac"
        if network in ("main", "test"):
            timestamp, nonce, bits = (
                (1_231_006_505, 2_083_236_893, 0x1D00FFFF)
                if network == "main"
                else (1_296_688_602, 414_098_458, 0x1D00FFFF)
            )
        elif network == "signet":
            timestamp, nonce, bits = 1_598_918_400, 52_613_770, 0x1E0377AE
        elif network == "regtest":
            timestamp, nonce, bits = 1_296_688_602, 2, 0x207FFFFF
        else:
            raise ValueError(f"unknown Bitcoin network: {network}")
    script_sig = (
        _push_data(encode_script_num(486_604_799))
        + _push_data(encode_script_num(4))
        + _push_data(timestamp_text)
    )
    coinbase = Transaction(
        version=1,
        inputs=(TxInput(OutPoint(bytes(32), 0xFFFFFFFF), script_sig),),
        outputs=(TxOutput(50 * COIN, output_script),),
        lock_time=0,
    )
    header = BlockHeader(1, bytes(32), coinbase.txid, timestamp, bits, nonce)
    return Block(header, (coinbase,))


TESTNET3 = ConsensusParams(pow_limit=_MAINNET_LIMIT, allow_min_difficulty=True)
SIGNET = ConsensusParams(
    pow_limit=int("00000377ae000000000000000000000000000000000000000000000000000000", 16),
)

MAIN = ChainParams(
    "main",
    bytes.fromhex("f9beb4d9"),
    8333,
    8332,
    MAINNET,
    _genesis("main"),
    (
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.net",
        "seed.bitcoin.sprovoost.nl",
        "seed.bitcoin.wiz.biz",
    ),
)
TEST = ChainParams(
    "test",
    bytes.fromhex("0b110907"),
    18333,
    18332,
    TESTNET3,
    _genesis("test"),
    ("testnet-seed.bitcoin.jonasschnelli.ch", "seed.tbtc.petertodd.net"),
)
TESTNET4 = ChainParams(
    "testnet4",
    bytes.fromhex("1c163f28"),
    48333,
    48332,
    TESTNET,
    _genesis("testnet4"),
    ("seed.testnet4.bitcoin.sprovoost.nl", "seed.testnet4.wiz.biz"),
)
SIGNET_PARAMS = ChainParams(
    "signet",
    bytes.fromhex("0a03cf40"),
    38333,
    38332,
    SIGNET,
    _genesis("signet"),
    ("seed.signet.bitcoin.sprovoost.nl", "seed.signet.achownodes.xyz"),
)
REGTEST_PARAMS = ChainParams(
    "regtest",
    bytes.fromhex("fabfb5da"),
    18444,
    18443,
    REGTEST,
    _genesis("regtest"),
)

NETWORKS = {
    "main": MAIN,
    "test": TEST,
    "testnet": TEST,
    "testnet4": TESTNET4,
    "signet": SIGNET_PARAMS,
    "regtest": REGTEST_PARAMS,
}


def get_chain_params(name: str) -> ChainParams:
    """Return built-in parameters for a named Bitcoin network."""
    try:
        return NETWORKS[name.lower()]
    except KeyError as exc:
        raise ValueError(f"unknown Bitcoin network: {name}") from exc

"""In-memory UTXO view and atomic block connection/disconnection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.subsidy import block_subsidy
from bitcoin_core.consensus.validation import check_block
from bitcoin_core.primitives.block import Block
from bitcoin_core.primitives.transaction import MAX_MONEY, OutPoint, Transaction
from bitcoin_core.script.interpreter import encode_script_num
from bitcoin_core.script.interpreter import ScriptFlags
from bitcoin_core.script.sigops import MAX_BLOCK_SIGOP_COST, input_sigop_cost, legacy_sigop_cost
from bitcoin_core.script.validation import consensus_script_flags

COINBASE_MATURITY = 100
InputVerifier = Callable[[Transaction, int, "Coin", tuple["Coin", ...]], bool]


@dataclass(frozen=True, slots=True)
class Coin:
    """A currently unspent transaction output with its chain origin."""

    value: int
    script_pubkey: bytes
    height: int
    coinbase: bool
    median_time_past: int = 0


@dataclass(slots=True)
class CoinsView:
    """In-memory map keyed by (raw txid, output index)."""

    coins: dict[tuple[bytes, int], Coin] = field(default_factory=dict)

    def get(self, outpoint: OutPoint) -> Coin | None:
        return self.coins.get((outpoint.txid, outpoint.index))

    def __len__(self) -> int:
        return len(self.coins)


@dataclass(frozen=True, slots=True)
class BlockUndo:
    """Data required to reverse one connected block."""

    height: int
    spent: tuple[tuple[tuple[bytes, int], Coin], ...]
    created: tuple[tuple[bytes, int], ...]


class BlockConnectionError(ValueError):
    """Raised when a block cannot be connected to the current UTXO view."""


def connect_block(
    view: CoinsView,
    block: Block,
    height: int,
    params: ConsensusParams,
    *,
    input_verifier: InputVerifier,
    check_pow: bool = True,
    median_time_past: int | None = None,
) -> BlockUndo:
    """Validate and atomically apply a block's UTXO changes."""
    if height < 0:
        raise BlockConnectionError("block height cannot be negative")
    result = check_block(block, params, check_pow=check_pow)
    if not result.valid:
        raise BlockConnectionError(result.reason)
    # Bitcoin Core deliberately skips the genesis block's transactions. Its
    # coinbase is provably unspendable and is absent from every UTXO snapshot.
    if height == 0:
        return BlockUndo(height, (), ())
    bip34_height = params.bip34_height
    bip30_exception = block.header.block_hash in params.bip30_exception_hashes
    if bip34_height is not None and height >= bip34_height:
        height_bytes = encode_script_num(height)
        coinbase_script = block.transactions[0].inputs[0].script_sig
        if height == 0:
            expected_prefix = b"\x00"
        elif height <= 16:
            expected_prefix = bytes((0x50 + height,))
        else:
            expected_prefix = bytes((len(height_bytes),)) + height_bytes
        if not coinbase_script.startswith(expected_prefix):
            raise BlockConnectionError("coinbase script does not begin with the block height")

    staged = view.coins.copy()
    block_mtp = block.header.timestamp if median_time_past is None else median_time_past
    bip113_active = params.csv_height is not None and height >= params.csv_height
    spent_undo: list[tuple[tuple[bytes, int], Coin]] = []
    created: list[tuple[bytes, int]] = []
    created_in_block: set[tuple[bytes, int]] = set()
    total_fees = 0
    sigop_cost = sum(legacy_sigop_cost(tx) for tx in block.transactions)
    block_script_flags = consensus_script_flags(params, height, block.header.block_hash)
    p2sh_active = bool(block_script_flags & ScriptFlags.P2SH)
    segwit_active = bool(block_script_flags & ScriptFlags.WITNESS)

    for tx_index, tx in enumerate(block.transactions):
        is_coinbase = tx_index == 0
        if not is_coinbase:
            lock_time_cutoff = (
                height
                if tx.lock_time < 500_000_000
                else block_mtp if bip113_active else block.header.timestamp
            )
            if tx.lock_time and tx.lock_time >= lock_time_cutoff and any(
                txin.sequence != 0xFFFFFFFF for txin in tx.inputs
            ):
                raise BlockConnectionError("transaction is non-final for this block")
            input_value = 0
            seen_inputs: set[tuple[bytes, int]] = set()
            input_coins: list[Coin] = []
            input_keys: list[tuple[bytes, int]] = []
            for txin in tx.inputs:
                key = (txin.previous_output.txid, txin.previous_output.index)
                if key in seen_inputs:
                    raise BlockConnectionError("transaction contains duplicate inputs")
                seen_inputs.add(key)
                coin = staged.get(key)
                if coin is None:
                    raise BlockConnectionError("transaction input spends a missing output")
                if coin.coinbase and height - coin.height < COINBASE_MATURITY:
                    raise BlockConnectionError("transaction spends an immature coinbase output")
                input_value += coin.value
                if input_value > MAX_MONEY:
                    raise BlockConnectionError("transaction input value out of range")
                input_coins.append(coin)
                input_keys.append(key)
            all_prevouts = tuple(input_coins)
            sigop_cost += input_sigop_cost(
                tx,
                all_prevouts,
                p2sh_active=p2sh_active,
                segwit_active=segwit_active,
            )
            if sigop_cost > MAX_BLOCK_SIGOP_COST:
                raise BlockConnectionError("block signature-operation cost exceeds maximum")
            if tx.version >= 2 and bip113_active:
                for txin, coin in zip(tx.inputs, all_prevouts):
                    sequence = txin.sequence
                    if sequence & (1 << 31):
                        continue
                    relative = sequence & 0x0000FFFF
                    if sequence & (1 << 22):
                        minimum_time = coin.median_time_past + (relative << 9) - 1
                        if minimum_time >= block_mtp:
                            raise BlockConnectionError("transaction sequence time lock is not satisfied")
                    elif coin.height + relative - 1 >= height:
                        raise BlockConnectionError("transaction sequence height lock is not satisfied")
            for input_index, coin in enumerate(all_prevouts):
                contextual_verifier = getattr(input_verifier, "verify_at_height", None)
                if contextual_verifier is not None:
                    verified = contextual_verifier(
                        tx,
                        input_index,
                        coin,
                        all_prevouts,
                        height,
                        block.header.block_hash,
                    )
                else:
                    verified = input_verifier(tx, input_index, coin, all_prevouts)
                if not verified:
                    raise BlockConnectionError("transaction input script verification failed")
            for key, coin in zip(input_keys, all_prevouts):
                del staged[key]
                if key not in created_in_block:
                    spent_undo.append((key, coin))
            output_value = tx.output_value()
            if output_value > input_value:
                raise BlockConnectionError("transaction spends more than its inputs")
            total_fees += input_value - output_value
            if total_fees > MAX_MONEY:
                raise BlockConnectionError("block fees exceed monetary range")

        for output_index, txout in enumerate(tx.outputs):
            key = (tx.txid, output_index)
            if key in staged:
                if not (is_coinbase and bip30_exception):
                    raise BlockConnectionError("transaction overwrites an unspent output")
                spent_undo.append((key, staged.pop(key)))
            staged[key] = Coin(txout.value, txout.script_pubkey, height, is_coinbase, block_mtp)
            created.append(key)
            created_in_block.add(key)

    coinbase_value = block.transactions[0].output_value()
    if coinbase_value > block_subsidy(height, params) + total_fees:
        raise BlockConnectionError("coinbase pays more than subsidy and fees")

    view.coins = staged
    return BlockUndo(height, tuple(spent_undo), tuple(created))


def disconnect_block(view: CoinsView, undo: BlockUndo) -> None:
    """Reverse a previously connected block using its undo record."""
    staged = view.coins.copy()
    for key in reversed(undo.created):
        staged.pop(key, None)
    for key, coin in undo.spent:
        if key in staged:
            raise BlockConnectionError("undo would overwrite an existing unspent output")
        staged[key] = coin
    view.coins = staged

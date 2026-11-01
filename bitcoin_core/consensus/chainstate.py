"""In-memory UTXO view and atomic block connection/disconnection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.consensus.subsidy import block_subsidy
from bitcoin_core.consensus.validation import check_block
from bitcoin_core.primitives.block import Block
from bitcoin_core.primitives.transaction import MAX_MONEY, OutPoint, Transaction

COINBASE_MATURITY = 100
InputVerifier = Callable[[Transaction, int, "Coin", tuple["Coin", ...]], bool]


@dataclass(frozen=True, slots=True)
class Coin:
    """A currently unspent transaction output with its chain origin."""

    value: int
    script_pubkey: bytes
    height: int
    coinbase: bool


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
) -> BlockUndo:
    """Validate and atomically apply a block's UTXO changes."""
    if height < 0:
        raise BlockConnectionError("block height cannot be negative")
    result = check_block(block, params, check_pow=check_pow)
    if not result.valid:
        raise BlockConnectionError(result.reason)

    staged = view.coins.copy()
    spent_undo: list[tuple[tuple[bytes, int], Coin]] = []
    created: list[tuple[bytes, int]] = []
    created_in_block: set[tuple[bytes, int]] = set()
    total_fees = 0

    for tx_index, tx in enumerate(block.transactions):
        is_coinbase = tx_index == 0
        if not is_coinbase:
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
            for input_index, coin in enumerate(all_prevouts):
                if not input_verifier(tx, input_index, coin, all_prevouts):
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
                raise BlockConnectionError("transaction overwrites an unspent output")
            staged[key] = Coin(txout.value, txout.script_pubkey, height, is_coinbase)
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

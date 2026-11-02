"""SQLite persistence for headers, blocks, UTXOs, and block undo data."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from bitcoin_core.consensus.chainstate import (
    BlockUndo,
    Coin,
    CoinsView,
    InputVerifier,
    connect_block as validate_and_connect_block,
    disconnect_block as apply_disconnect,
)
from bitcoin_core.consensus.params import ConsensusParams
from bitcoin_core.node.chain import BlockIndex
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.primitives.block import Block, BlockHeader


class SQLiteNodeStore:
    """Store blockchain data in a local SQLite database."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._db = sqlite3.connect(self.path)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS headers (
                hash BLOB PRIMARY KEY CHECK(length(hash) = 32),
                previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
                height INTEGER NOT NULL,
                chainwork TEXT NOT NULL,
                header BLOB NOT NULL CHECK(length(header) = 80),
                active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0, 1))
            );
            CREATE INDEX IF NOT EXISTS headers_by_height ON headers(height);
            CREATE TABLE IF NOT EXISTS blocks (
                hash BLOB PRIMARY KEY CHECK(length(hash) = 32),
                height INTEGER NOT NULL,
                payload BLOB NOT NULL,
                tx_count INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0, 1))
            );
            CREATE TABLE IF NOT EXISTS coins (
                txid BLOB NOT NULL CHECK(length(txid) = 32),
                output_index INTEGER NOT NULL,
                value INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                height INTEGER NOT NULL,
                coinbase INTEGER NOT NULL CHECK(coinbase IN (0, 1)),
                PRIMARY KEY(txid, output_index)
            );
            CREATE TABLE IF NOT EXISTS undo (
                block_hash BLOB PRIMARY KEY CHECK(length(block_hash) = 32),
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(blocks)")}
        if "active" not in columns:
            self._db.execute("ALTER TABLE blocks ADD COLUMN active INTEGER NOT NULL DEFAULT 0")
        self._db.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()

    def __enter__(self) -> SQLiteNodeStore:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def save_header(self, index: BlockIndex, *, active: bool = False) -> None:
        """Insert or update one validated header index entry."""
        previous_hash = index.header.previous_block
        with self._db:
            self._db.execute(
                """INSERT INTO headers(hash, previous_hash, height, chainwork, header, active)
                   VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(hash) DO UPDATE SET previous_hash=excluded.previous_hash,
                       height=excluded.height, chainwork=excluded.chainwork,
                       header=excluded.header, active=excluded.active""",
                (
                    index.block_hash,
                    previous_hash,
                    index.height,
                    str(index.chainwork),
                    index.header.serialize(),
                    int(active),
                ),
            )

    def save_block(self, block: Block, index: BlockIndex) -> None:
        """Persist a serialized block after confirming its header identity."""
        if block.header != index.header:
            raise ValueError("block header does not match its block index")
        with self._db:
            self._db.execute(
                """INSERT INTO blocks(hash, height, payload, tx_count, active) VALUES(?, ?, ?, ?, 0)
                   ON CONFLICT(hash) DO UPDATE SET height=excluded.height,
                       payload=excluded.payload, tx_count=excluded.tx_count""",
                (index.block_hash, index.height, block.serialize(), len(block.transactions)),
            )

    def load_block(self, block_hash: bytes) -> Block | None:
        """Load and deserialize a block by its raw hash."""
        row = self._db.execute("SELECT payload FROM blocks WHERE hash=?", (block_hash,)).fetchone()
        return None if row is None else Block.deserialize(row[0])

    def has_block(self, block_hash: bytes) -> bool:
        """Return whether serialized block data is available locally."""
        return self._db.execute("SELECT 1 FROM blocks WHERE hash=?", (block_hash,)).fetchone() is not None

    def discard_side_blocks(self, block_hashes: tuple[bytes, ...]) -> None:
        """Remove downloaded block bodies that have not been connected."""
        with self._db:
            self._db.executemany("DELETE FROM blocks WHERE hash=? AND active=0", ((item,) for item in block_hashes))

    def active_block_hash(self, height: int) -> bytes | None:
        """Return the connected active-chain block hash at a height."""
        row = self._db.execute("SELECT hash FROM blocks WHERE height=? AND active=1", (height,)).fetchone()
        return None if row is None else bytes(row[0])

    def load_header(self, block_hash: bytes) -> bytes | None:
        """Return the serialized 80-byte header for a block hash."""
        row = self._db.execute("SELECT header FROM headers WHERE hash=?", (block_hash,)).fetchone()
        return None if row is None else bytes(row[0])

    def header_height(self, block_hash: bytes) -> int | None:
        """Return the stored height for a validated header hash."""
        row = self._db.execute("SELECT height FROM headers WHERE hash=?", (block_hash,)).fetchone()
        return None if row is None else row[0]

    def best_block(self) -> bytes | None:
        """Return the persisted active tip hash, if one has been recorded."""
        row = self._db.execute("SELECT value FROM metadata WHERE key='best_block'").fetchone()
        return None if row is None else bytes(row[0])

    def best_height(self) -> int:
        """Return the active tip height, or -1 before genesis is connected."""
        block_hash = self.best_block()
        if block_hash is None:
            return -1
        row = self._db.execute("SELECT height FROM headers WHERE hash=?", (block_hash,)).fetchone()
        if row is None:
            raise ValueError("best-block metadata points to a missing header")
        return row[0]

    def load_header_chain(self, chain: HeaderChain) -> None:
        """Rebuild a validated in-memory header index from stored headers."""
        rows = self._db.execute("SELECT height, header FROM headers ORDER BY height, hash")
        for height, raw_header in rows:
            header = BlockHeader.deserialize(raw_header)
            if height == 0:
                if chain.tip is None:
                    chain.add_genesis(header)
            else:
                chain.add_header(header)

    def load_coins(self) -> CoinsView:
        """Load the persisted UTXO set into an in-memory view."""
        rows = self._db.execute(
            "SELECT txid, output_index, value, script_pubkey, height, coinbase FROM coins"
        )
        view = CoinsView()
        view.coins = {
            (bytes(txid), index): Coin(value, bytes(script), height, bool(coinbase))
            for txid, index, value, script, height, coinbase in rows
        }
        return view

    def save_coins(self, view: CoinsView) -> None:
        """Replace the stored UTXO set with a supplied complete view."""
        with self._db:
            self._db.execute("DELETE FROM coins")
            self._db.executemany(
                "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase) "
                "VALUES(?, ?, ?, ?, ?, ?)",
                (
                    (txid, index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase))
                    for (txid, index), coin in view.coins.items()
                ),
            )

    def persist_connected_block(
        self,
        block: Block,
        index: BlockIndex,
        undo: BlockUndo,
        view: CoinsView,
    ) -> None:
        """Atomically persist a block, its undo record, and its UTXO changes."""
        if block.header != index.header or undo.height != index.height:
            raise ValueError("block, index, and undo record do not match")
        current_tip = self.best_block()
        if current_tip is not None and current_tip != block.header.previous_block:
            raise ValueError("connected block does not extend the persisted active tip")
        if current_tip is None and index.height != 0:
            raise ValueError("the first connected block must be genesis")
        undo_payload = _encode_undo(undo)
        created = set(undo.created)
        with self._db:
            self._db.execute(
                "INSERT INTO blocks(hash, height, payload, tx_count, active) VALUES(?, ?, ?, ?, 1) "
                "ON CONFLICT(hash) DO UPDATE SET height=excluded.height, "
                "payload=excluded.payload, tx_count=excluded.tx_count, active=1",
                (index.block_hash, index.height, block.serialize(), len(block.transactions)),
            )
            self._db.execute(
                "INSERT INTO undo(block_hash, payload) VALUES(?, ?) "
                "ON CONFLICT(block_hash) DO UPDATE SET payload=excluded.payload",
                (index.block_hash, undo_payload),
            )
            self._db.executemany(
                "DELETE FROM coins WHERE txid=? AND output_index=?",
                ((txid, index_num) for (txid, index_num), _coin in undo.spent),
            )
            for txid, index_num in created:
                coin = view.coins.get((txid, index_num))
                if coin is None:
                    self._db.execute("DELETE FROM coins WHERE txid=? AND output_index=?", (txid, index_num))
                else:
                    self._put_coin(txid, index_num, coin)
            self._db.execute(
                "INSERT INTO headers(hash, previous_hash, height, chainwork, header, active) "
                "VALUES(?, ?, ?, ?, ?, 1) ON CONFLICT(hash) DO UPDATE SET active=1",
                (
                    index.block_hash,
                    index.header.previous_block,
                    index.height,
                    str(index.chainwork),
                    index.header.serialize(),
                ),
            )
            self._db.execute(
                "INSERT INTO metadata(key, value) VALUES('best_block', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (index.block_hash,),
            )

    def disconnect_persisted_block(self, block_hash: bytes, view: CoinsView) -> BlockUndo:
        """Atomically roll back stored UTXOs and return the block undo record."""
        if self.best_block() != block_hash:
            raise ValueError("only the persisted active tip can be disconnected")
        row = self._db.execute("SELECT payload FROM undo WHERE block_hash=?", (block_hash,)).fetchone()
        if row is None:
            raise ValueError("undo data for block is unavailable")
        undo = _decode_undo(row[0])
        if undo.height == 0:
            raise ValueError("genesis block cannot be disconnected")
        staged = CoinsView(view.coins.copy())
        from bitcoin_core.consensus.chainstate import disconnect_block

        disconnect_block(staged, undo)
        block_row = self._db.execute("SELECT payload FROM blocks WHERE hash=?", (block_hash,)).fetchone()
        if block_row is None:
            raise ValueError("block data for disconnect is unavailable")
        block = Block.deserialize(block_row[0])
        previous_hash = block.header.previous_block
        with self._db:
            self._db.executemany(
                "DELETE FROM coins WHERE txid=? AND output_index=?",
                undo.created,
            )
            self._db.executemany(
                "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase) "
                "VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
                "value=excluded.value, script_pubkey=excluded.script_pubkey, "
                "height=excluded.height, coinbase=excluded.coinbase",
                (
                    (txid, index_num, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase))
                    for (txid, index_num), coin in undo.spent
                ),
            )
            self._db.execute("UPDATE headers SET active=0 WHERE hash=?", (block_hash,))
            self._db.execute("UPDATE blocks SET active=0 WHERE hash=?", (block_hash,))
            self._db.execute("UPDATE headers SET active=1 WHERE hash=?", (previous_hash,))
            self._db.execute("UPDATE blocks SET active=1 WHERE hash=?", (previous_hash,))
            self._db.execute(
                "INSERT INTO metadata(key, value) VALUES('best_block', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (previous_hash,),
            )
        view.coins = staged.coins
        return undo

    def reorganize(
        self,
        view: CoinsView,
        old_branch_tip_down: tuple[bytes, ...],
        new_blocks: tuple[Block, ...],
        new_indexes: tuple[BlockIndex, ...],
        params: ConsensusParams,
        *,
        input_verifier: InputVerifier,
        check_pow: bool = True,
    ) -> tuple[BlockUndo, ...]:
        """Atomically switch the active chain after validating a complete branch."""
        if len(new_blocks) != len(new_indexes) or not new_blocks:
            raise ValueError("reorganization requires matching non-empty block and index lists")
        current_tip = self.best_block()
        if old_branch_tip_down:
            if current_tip != old_branch_tip_down[0]:
                raise ValueError("reorganization old branch does not start at active tip")

        old_undos: list[tuple[bytes, BlockUndo]] = []
        for block_hash in old_branch_tip_down:
            row = self._db.execute("SELECT payload FROM undo WHERE block_hash=?", (block_hash,)).fetchone()
            if row is None:
                raise ValueError("undo data for old branch is unavailable")
            old_undos.append((block_hash, _decode_undo(row[0])))

        staged = CoinsView(view.coins.copy())
        for _block_hash, undo in old_undos:
            apply_disconnect(staged, undo)

        if old_branch_tip_down:
            old_tip_block = self.load_block(old_branch_tip_down[-1])
            if old_tip_block is None:
                raise ValueError("old branch block data is unavailable")
            expected_parent = old_tip_block.header.previous_block
        else:
            expected_parent = current_tip if current_tip is not None else bytes(32)

        new_undos: list[BlockUndo] = []
        for block, index in zip(new_blocks, new_indexes):
            if block.header != index.header or block.header.previous_block != expected_parent:
                raise ValueError("new branch blocks are not a continuous header sequence")
            undo = validate_and_connect_block(
                staged,
                block,
                index.height,
                params,
                input_verifier=input_verifier,
                check_pow=check_pow,
            )
            new_undos.append(undo)
            expected_parent = index.block_hash

        created_new = {key for undo in new_undos for key in undo.created}
        new_tip = new_indexes[-1]
        active_headers: list[BlockIndex] = []
        cursor: BlockIndex | None = new_tip
        while cursor is not None:
            active_headers.append(cursor)
            cursor = cursor.previous

        with self._db:
            for _block_hash, undo in old_undos:
                self._db.executemany(
                    "DELETE FROM coins WHERE txid=? AND output_index=?",
                    undo.created,
                )
                self._db.executemany(
                    "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase) "
                    "VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
                    "value=excluded.value, script_pubkey=excluded.script_pubkey, "
                    "height=excluded.height, coinbase=excluded.coinbase",
                    (
                        (txid, output_index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase))
                        for (txid, output_index), coin in undo.spent
                    ),
                )
                self._db.execute("UPDATE blocks SET active=0 WHERE hash=?", (_block_hash,))
            for undo in new_undos:
                self._db.executemany(
                    "DELETE FROM coins WHERE txid=? AND output_index=?",
                    ((txid, output_index) for (txid, output_index), _coin in undo.spent),
                )
            for txid, output_index in created_new:
                coin = staged.coins.get((txid, output_index))
                if coin is None:
                    self._db.execute(
                        "DELETE FROM coins WHERE txid=? AND output_index=?", (txid, output_index)
                    )
                else:
                    self._put_coin(txid, output_index, coin)
            self._db.execute("UPDATE headers SET active=0")
            for index in active_headers:
                self._db.execute(
                    "INSERT INTO headers(hash, previous_hash, height, chainwork, header, active) "
                    "VALUES(?, ?, ?, ?, ?, 1) ON CONFLICT(hash) DO UPDATE SET active=1",
                    (
                        index.block_hash,
                        index.header.previous_block,
                        index.height,
                        str(index.chainwork),
                        index.header.serialize(),
                    ),
                )
            for block, index, undo in zip(new_blocks, new_indexes, new_undos):
                self._db.execute(
                    "INSERT INTO blocks(hash, height, payload, tx_count, active) VALUES(?, ?, ?, ?, 1) "
                    "ON CONFLICT(hash) DO UPDATE SET height=excluded.height, payload=excluded.payload, "
                    "tx_count=excluded.tx_count, active=1",
                    (index.block_hash, index.height, block.serialize(), len(block.transactions)),
                )
                self._db.execute(
                    "INSERT INTO undo(block_hash, payload) VALUES(?, ?) "
                    "ON CONFLICT(block_hash) DO UPDATE SET payload=excluded.payload",
                    (index.block_hash, _encode_undo(undo)),
                )
            self._db.execute(
                "INSERT INTO metadata(key, value) VALUES('best_block', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (new_tip.block_hash,),
            )
        view.coins = staged.coins
        return tuple(new_undos)

    def connect_block(
        self,
        view: CoinsView,
        block: Block,
        index: BlockIndex,
        params: ConsensusParams,
        *,
        input_verifier: InputVerifier,
        check_pow: bool = True,
    ) -> BlockUndo:
        """Validate a block and persist its effects, rolling memory back on failure."""
        undo = validate_and_connect_block(
            view,
            block,
            index.height,
            params,
            input_verifier=input_verifier,
            check_pow=check_pow,
        )
        try:
            self.persist_connected_block(block, index, undo, view)
        except Exception:
            apply_disconnect(view, undo)
            raise
        return undo

    def disconnect_block(self, block_hash: bytes, view: CoinsView) -> BlockUndo:
        """Disconnect the active tip from both SQLite and the in-memory view."""
        return self.disconnect_persisted_block(block_hash, view)

    def _put_coin(self, txid: bytes, output_index: int, coin: Coin) -> None:
        self._db.execute(
            "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase) "
            "VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
            "value=excluded.value, script_pubkey=excluded.script_pubkey, "
            "height=excluded.height, coinbase=excluded.coinbase",
            (txid, output_index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase)),
        )


def _encode_undo(undo: BlockUndo) -> bytes:
    data = {
        "height": undo.height,
        "spent": [
            [txid.hex(), index, coin.value, coin.script_pubkey.hex(), coin.height, coin.coinbase]
            for (txid, index), coin in undo.spent
        ],
        "created": [[txid.hex(), index] for txid, index in undo.created],
    }
    return json.dumps(data, separators=(",", ":")).encode("ascii")


def _decode_undo(payload: bytes) -> BlockUndo:
    data = json.loads(payload)
    spent = tuple(
        (
            (bytes.fromhex(txid), index),
            Coin(value, bytes.fromhex(script), height, coinbase),
        )
        for txid, index, value, script, height, coinbase in data["spent"]
    )
    created = tuple((bytes.fromhex(txid), index) for txid, index in data["created"])
    return BlockUndo(data["height"], spent, created)

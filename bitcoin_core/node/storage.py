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
from bitcoin_core.consensus.blockfilter import (
    basic_filter_elements,
    compact_filter_hash,
    compact_filter_header,
    encode_basic_filter,
)
from bitcoin_core.node.chain import BlockIndex
from bitcoin_core.node.chain import HeaderChain
from bitcoin_core.primitives.block import Block, BlockHeader
from bitcoin_core.primitives.transaction import Transaction


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
                median_time_past INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(txid, output_index)
            );
            CREATE TABLE IF NOT EXISTS undo (
                block_hash BLOB PRIMARY KEY CHECK(length(block_hash) = 32),
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tx_index (
                txid BLOB PRIMARY KEY CHECK(length(txid) = 32),
                block_hash BLOB NOT NULL CHECK(length(block_hash) = 32),
                height INTEGER NOT NULL,
                tx_position INTEGER NOT NULL,
                payload BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tx_index_by_block ON tx_index(block_hash);
            CREATE TABLE IF NOT EXISTS basic_filters (
                block_hash BLOB PRIMARY KEY CHECK(length(block_hash) = 32),
                encoded_filter BLOB NOT NULL,
                filter_hash BLOB NOT NULL CHECK(length(filter_hash) = 32),
                filter_header BLOB NOT NULL CHECK(length(filter_header) = 32)
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
        coin_columns = {row[1] for row in self._db.execute("PRAGMA table_info(coins)")}
        if "median_time_past" not in coin_columns:
            self._db.execute("ALTER TABLE coins ADD COLUMN median_time_past INTEGER NOT NULL DEFAULT 0")
        self._db.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()

    def __enter__(self) -> SQLiteNodeStore:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def save_header(self, index: BlockIndex, *, active: bool | None = None) -> None:
        """Insert or update one validated header index entry."""
        previous_hash = index.header.previous_block
        with self._db:
            self._db.execute(
                """INSERT INTO headers(hash, previous_hash, height, chainwork, header, active)
                   VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(hash) DO UPDATE SET previous_hash=excluded.previous_hash,
                       height=excluded.height, chainwork=excluded.chainwork,
                       header=excluded.header,
                       active=CASE WHEN ? IS NULL THEN headers.active ELSE excluded.active END""",
                (
                    index.block_hash,
                    previous_hash,
                    index.height,
                    str(index.chainwork),
                    index.header.serialize(),
                    int(bool(active)),
                    None if active is None else int(active),
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

    def load_undo(self, block_hash: bytes) -> BlockUndo | None:
        """Load persisted undo data for one connected block, if retained."""
        row = self._db.execute("SELECT payload FROM undo WHERE block_hash=?", (block_hash,)).fetchone()
        return None if row is None else _decode_undo(bytes(row[0]))

    def load_basic_filter(self, block_hash: bytes) -> tuple[bytes, bytes] | None:
        """Load or lazily index a block's BIP158 filter and BIP157 header."""
        row = self._db.execute(
            "SELECT encoded_filter, filter_header FROM basic_filters WHERE block_hash=?",
            (block_hash,),
        ).fetchone()
        if row is not None:
            return bytes(row[0]), bytes(row[1])

        pending: list[tuple[bytes, bytes]] = []
        cursor = block_hash
        previous_header = bytes(32)
        while True:
            cached = self._db.execute(
                "SELECT filter_header FROM basic_filters WHERE block_hash=?", (cursor,)
            ).fetchone()
            if cached is not None:
                previous_header = bytes(cached[0])
                break
            header_row = self._db.execute(
                "SELECT previous_hash FROM headers WHERE hash=?", (cursor,)
            ).fetchone()
            block_row = self._db.execute("SELECT 1 FROM blocks WHERE hash=?", (cursor,)).fetchone()
            undo_row = self._db.execute("SELECT 1 FROM undo WHERE block_hash=?", (cursor,)).fetchone()
            if header_row is None or block_row is None or undo_row is None:
                return None
            parent_hash = bytes(header_row[0])
            pending.append((cursor, parent_hash))
            if parent_hash == bytes(32):
                break
            cursor = parent_hash

        for current_hash, parent_hash in reversed(pending):
            block = self.load_block(current_hash)
            undo = self.load_undo(current_hash)
            if block is None or undo is None:
                return None
            encoded = encode_basic_filter(current_hash, basic_filter_elements(block, undo))
            filter_hash = compact_filter_hash(encoded)
            filter_header = compact_filter_header(filter_hash, previous_header)
            with self._db:
                self._db.execute(
                    "INSERT OR REPLACE INTO basic_filters(block_hash, encoded_filter, filter_hash, filter_header) "
                    "VALUES(?, ?, ?, ?)",
                    (current_hash, encoded, filter_hash, filter_header),
                )
            previous_header = filter_header

        row = self._db.execute(
            "SELECT encoded_filter, filter_header FROM basic_filters WHERE block_hash=?",
            (block_hash,),
        ).fetchone()
        return None if row is None else (bytes(row[0]), bytes(row[1]))

    def has_block(self, block_hash: bytes) -> bool:
        """Return whether serialized block data is available locally."""
        return self._db.execute("SELECT 1 FROM blocks WHERE hash=?", (block_hash,)).fetchone() is not None

    def is_active_block(self, block_hash: bytes) -> bool:
        """Return whether a known block belongs to the active chain."""
        return self._db.execute(
            "SELECT 1 FROM blocks WHERE hash=? AND active=1", (block_hash,)
        ).fetchone() is not None

    def find_transaction(self, txid: bytes) -> tuple[bytes, int, int, Transaction] | None:
        """Find a transaction in the active-chain transaction index."""
        row = self._db.execute(
            "SELECT block_hash, height, tx_position, payload FROM tx_index WHERE txid=?",
            (txid,),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0]), int(row[1]), int(row[2]), Transaction.deserialize(bytes(row[3]))

    def discard_side_blocks(self, block_hashes: tuple[bytes, ...]) -> None:
        """Remove downloaded block bodies that have not been connected."""
        with self._db:
            self._db.executemany("DELETE FROM blocks WHERE hash=? AND active=0", ((item,) for item in block_hashes))

    def active_block_hash(self, height: int) -> bytes | None:
        """Return the connected active-chain block hash at a height."""
        row = self._db.execute("SELECT hash FROM blocks WHERE height=? AND active=1", (height,)).fetchone()
        return None if row is None else bytes(row[0])

    def active_transaction_count(self, height: int) -> int:
        """Return the cumulative transaction count through an active-chain height."""
        row = self._db.execute(
            "SELECT COALESCE(SUM(tx_count), 0) FROM blocks WHERE active=1 AND height<=?",
            (height,),
        ).fetchone()
        return int(row[0])

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

    def load_coins(self, chain: HeaderChain | None = None) -> CoinsView:
        """Load the persisted UTXO set into an in-memory view."""
        rows = self._db.execute(
            "SELECT txid, output_index, value, script_pubkey, height, coinbase, median_time_past FROM coins"
        )
        view = CoinsView()
        for txid, index, value, script, height, coinbase, median_time_past in rows:
            if median_time_past == 0 and chain is not None and height > 0 and chain.tip is not None:
                parent = chain.tip.ancestor(height - 1)
                if parent is not None:
                    median_time_past = parent.median_time_past
            view.coins[(bytes(txid), index)] = Coin(
                value, bytes(script), height, bool(coinbase), median_time_past
            )
        return view

    def iter_coins(self):
        """Stream UTXO records in the same transaction-id/index order as the database."""
        rows = self._db.execute(
            "SELECT txid, output_index, value, script_pubkey, height, coinbase, median_time_past "
            "FROM coins ORDER BY txid, output_index"
        )
        for txid, output_index, value, script, height, coinbase, median_time_past in rows:
            yield (bytes(txid), int(output_index)), Coin(
                int(value), bytes(script), int(height), bool(coinbase), int(median_time_past)
            )

    def utxo_summary(self) -> tuple[int, int, int]:
        """Return output count, distinct transaction count, and total satoshis."""
        row = self._db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT txid), COALESCE(SUM(value), 0) FROM coins"
        ).fetchone()
        return int(row[0]), int(row[1]), int(row[2])

    def save_coins(self, view: CoinsView) -> None:
        """Replace the stored UTXO set with a supplied complete view."""
        with self._db:
            self._db.execute("DELETE FROM coins")
            self._db.executemany(
                "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase, median_time_past) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    (txid, index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase), coin.median_time_past)
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
            self._index_block_transactions(block, index)
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
                "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase, median_time_past) "
                "VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
                "value=excluded.value, script_pubkey=excluded.script_pubkey, "
                "height=excluded.height, coinbase=excluded.coinbase, median_time_past=excluded.median_time_past",
                (
                    (txid, index_num, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase), coin.median_time_past)
                    for (txid, index_num), coin in undo.spent
                ),
            )
            self._db.execute("UPDATE headers SET active=0 WHERE hash=?", (block_hash,))
            self._db.execute("UPDATE blocks SET active=0 WHERE hash=?", (block_hash,))
            self._db.execute("DELETE FROM tx_index WHERE block_hash=?", (block_hash,))
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
                median_time_past=index.previous.median_time_past if index.previous is not None else 0,
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
                    "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase, median_time_past) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
                    "value=excluded.value, script_pubkey=excluded.script_pubkey, "
                    "height=excluded.height, coinbase=excluded.coinbase, median_time_past=excluded.median_time_past",
                    (
                        (txid, output_index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase), coin.median_time_past)
                        for (txid, output_index), coin in undo.spent
                    ),
                )
                self._db.execute("UPDATE blocks SET active=0 WHERE hash=?", (_block_hash,))
                self._db.execute("DELETE FROM tx_index WHERE block_hash=?", (_block_hash,))
            for undo in new_undos:
                self._db.executemany(
                    "DELETE FROM coins WHERE txid=? AND output_index=?",
                    ((txid, output_index) for (txid, output_index), _coin in undo.spent),
                )
            for block, index in zip(new_blocks, new_indexes):
                self._index_block_transactions(block, index)
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
            median_time_past=index.previous.median_time_past if index.previous is not None else 0,
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
            "INSERT INTO coins(txid, output_index, value, script_pubkey, height, coinbase, median_time_past) "
            "VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txid, output_index) DO UPDATE SET "
            "value=excluded.value, script_pubkey=excluded.script_pubkey, "
            "height=excluded.height, coinbase=excluded.coinbase, median_time_past=excluded.median_time_past",
            (txid, output_index, coin.value, coin.script_pubkey, coin.height, int(coin.coinbase), coin.median_time_past),
        )

    def remove_unspendable_genesis_coinbase(self, block: Block) -> None:
        """Remove an incorrectly persisted genesis output from older Python databases."""
        if not block.transactions:
            return
        txid = block.transactions[0].txid
        with self._db:
            self._db.execute(
                "DELETE FROM coins WHERE txid=? AND height=0 AND coinbase=1",
                (txid,),
            )
            self._db.execute("DELETE FROM undo WHERE block_hash=?", (block.header.block_hash,))

    def _index_block_transactions(self, block: Block, index: BlockIndex) -> None:
        """Replace active-chain transaction index rows for one block."""
        self._db.execute("DELETE FROM tx_index WHERE block_hash=?", (index.block_hash,))
        self._db.executemany(
            "INSERT INTO tx_index(txid, block_hash, height, tx_position, payload) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(txid) DO UPDATE SET block_hash=excluded.block_hash, height=excluded.height, "
            "tx_position=excluded.tx_position, payload=excluded.payload",
            (
                (tx.txid, index.block_hash, index.height, position, tx.serialize())
                for position, tx in enumerate(block.transactions)
            ),
        )


def _encode_undo(undo: BlockUndo) -> bytes:
    data = {
        "height": undo.height,
        "spent": [
            [txid.hex(), index, coin.value, coin.script_pubkey.hex(), coin.height, coin.coinbase, coin.median_time_past]
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
            Coin(value, bytes.fromhex(script), height, coinbase, spent_row[6] if len(spent_row) > 6 else 0),
        )
        for spent_row in data["spent"]
        for txid, index, value, script, height, coinbase in [spent_row[:6]]
    )
    created = tuple((bytes.fromhex(txid), index) for txid, index in data["created"])
    return BlockUndo(data["height"], spent, created)

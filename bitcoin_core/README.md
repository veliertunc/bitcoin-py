# Modular Python Bitcoin node

This package contains the staged Python implementation in the Bitcoin Core
source tree. It is organized by protocol and responsibility:

- `primitives` and `serialization` implement transaction, block, and wire data.
- `crypto`, `encoding`, and `script` implement cryptographic, address, and
  script operations.
- `consensus` contains proof-of-work, block validation, and UTXO transitions.
- `consensus.blockfilter` builds BIP 158 basic filters and BIP 157 headers.
- `node.utxo_stats` streams active-chain UTXOs into Core-format statistics,
  including `hash_serialized_3` and the MuHash3072 commitment.
- `policy` and `node.mempool` handle transaction admission and relay policy.
- `prioritisetransaction` stores fee deltas separately from paid fees, and block
  template selection uses the resulting modified fee rate.
- `network` implements peer messages, handshakes, connections, and address
  management, including handshake deadlines and ping/pong liveness tracking.
- `node.relay` answers BIP35 mempool requests with fee-filtered inventory.
- `node.mempool_persistence` reads and writes Bitcoin Core's version-2
  `mempool.dat` format, revalidates transactions after restart, restores
  unbroadcast state, and backs the `savemempool` and `importmempool` RPCs.
- `node` composes synchronization, persistence, RPC, and process startup.
- `submitblock` accepts serialized mined blocks through the local block
  synchronizer and announces newly activated tips to connected peers.
- `getblocktemplate` builds BIP22-style templates from dependency-ordered
  mempool transactions, applying block weight and sigop limits and producing
  the active witness commitment. Proposal mode checks block validity against a
  staged copy of chainstate without committing changes.

The genesis coinbase is excluded from chainstate as in Bitcoin Core. Startup
also removes that output from databases created by earlier Python stages.

Run from a checkout with `python -m bitcoin_core --network regtest --datadir PATH`,
or install the package and use `bitcoin-py-node`. The node currently
implements a growing subset of Bitcoin Core; this package is not a complete
replacement for the C++ Bitcoin Core implementation yet.

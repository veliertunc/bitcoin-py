# Modular Python Bitcoin node

This package contains the staged Python implementation in the Bitcoin Core
source tree. It is organized by protocol and responsibility:

- `primitives` and `serialization` implement transaction, block, and wire data.
- `crypto`, `encoding`, and `script` implement cryptographic, address, and
  script operations.
- `script.describe` formats scripts for RPC output, recognizes standard output
  templates, and encodes their network-specific addresses.
- `consensus` contains proof-of-work, block validation, and UTXO transitions.
- `consensus.versionbits` provides a fork-aware BIP9 threshold state machine,
  signalling statistics, activation heights, and block-version construction;
  `getdeploymentinfo` reports the configured deployment state at a selected
  block.
- `consensus.blockfilter` builds BIP 158 basic filters and BIP 157 headers.
- `node.utxo_stats` streams active-chain UTXOs into Core-format statistics,
  including `hash_serialized_3` and the MuHash3072 commitment.
- `policy` and `node.mempool` handle transaction admission and relay policy.
- The mempool RPCs expose entry details, ancestor/descendant queries, and
  non-mutating `testmempoolaccept` evaluation.
- `prioritisetransaction` stores fee deltas separately from paid fees, and block
  template selection uses the resulting modified fee rate.
- `node.fee_estimator` persists six-block mempool coverage statistics, while
  `node.block_policy_estimator` persists decaying fee buckets over short, medium,
  and long confirmation horizons. `estimatesmartfee` combines the two policies,
  and `estimaterawfee` exposes per-horizon pass/fail bucket statistics.
- `network` implements peer messages, handshakes, connections, and address
  management, including handshake deadlines, ping/pong liveness tracking, and
  per-peer traffic counters and address-gossip rate limits for RPC diagnostics.
  BIP155 `sendaddrv2` negotiation
  and `addrv2` exchange support IPv4/IPv6, Tor v3, I2P, and CJDNS address
  records. Fresh routable IP announcements from small address messages are
  relayed to a keyed subset of peers that rotates daily; automatic outbound dialing remains
  limited to IPv4/IPv6. The
  `getnodeaddresses` RPC exposes the retained address records with network
  filtering. `setnetworkactive` pauses or resumes new inbound and outbound
  connections while leaving established peer sessions intact. `disconnectnode`
  closes a selected peer connection by address or stable peer ID. `addnode` and
  `getaddednodeinfo` manage runtime persistent peer targets and retry them while
  P2P networking is active. `setban`, `listbanned`, and `clearbanned` persist
  IP/subnet bans and enforce them on inbound and outbound connections.
  The `ping` RPC sends an immediate nonce ping to established peers, with round-
  trip samples reported through `getpeerinfo`.
- `node.relay` answers BIP35 mempool requests, negotiates BIP339 wtxid relay,
  rebroadcasts pending local transactions after chain updates, and uses a
  bounded per-peer orphan transaction pool.
- `node.mempool_persistence` reads and writes Bitcoin Core's version-2
  `mempool.dat` format, revalidates transactions after restart, restores
  unbroadcast state, and backs the `savemempool` and `importmempool` RPCs.
- `node` composes synchronization, persistence, RPC, and process startup.
- `submitblock` accepts serialized mined blocks through the local block
  synchronizer and announces newly activated tips to connected peers.
- `getblocktemplate` builds BIP22-style templates from dependency-ordered
  mempool transactions, applying block weight and sigop limits and producing
  the active witness commitment. Long polling waits for tip or mempool changes;
  proposal mode checks block validity against a staged copy of chainstate
  without committing changes. Signet templates require the `signet` client rule
  and expose the active challenge.
- `getmininginfo` reports current and next targets, and `getnetworkhashps`
  estimates hash rate from active-chain work and timestamps.
- `getblock` verbosity 3 includes input prevouts from block undo data, and
  `gettxoutsetinfo` can reconstruct historical active-chain UTXO statistics.

The genesis coinbase is excluded from chainstate as in Bitcoin Core. Startup
also removes that output from databases created by earlier Python stages.

Run from a checkout with `python -m bitcoin_core --network regtest --datadir PATH`,
or install the package and use `bitcoin-py-node`. The node currently
implements a growing subset of Bitcoin Core; this package is not a complete
replacement for the C++ Bitcoin Core implementation yet.

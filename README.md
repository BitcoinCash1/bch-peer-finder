# Bitcoin Cash Peer Finder

A zero-dependency Go implementation of just enough of the Bitcoin Cash P2P
stack to **discover, probe and rank healthy BCHN/bchd peers** for use in your
own `bitcoin.conf` via `addnode=` directives.

It does _not_ sync the chain, wallet anything, or relay transactions. It only:

1. Resolves the BCH mainnet DNS seeders.
2. Speaks the BCH P2P wire protocol (magic `e3 e1 f3 e8`, port 8333) from
   scratch — framing, varints, double-SHA256 checksums, `version`/`verack`,
   `addr`/`addrv2` (BIP-155), `inv`, `ping`/`pong`, `filterload`, `mempool`,
   `getaddr`.
3. Concurrently probes hundreds of peers, recursively growing its address pool
   from every `addr`/`addrv2` it receives — exactly how a real BCHN node
   bootstraps.
4. Filters by user-agent so eCash / BSV / ABC peers (which share BCH's magic
   bytes) don't pollute the output.
5. Ranks survivors by mempool depth, sync proximity to the median tip,
   service flags, latency and gossip willingness.
6. Writes the top N to a ready-to-paste `bch-addnodes.conf` (limited numbers of peer from the `-top` flag, default 50 peers). As well as a `bch-peers.json` JSON file containing all the results.

## Build

Simply `git clone` the repository and build:

```bash
cd bch-peer-finder
go build -o bch-peer-finder .
```

## Run

```bash
# Defaults: 80 workers, 3-minute crawl, top 50 peers
./bch-peer-finder

# Aggressive: 200 workers, 10-minute crawl, top 100 peers
./bch-peer-finder -workers 200 -duration 10m -top 100

# Just see what's out there, don't write files
./bch-peer-finder -out "" -json ""
```

### Flags

| Flag           | Default             | Meaning                                            |
| -------------- | ------------------- | -------------------------------------------------- |
| `-workers`     | 80                  | Concurrent peer probes                             |
| `-duration`    | 3m                  | Total crawl wall-clock time                        |
| `-probe`       | 12s                 | Per-peer read window after handshake               |
| `-top`         | 50                  | Number of peers to keep in the ranked output       |
| `-out`         | `bch-addnodes.conf` | `addnode=`-formatted output file                   |
| `-json`        | `bch-peers.json`    | Full JSON dump of every scored peer                |
| `-max-known`   | 50000               | Cap on the candidate address pool                  |
| `-ipv6`        | false               | Also crawl and rank IPv6 peers (default IPv4 only) |
| `-user-agents` | false               | Show observed user-agent counts                    |

Send `SIGINT` (Ctrl-C) and it'll stop early and still write whatever it has.

## Output

A typical run finishes with a console table like (example):

| rank | score | mempool | height |  rtt | user-agent                         |
| ---: | ----: | ------: | -----: | ---: | ---------------------------------- |
|    1 | 17234 |    5821 | 899451 | 42ms | /Bitcoin Cash Node:29.0.0(EB32.0)/ |
|    2 | 16980 |    5743 | 899451 | 51ms | /Bitcoin Cash Node:29.0.0(EB32.0)/ |
|    3 | 14102 |    3892 | 899451 | 88ms | /bchd:0.22.0(EB32.0)/              |

...and a file `bch-addnodes.conf` containing (limited to `-top` flag peer results, by default 50):

```conf
# score=5489 mempool=106 height=950733 latency=116ms ua=/Bitcoin Cash Node:29.0.0(EB32.0)/
addnode=70.50.144.93:8999

# score=5282 mempool=107 height=950733 latency=170ms ua=/Bitcoin Cash Node:29.0.0(EB32.0)/
addnode=8.214.158.13:8363
```

Drop the contents of `bch-addnodes.conf` into your BCHN `bitcoin.conf`, adapt if needed, and restart `bitcoind`. Done 🙂︎.

Finally, there is also a JSON file: `bch-peers.json` generated, containing all the results.

## How the scoring works

Every peer that completes the handshake and looks like real BCH gets:

```sh
score = mempool_count × 2
      + (mempool > 100        →  +500 )
      + (NODE_NETWORK         →  +500 )
      + (NODE_BLOOM           →  +200 )
      + (NODE_BITCOIN_CASH    →  +300 )
      + (BCHN client          →  +650 )
      + (bchd  client         →  +500 )
      + (knuth  client        →  +500 )
      + (within 6 of tip      → +2000 ; ≤100 → +1000 ; >1000 → 0)
      + (addrs shared         → min(2n, 200))
      + (proto ≥ 70015        →  +100 )
      − (latency_ms ÷ 5)
```

Peers that don't handshake, or whose user-agent isn't on the BCH whitelist
(`Bitcoin Cash Node`, `bchd`, `kth`, `Flowee`, `Bitcoin Verde`, `Bitcoin Unlimited`
with `EB` tag), get a score of zero and are excluded from the output.

The reference tip height is the **median** of `start_height` values reported
by all peers we've talked to — this self-corrects against individual peers
being slightly behind or ahead.

## Chain disambiguation: why user-agent filtering is critical

BSV and eCash both forked from BCH and **share the same network magic
bytes** (`e3 e1 f3 e8`). A naive crawler will happily handshake with them and
recommend their nodes as BCH peers — which would be useless (`addnode=` to a
BSV node achieves nothing for a BCH server).

We filter at the user-agent layer:

- **Accept**: `Bitcoin Cash Node`, `bchd`, `kth`, `Flowee`, `Bitcoin Verde`,
  `Bitcoin Unlimited`.
- **Reject**: anything containing `Bitcoin SV`, `BSV`, `eCash`, `Bitcoin ABC`,
  `Cashnodes`.

If a new BCH client appears, edit `isBCHUserAgent` in `peer.go`.

## File layout

```sh
bch-peer-finder/
├── go.mod
├── README.md
├── main.go        — AddrManager, worker pool, scoring, output
├── peer.go        — Per-peer probe + scoring heuristic
├── protocol.go    — Wire format: framing, varint, version/addr/addrv2/inv
└── seeds.go       — Mainnet DNS seeders + optional hardcoded fallback IPs
```

## Why this approach beats just grepping `getpeerinfo`

`bitcoin-cli getpeerinfo` gives you your **current** peers — typically 8–10
outbound, which `bitcoind` already chose. This tool actively maps a much
wider slice of the network (1000+ peers in a few minutes), ranks them by
freshness signals, and surfaces the ones you'd otherwise never connect to.

## Design notes / things you can tune

- **`filterload` before `mempool`**: BCHN requires the connecting peer to
  have set a bloom filter before it'll honour `mempool`. We send a
  match-all 1-byte filter to satisfy this.
- **Protocol version 70016**: matches current BCHN.
- **Routability filter** (`isRoutableIPv4` in `peer.go`): drops RFC 1918,
  CGNAT (100.64/10), 0.0.0.0/8, 127/8, multicast, link-local before
  enqueuing. Saves a lot of pointless dial timeouts.
- **AddrManager** is a FIFO; you can swap it for a priority queue keyed on
  e.g. ASN diversity if you want geographically-spread peers.
- **Hardcoded seed fallback** (`MainnetHardcodedSeeds` in `seeds.go`) is
  intentionally empty — populate it if you run somewhere DNS is blocked.
  BCHN itself ships the full packed list in `src/chainparamsseeds.h`.

## What it deliberately doesn't do

- No blockchain validation, no block download, no UTXO set.
- No wallet, no key handling.
- No transaction relay.
- No Tor / I2P / CJDNS. IPv6 is opt-in via `-ipv6` (off by default).
- No persistence between runs — each invocation starts fresh from DNS seeds.
  (Easy to add: dump `AddrManager.known` to disk on exit, reload on start.)

## References

- BCHN source: <https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node>
- bchd: <https://github.com/gcash/bchd>
- BIP-155 (addrv2): <https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki>
- Bitcoin Cash protocol reference: <https://reference.cash/protocol/network/messages>

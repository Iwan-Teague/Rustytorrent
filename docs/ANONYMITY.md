# RustyTorrent — Anonymity & Threat Model

This document spells out exactly what `--socks5` and `--anonymous` protect
against, what they don't, and how the two combine. **Read this before
trusting either flag with anything you actually care about.**

---

## Quick decision table

| Goal | Flags |
|---|---|
| Just hide my IP from peers and the tracker; still want incoming connections (e.g. behind a paid VPN with port-forwarding) | `--socks5 HOST:PORT` |
| Hide my IP **and** close all side-channels that leak it; no incoming peers, no DHT | `--socks5 HOST:PORT --anonymous` |
| Use Tor | `--socks5 127.0.0.1:9050 --anonymous` (Tor can't carry UDP — DHT & UDP trackers must be off) |

`--anonymous` is the strict bundle: it **refuses to start** without `--socks5`,
because anonymous-mode-without-a-proxy is a footgun that would happily dial
every peer from your real IP.

---

## Threat model

| Adversary | Without anon flags | With `--socks5` | With `--socks5 --anonymous` |
|---|---|---|---|
| Other peers in the swarm seeing your IP | ❌ exposed | ✅ they see the proxy IP | ✅ they see the proxy IP |
| Tracker logging announcing IPs | ❌ exposed (tracker sees source IP) | ✅ tracker sees proxy IP | ✅ tracker sees proxy IP; and we send `port=0` so you can't be back-connected |
| Passive ISP observer / DPI | ❌ sees BT traffic to clearnet peers | 🟡 sees BT traffic to proxy IP only | 🟡 sees BT traffic to proxy IP only |
| MSE/PE-aware DPI (looks at byte patterns) | ❌ plain BT is trivially fingerprinted | 🟡 still fingerprintable inside the proxy tunnel if peer chose plain | ✅ if proxy is Tor or commercial VPN, transport encryption hides BT shape; `--encrypt` forces MSE outbound for additional cover |
| Active DHT scraper enumerating swarms | ❌ your IP is in the DHT for everyone to scrape | 🟡 still exposed: DHT runs UDP, can't ride SOCKS5 CONNECT, but we leave it on unless `--anonymous` | ✅ DHT is forcibly **off** |
| Port-scan of your IP from the peer listen port | ❌ exposed by listener bind | ❌ still bound on your real IP | ✅ listener is **not bound** |
| Cross-session correlation by stable `peer_id` | ❌ same `-RT0100-…` prefix + 12 stable random bytes every run | ❌ peer_id still persisted | ✅ peer_id is freshly generated every run with a libtorrent-style `-LT2090-` prefix; rotated at every reannounce |
| Client-name fingerprint in BEP 10 extension handshake | ❌ `v = "rustytorrent <ver>"` and `reqq = 0` distinguish us | ❌ same | ✅ both keys omitted under `--anonymous`; only `m` dict emitted |
| Tracker User-Agent fingerprint | ❌ `rustytorrent/<ver>` | ❌ same | ✅ libtorrent-style UA sent per-announce |
| Cleartext HTTP tracker announce body inside the proxy tunnel | ❌ exposed | ❌ tracker IP masked but announce body still readable to observers between us and the proxy | ✅ `http://` trackers refused at startup; only `https://` and (where applicable) `udp://` allowed |
| Compromised proxy | n/a | ❌ proxy operator sees everything | ❌ proxy operator sees everything |
| Compromised proxy + correlation with tracker IP-allocation records | n/a | ❌ deanonymizable | ❌ deanonymizable (need a different transport, e.g. I2P) |

---

## What each piece does

### `--socks5 HOST:PORT [--socks5-user U --socks5-pass P]`

Routes every **outbound TCP connection** — peer dials AND HTTP/HTTPS tracker
requests — through a SOCKS5 proxy. Implemented in
[`src/socks5.rs`](../src/socks5.rs) by hand against
[RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928) + auth from
[RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929). Both no-auth and
username/password methods are supported.

We use the `socks5h://` URL form when handing the proxy to reqwest, which
forces remote DNS resolution — no clearnet DNS leak from tracker hostnames.

UDP trackers cannot be proxied through SOCKS5 CONNECT (which is TCP-only);
when a proxy is set, UDP trackers in the `announce-list` are silently skipped.

### `--anonymous`

A bundle flag that:

1. **Refuses to start without `--socks5`.** Anonymous mode without a proxy is
   a footgun.
2. **Disables the inbound TCP listener.** A bound listener exposes a port on
   your real IP that anyone in the swarm can reach. With the listener off you
   are outgoing-only.
3. **Disables the DHT** regardless of `--dht`. DHT uses UDP (can't go through
   SOCKS5), and announcing into the DHT broadcasts your real IP+port pair to
   the entire network.
4. **Randomizes peer_id every run** and skips persistence. The default
   behavior persists a stable peer_id across sessions — better network
   citizenship, worse anonymity.
5. **Sets `port=0` in tracker announces.** We don't run a public listener, so
   advertising a port is both a lie and a unique-fingerprint risk.

### `--encrypt`

Forces every outgoing dial to use MSE/PE rather than trying plain first.
Useful when the swarm is known to be MSE-only, or when you specifically want
the byte-level obfuscation MSE provides. **Note: MSE is obfuscation, not
encryption-of-record.** The RC4 cipher it uses is cryptographically broken;
treat MSE as protecting against trivial DPI fingerprinting, not against a
serious adversary.

### `--bind-iface IFACE`

VPN kill switch: pins outbound sockets to a specific interface (e.g. `utun0`)
so that if the tunnel drops, traffic fails closed instead of falling back to
the default route and leaking your real IP.

**Coverage — read this before relying on it:**

- ✅ **Peer dials** (TCP, and the first hop of a SOCKS5 chain) are bound to
  the interface. If it disappears, the dial fails rather than re-routing.
- ✅ **The DHT's UDP socket is bound to the interface** (`IP_BOUND_IF` /
  `SO_BINDTODEVICE`), so DHT traffic fails closed with the rest of the kill
  switch if the tunnel drops — DHT stays usable under `--bind-iface`.
- ✅ **µTP's UDP socket is bound to the interface** (`UtpSocket::from_udp`
  over `netbind::bind_udp_to_interface`), so `--utp` works under
  `--bind-iface` and fails closed with the rest of the kill switch if the
  tunnel drops.
- ⚠️ **Tracker HTTP is NOT interface-bound.** The HTTP client (`reqwest`)
  doesn't expose per-interface binding, so tracker announces ride the OS's
  normal routing. For a complete kill switch, **pair `--bind-iface` with
  `--socks5`** so the tracker rides the proxy (and point the proxy at the
  tunnel), or use `--no-tracker`. `--anonymous` (which requires `--socks5`)
  gives the strongest posture.

---

## Combining with Tor

Tor's SOCKS5 port (default `127.0.0.1:9050`) is supported. To use it:

```bash
rustytorrent download foo.torrent \
    --socks5 127.0.0.1:9050 \
    --anonymous
```

Tor caveats specific to high-volume P2P traffic:

- **Tor is TCP only** — DHT and UDP trackers can't go through it. `--anonymous`
  handles this by turning them off.
- **Tor exits are bandwidth-constrained** — expect 100 KB/s, not 10 MB/s. Be
  considerate of exit relay operators; don't seed long-term over Tor.
- **Tor + heavy P2P has a checkered history.** Past clients (incl. some big
  ones) leaked the real IP through DHT or PEX even when nominally "torified".
  This client closes DHT in `--anonymous` mode and never enabled PEX; we
  believe the visible attack surface from `--socks5 --anonymous` is just the
  outbound TCP connection through Tor's SOCKS port. If you find a leak vector,
  open an issue.

---

## What we don't (and can't) protect against

- **A compromised proxy** sees everything you do. Pick your proxy carefully.
  Tor distributes trust across three relays; commercial VPNs concentrate it
  in one operator.
- **Traffic-analysis correlation.** An observer who can watch both your link
  and the proxy/exit can correlate timing & volume. Tor mitigates some of
  this, no proxy does.
- **OS-level leaks** (DNS resolved by another process, ICMP, etc.) are out of
  scope. Use a system-wide VPN or transparent-proxy setup if those matter.
- **Application-level leaks in this codebase** — e.g. accidentally including
  a hostname in a log line. We try to keep these minimal. Report them.
- **The `daemon` subcommand does not support `--anonymous`.** The
  multi-torrent daemon's sessions dial clearnet (tracker-only, DHT off)
  and the privacy flags are not yet wired through `SessionManager`. Do not
  use `daemon` for anonymous workloads. Its web UI is loopback-only, like
  `--web`, and the only outbound it makes is the runtime magnet/tracker
  bootstrap for `POST /api/add_magnet` — also clearnet.
- **µTP (BEP 29) is implemented** (UDP-based, raced against TCP on every
  dial). Because UDP can't ride a SOCKS5 CONNECT, µTP is **force-disabled**
  under `--anonymous` and `--socks5` — exactly the hard-off treatment DHT
  gets — so it is *not* a leak vector there. Under `--bind-iface` (no
  proxy) µTP stays on but its socket is interface-bound, so it fails closed
  with the kill switch. The only configuration where µTP egresses on the
  default route is plain clearnet (no privacy flags), which is by
  definition not trying to be anonymous.

---

## Verification

The SOCKS5 client is verified by 11 unit tests in
[`src/socks5.rs`](../src/socks5.rs), including:

- Wire-layout checks for IPv4 and IPv6 CONNECT requests.
- A full no-auth handshake roundtrip against an in-process mock proxy.
- A full USER/PASS handshake roundtrip with credential validation.
- The "no acceptable methods" error path.
- The "destination refused" reply path.

End-to-end verification with the bundled
[`tests/mini_socks5.py`](../tests/mini_socks5.py) test proxy:

```
seeder        :7400  (rustytorrent --no-tracker)
mini SOCKS5   :7300  (python tests/mini_socks5.py 7300)
leecher       :7500  rustytorrent --no-tracker
                     --anonymous --socks5 127.0.0.1:7300
                     --peer 127.0.0.1:7400
→ 32 MiB downloaded in 1 s, MD5 byte-identical
```

The leecher's startup banner confirms anonymous mode is engaged:

```
Proxy:      127.0.0.1:7300 (SOCKS5)
Anonymous:  on (DHT off, listener off, peer_id ephemeral, port=0 in announces)
[INFO  engine]: anonymous mode: DHT off, listener off, port=0 in announces
[INFO  engine]: routing peer + tracker traffic through SOCKS5 proxy=127.0.0.1:7300
```

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
| Cross-session correlation by stable `peer_id` | ❌ same `-RT0100-…` prefix + 12 stable random bytes every run | ❌ peer_id still persisted | ✅ peer_id is freshly generated every run, never persisted |
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
- **µTP (BEP 29).** We use TCP for the peer wire protocol. Many real-world
  clients support µTP, which is UDP-based and bypasses the SOCKS5 path
  entirely. Since we don't implement µTP at all, this isn't an active leak —
  but if/when we do, it'll need its own proxy story (or a hard-off in
  anonymous mode, like DHT).

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

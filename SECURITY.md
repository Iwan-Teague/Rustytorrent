# Security Policy

`rustytorrent` is a peer-to-peer file transfer client. Like the rest of
the suite, we take vulnerability reports seriously and want to make it
easy to send one in.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use one of these private channels:

- **GitHub Security Advisories** (preferred). Open a draft advisory at
  <https://github.com/Iwan-Teague/Rustytorrent/security/advisories/new>.
  The form lets you describe the issue, propose a fix, and request a
  CVE; only repository maintainers and the people you invite can see
  it until you publish.
- **Email**: `teague.iwan@outlook.com`. Plain English is fine. PGP is
  not required; if you'd like an encrypted channel anyway, ask in the
  initial mail and a key will be supplied for the reply.

When you report, please include:

1. A description of the vulnerability and which module it lives in
   (`src/peer/`, `src/tracker/`, `src/dht/`, the web monitor, ...).
2. The shortest reproduction you can produce — a malformed metainfo
   file, tracker/DHT/PEX response, peer wire message, whatever applies.
   Avoid live exploitation of third-party swarms or deployments.
3. The impact you think the issue has (information disclosure, DoS,
   integrity, path traversal via filenames, etc.) and any mitigation
   you've identified.
4. Whether you'd like to be credited in the resulting advisory.

Expected response times:

- **Acknowledgement**: within 72 hours.
- **Initial assessment** (severity, scope): within 7 days.
- **Patch release** (measured from confirmation, per severity):

  | Severity | Patch release target |
  |----------|----------------------|
  | Critical | 48 hours |
  | High     | 7 days |
  | Medium   | 30 days |

  Lower severities are best-effort and ride the normal release
  train.

If you don't hear back within 72 hours, please escalate by emailing
again with a subject prefix `[BUMP]` — the original mail may have
been caught in a filter.

## Supported versions

The `main` branch is the only supported release line; we don't ship
LTS branches yet. Once stable releases are cut, this section will list
explicit supported version windows.

## Known protocol-mandated legacy primitives (X2 exemptions)

BitTorrent v1 hard-codes two legacy primitives that cannot be removed
without breaking interoperability. Both are used **non-confidentially**
under the suite's X2 exemption policy (ADR-012 X2 / charter T2 §K),
with dated rows in `deny.toml`:

- **RC4** (`src/peer/mse/rc4.rs`): BEP-8 MSE handshake *obfuscation
  only* — it defeats ISP traffic shaping, not attackers. Exemption
  expires 2027-03-01.
- **SHA-1**: the BT-v1 info-hash (protocol-mandated identifier and
  piece integrity). Not a confidentiality or authentication boundary.
  Exemption expires 2027-03-01.

Reports about the *strength* of these primitives themselves will be
closed as known/intentional; reports about anything these primitives
are (mis)used to *protect* are very much in scope.

## Scope

In scope for security reports:

- Parsing of untrusted input: metainfo/.torrent files, tracker HTTP
  responses, DHT bencoding, PEX messages, peer wire protocol frames.
- The MSE/PE handshake and its key material (DH exchange, RC4 state
  hygiene, `zeroize` coverage).
- The `--paranoid` encrypted spool (AES-GCM/Argon2 passphrase
  handling, key wiping, on-disk state).
- The web monitoring server (auth, injection, CSRF, information
  exposure).
- The `--bind-iface` / kill-switch behaviour: traffic leaking outside
  the bound interface.
- Supply-chain integrity: build/CI, dependency policy (`deny.toml`),
  action pinning.

Out of scope:

- Volume of the Denial-of-service kind inherent to running a public
  BitTorrent client.
- Attacks requiring control of the user's local machine already.

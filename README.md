# Wake & Actions — Jen Plugin

Wake-on-LAN from any Lease, Reservation, or Device row in [Jen](https://github.com/ltkojak/jen-kea), plus a favourites list for the hosts you wake often — the first plugin built on Jen's row actions.

> **IPv4 only.** A wake target is identified by its IPv4-side subnet for broadcast purposes. This isn't a bug or a gap to report — it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.65.2 or later

## How a wake packet is sent

A standard 102-byte Wake-on-LAN magic packet (six `0xFF` bytes, then the target MAC repeated 16 times), with an optional 4- or 6-byte SecureOn password appended, is sent over a broadcast UDP socket to port 9 at **both** the target subnet's own directed broadcast address (computed from its CIDR) and the limited broadcast address `255.255.255.255`. Jen is usually on the same L2 network as its subnets, where either address works; if a target is on a *different* L2, the router between them must be explicitly configured to forward directed broadcasts — this plugin cannot make that work by itself, and most home routers don't do it by default.

## Features

- **Wake** row action on Lease, Reservation, and Device rows — sends a packet with one click and a confirmation naming the actual MAC
- **Favourites** page (nav Management → Wake): save a MAC (with an optional label, an IP to show on the row, and a SecureOn password that a blank re-add keeps), wake it with one click, see when it was last woken and by whom
- **Rate-limited**: at most one wake packet per MAC every 5 seconds, whichever entry point sent it
- Every wake is audited (`WOL_SENT`) and emits a `plugin.wol.sent` event
- **JSON API**: `POST /api/v1/plugins/wol/wake` `{"mac": "..."}` (write key), scoped to the calling key's accessible subnets
- Respects Jen's subnet access control on both the favourites list and the "Add Favourite" picker — a favourite on a subnet you can't see is neither shown nor wakeable. The subnet of a wake or a new favourite is worked out from the MAC (its active lease, then its reservation) — never from a value in the request — and a MAC Jen has never seen has no subnet, so it is for accounts that can see every subnet (API keys too). Adding, removing, and waking a favourite, and using the row action, all need admin — viewers are read-only

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Wake & Actions. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/wol/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute, an un-nonce'd `<script>`, or a POST form missing `csrf_token`, `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function — MAC normalisation, the magic packet builder (checked byte-for-byte against a hand-computed packet), SecureOn password parsing, directed-broadcast address computation, and the rate-limit window — plus calls `register(app)` end to end against a stub `jen.plugin_api`, no Jen, database, or network access needed.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau

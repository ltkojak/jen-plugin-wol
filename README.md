# Wake & Actions — Jen Plugin

Wake-on-LAN from any Lease, Reservation, or Device row in [Jen](https://github.com/ltkojak/jen-kea), plus a list of saved hosts for the ones you wake often — the first plugin built on Jen's row actions.

> **IPv4 only.** A wake target is identified by its IPv4-side subnet for broadcast purposes. This isn't a bug or a gap to report — it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.68.0 or later

## How a wake packet is sent

A standard 102-byte Wake-on-LAN magic packet (six `0xFF` bytes, then the target MAC repeated 16 times), with an optional 4- or 6-byte SecureOn password appended, is sent over a broadcast UDP socket to port 9 at **both** the target subnet's own directed broadcast address (computed from its CIDR) and the limited broadcast address `255.255.255.255`. Jen is usually on the same L2 network as its subnets, where either address works; if a target is on a *different* L2, the router between them must be explicitly configured to forward directed broadcasts — this plugin cannot make that work by itself, and most home routers don't do it by default.

## When the host is on another subnet or Jen runs in Docker

A wake that is sent is not a wake that arrived. Before it answers, the plugin asks Jen whether Jen's own host has an address in the subnet the wake was sent on, and says what it found:

- **Jen has an address in that subnet**: *Wake packet sent to ...*, as before.
- **Jen has no address in that subnet**: a warning, *Wake packet sent toward 10.0.2.255 for aa:bb:cc:dd:ee:ff. Jen has no address in that subnet, so it arrives only if a router forwards directed broadcasts.* A directed broadcast crosses a router only if the router is configured to forward directed broadcasts, and most are not by default.
- **Jen does not know which subnet the MAC is on** (no lease, no reservation, no device record): a warning that the packet was sent on Jen's own network only. Only `255.255.255.255` was targeted, and that address never leaves the network Jen's host is on.
- **The MAC is on a subnet Jen is not configured for** (a Kea subnet that is not in Jen's subnet list; since 1.2.1): a warning, *Wake packet sent on Jen's own network only: subnet 7 is not one Jen is configured for.* Jen has no broadcast address for that subnet, so again only `255.255.255.255` was targeted.
- **Jen could not be asked** (its subnet information did not answer, or, since 1.2.1, the host has no `ip` command to read its own addresses with): the plain *sent* sentence. The packet went out either way; the check only words the answer and never stops or redirects a wake.

The API answer carries the same fact as `on_link` (`true`, `false` or `null`) beside `targets`, the addresses the packet was sent to.

**Docker.** Under Docker's default bridge network the packet does not reach the LAN at all: inside the container `255.255.255.255` is the Docker bridge, and the Docker host does not forward a directed broadcast. Wake needs the container on the LAN itself: host networking (`network_mode: host`) or a macvlan network. Jen's container image up to 7.2.0-beta.5 has no `ip` command, so in it Jen cannot say which addresses it has: the answer is the plain *sent* sentence, `on_link` is `null` and the audit row says `on_link=unknown`, on the bridge network as well as under host networking (since 1.2.1; 1.2.0 warned on every wake that Jen has no address in the subnet, which was false under host networking). The warning needs an image or a host that has the `ip` command.

## Features

- **Wake** row action on Lease, Reservation, and Device rows — sends a packet with one click and a confirmation naming the actual MAC
- **Saved hosts** on the Wake page (nav Management → Wake, **Save Host**): save a MAC (with an optional label, an IP to keep with it, and a SecureOn password that a blank re-add keeps; the password is stored encrypted and never shown again), wake it with one click, see when it was last woken and by whom
- **On the Investigation page** (Jen 5.68.0): a card under "What else Jen knows" for a saved host — its label, whether a SecureOn password is set, and when it was last woken and by whom. A saved host is judged by the subnet it was saved in on every surface (the list, add, delete, the wake from the list), so it is not shown or editable by an account that cannot see that subnet just because the host has since moved into one it can; a wake itself is judged on where the host is now, and never uses the SecureOn password of a saved host the account may not see; where the host is now is shown only when the account may see that subnet too
- **Investigate** on every saved host's row, Jen's own action for a row that names a client
- **Rate-limited**: at most one wake packet per MAC every 5 seconds, whichever entry point sent it
- Every wake is audited (`WOL_SENT`) and emits a `plugin.wol.sent` event. The audit row says how the wake was asked for and where it went: `via=favorite|row|page|api subnet_id=<N or none> on_link=yes|no|unknown`, and a wake through the API starts with `[api-key:<name>]`, the same prefix Jen's own API writes carry
- **JSON API**: `POST /api/v1/plugins/wol/wake` `{"mac": "..."}` (write key), scoped to the calling key's accessible subnets. A wake that was sent answers `{"ok": true, "mac": "...", "on_link": true|false|null, "targets": ["10.0.2.255", "255.255.255.255"]}`
- **A wake is refused when the saved settings cannot be read**: if the lookup of the MAC's saved host fails (the database did not answer), nothing is sent, because the saved host may hold a SecureOn password the NIC requires. The page says *Could not read the saved wake settings - nothing was sent. Try again in a moment.* and the API answers 503
- Respects Jen's subnet access control on both the list of saved hosts and the "Save Host" picker — a saved host on a subnet you can't see is neither shown nor wakeable. The subnet of a wake or a new saved host is worked out from the MAC (its active lease, then its reservation, then the device's last known subnet, which is what a host that is asleep usually still has) — never from a value in the request — and a MAC Jen has never seen has no subnet, so it is for accounts that can see every subnet (API keys too). Adding, removing, and waking a saved host, and using the row action, all need admin — viewers are read-only
- **The words.** The page, its messages and the Investigation card say *saved host* since 1.2.1, because the word used before is now the name of Jen's pinned pages (`Favorites` in the navigation). The names behind the page are unchanged and still carry the older word: the routes `/management/wol/favorites/...`, the audit actions `WOL_ADD_FAVORITE` and `WOL_DELETE_FAVORITE`, and the audit detail `via=favorite`

## Recorded for the audit trail, not displayed

`wol_hosts.ip` is the optional address typed into the Save Host form. It is stored with the saved host (only when it is an address in the subnet the MAC is in) and nothing in this plugin reads it back: a wake is aimed by the MAC and the subnet's broadcast address, and no page or API response shows the IP. The column is kept as the record of what was entered and is not dropped. (`last_woken_at` and `last_woken_by`, which look similar, are shown on the list of saved hosts.)

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Wake & Actions. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/wol/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute, an un-nonce'd `<script>`, or a POST form missing `csrf_token`, `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function — MAC normalization, the magic packet builder (checked byte-for-byte against a hand-computed packet), SecureOn password parsing, directed-broadcast address computation, and the rate-limit window — plus calls `register(app)` end to end against a stub `jen.plugin_api`, and runs the wake routes against a fake database and a socket that records where each packet was sent; no Jen, database, or network access needed.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau

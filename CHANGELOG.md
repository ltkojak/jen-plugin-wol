# Wake & Actions Plugin — Changelog

## [1.0.0] - 2026-09-24

### First release

Wake-on-LAN from any Lease, Reservation, or Device row, plus a
favourites list for the hosts you wake often — the first plugin
built on Jen's row actions. A single click sends a standard 102-byte
magic packet (with an optional SecureOn password) over broadcast UDP
to both the target subnet's directed broadcast address and
`255.255.255.255`, so a target on the same L2 as Jen wakes reliably
without any extra router configuration.

Every wake is rate-limited to once per MAC every five seconds,
audited, and raises a `plugin.wol.sent` event. Favourites remember a
label, an optional SecureOn password, and when they were last woken
and by whom; a small JSON API lets another tool send a wake with a
Jen API key. Everything respects Jen's subnet access control — a
favourite on a subnet you can't see is neither shown nor wakeable.

Built on Jen 5.61.0's plugin API v3 from the first commit: sprite
icons, a phone-ready rowlist, and no inline styles.

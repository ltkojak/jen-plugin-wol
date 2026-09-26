# Wake & Actions Plugin — Changelog

## [1.0.2] - 2026-09-25

Requires Jen 5.65.6 or later (`client_subnet_for_mac` in the plugin API). Adds one migration (the `secureon` column becomes `TEXT` so it can hold the encrypted form); it runs by itself on the next start.

### Fixed: the SecureOn password was stored in clear

Every other plugin credential is stored with Jen's `encrypt_secret`; a favourite's SecureOn password was inserted exactly as typed. It is now encrypted on write, and never shown again (the page has only ever shown whether one is set). A favourite saved by 1.0.0 or 1.0.1 still wakes: a stored value that is not in Jen's encrypted format is accepted as the legacy plain value it is, and is re-encrypted in place the first time it is used. A stored value that cannot be decrypted (a restored database with a different key) refuses the wake with a plain message instead of sending a packet without the password.

### Changed: one place decides which subnet a MAC is in

The plugin carried its own lookup (a lease, then a reservation); Jen now offers one precedence to every plugin, `client_subnet_for_mac` (current lease, then reservation, then the device's last known subnet), and this plugin uses it. The device fallback means a MAC Jen only knows from its devices table now has a subnet to be judged on.

### Fixed: raw exception text on the page

A failed send, add, or remove put the exception's own text into the page. The details go to Jen's log and the page shows a generic message.

### Changed

- `tools/test_plugin.py` covers the SecureOn round trip, the legacy read and re-encrypt, an undecryptable value, and the failed-send message.

## [1.0.1] - 2026-09-25

Requires Jen 5.65.2 or later (the `can_access_subnet` and `api_key_can_access_subnet` helpers in the plugin API).

### Fixed: routes authorised one thing and acted on another

The wake packet always also goes out on the limited broadcast (`255.255.255.255`) to the Jen host's own segment, so the subnet check was the only thing standing between a subnet-restricted admin and waking any host on that segment. Four places got it wrong. The pattern this release names in every plugin: a route authorises on one thing (a subnet id the caller typed, or nothing for a by-id POST) and acts on another, or reads "no subnet" as "allow".

- **"Wake" from a lease, reservation or device row** authorised the `subnet_id` in the query string, which is only what the row that linked there happened to know. A caller could name a subnet they own and wake a MAC in another. The value is now ignored; the subnet is the one the MAC is in (its active lease, then its reservation, then, for a MAC with neither, the subnet stored on its favourite).
- **Adding a favourite** worked the subnet out from the optional IP field, so any MAC could be attached to a subnet the caller owns. The subnet now comes from the MAC; a typed address that is not in it is not stored. A MAC Jen has never seen has no subnet and is for accounts that can see every subnet.
- **Removing a favourite** by id checked nothing about the row; it now reads as not found unless the row's subnet is the caller's (a favourite with no subnet is an unrestricted account's).
- **The wake API** let a MAC with no attributable subnet through to a subnet-scoped key. That is now for unrestricted keys only.

### Fixed: re-adding a favourite with a blank SecureOn erased the saved password

The upsert wrote the blank over the stored value. A blank field now keeps what is saved (the form says so).

### Fixed: the rate-limit map grew for as long as Jen ran

Every distinct MAC ever woken stayed in the once-per-five-seconds map forever. Each wake now drops entries older than a minute.

### Corrected: the version floor

1.0.0's README and changelog said Jen 5.61.0 while its manifest said 5.57.0; 5.57.0 was the true floor for 1.0.0, which used only the row-action and plugin-API v3 surfaces that existed then. 1.0.1 uses the subnet helpers added in Jen 5.65.2, so all three now say 5.65.2.

### Changed

- The row action link no longer carries `ip` and `subnet_id` (the route ignores both).
- The page's static styling moved out of inline `style=` attributes into its own `<style>` block; `tools/verify.py` now fails a template that carries one.
- `tools/test_plugin.py` now runs the real routes and the API against fakes: a MAC in another subnet is not woken whatever the query string says, a blank SecureOn keeps the stored one, and the rate map is pruned.

## [1.0.0] - 2026-09-24

*Correction, 2026-09-25: the last paragraph below says this release was built on Jen 5.61.0's plugin API; the floor it actually needed, and declared in its manifest, was Jen 5.57.0.*

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

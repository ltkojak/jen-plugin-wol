# Wake & Actions Plugin — Changelog

## [1.1.2] - 2026-10-06

Fix: the rule 1.1.1 applied to the Investigation card now applies to every surface of the plugin. No change to what Jen needs:
`requires_jen` stays 5.68.0.

### Fixed: a favourite is judged by its stored subnet on the page, in add and delete, and in the wake

1.1.1 stopped the Investigation card from judging a favourite by where its MAC is now, and left the rest of the plugin as it
was. The favourites list, "Add favourite" over an existing MAC, delete, and the wake from a favourite all still judged the row
on the MAC's current subnet with the stored one as a fallback, so a favourite saved in subnet B (its label, whether a SecureOn
password is set) listed for a caller scoped to A once the client moved to A, and that caller could rewrite its label, address
and SecureOn password or delete it. A favourite is a stored object and is now judged on its own stored subnet everywhere; a
favourite with no subnet is for an unrestricted caller only. Where the host is now appears on the list as *now in …* only when
the caller may see that subnet.

### Fixed: a wake never borrows a favourite's SecureOn password the caller may not see

A wake is an act on a live host and is still judged on where the host is now — that is the network the packet is sent to. But
the wake from a row (the *Wake* row action) and the wake API read the stored favourite's SecureOn password first and judged the
subnet afterwards, so a caller scoped to A waking a host now in A used a hidden favourite's password stored in B, and an API key
did the same. The password is now read for a wake only when the favourite's own stored subnet is in the caller's scope (the
session's, or the key's for the API); a favourite out of scope contributes nothing to the wake, neither its password nor its
stored subnet as a fallback, so the wake goes ahead without it and a NIC that wants the password ignores the packet. Waking from
the favourites list needs both: the favourite in scope by its stored subnet, and the host's current subnet in scope.

## [1.1.1] - 2026-10-06

Fix to the investigation provider added in 1.1.0. No change to what Jen needs: `requires_jen` stays 5.68.0.

### Fixed: a favourite is judged by the subnet it was saved in, not by where the client is now

1.1.0 judged the Investigation card by the subnet the MAC is in now, falling back to the favourite's own. That is the right
question for a wake, which acts on a live host, and the wrong one for showing stored data: a favourite saved in subnet B
(its label, whether a SecureOn password is set, who last woke it) was shown to a caller scoped to subnet A as soon as the
client's lease moved to A. A favourite is now judged by its own stored subnet, and a favourite with no subnet is for an
unrestricted caller only. Where the client is now is shown on the card as **Now in** when the caller may see that subnet —
only ever as a fact, and never named when it is a subnet the caller cannot see. The wake itself is unchanged.

## [1.1.0] - 2026-10-04

Requires Jen 5.68.0 (a 5.68.0 beta satisfies it): this release registers an **investigation provider**.

### Added: favourite, SecureOn and last wake, on Jen's Investigation page

Jen's Investigation page (`/client`) now has a "What else Jen knows" section on its Overview, and this plugin
contributes one card to it for a client that is a saved favourite: its label, whether a SecureOn password is set (never
the password), and when and by whom it was last woken. A client that was never saved here adds no card.

The card is judged the way a wake of the same MAC is: on the subnet the MAC is in now (Jen's one precedence), falling
back to the subnet stored on its favourite, and a client outside the caller's scope — or in no subnet, for a restricted
caller — gets nothing. `requires_jen` moves to 5.68.0 because the hook does not exist before it.

## [1.0.4] - 2026-09-27

Follow-up to 1.0.3, found while Jen's own authorization matrix added a row for a malformed API
body on every plugin API route.

### Fixed: a malformed JSON body crashed the wake API instead of refusing it

`_api_wake` read its body as `request.get_json(silent=True) or {}` — the `or {}` only rescues a
falsy body (`None`, an empty object), so a JSON array or any other non-object value reached
`body.get("mac", "")` directly and raised `AttributeError`, an unhandled 500. It now goes through
Jen's shared `json_object_body()`/`str_field()` (the same helpers every other plugin API route
already uses), which refuse a malformed body with a real `400 {"error": "expected a JSON object"}`
before touching it. A non-string `mac` (`{"mac": 5}`) is unaffected — it was, and still is, a
caller-visible "invalid mac".

### Changed

- `tools/test_plugin.py` sends a JSON array to `_api_wake` and checks it gets 400, not an
  uncaught exception.

## [1.0.3] - 2026-09-27

Jen's Q100 sweep: the favourites list, adding one, deleting one and waking one judged access on the
STORED subnet a favourite was created with, which nothing ever refreshed — the same shape of bug
Presence 1.0.2 fixed for tracked devices. `wake_from_row` and the JSON API already judged the MAC's
CURRENT subnet correctly; the favourites themselves did not.

### Fixed: a moved favourite stayed visible, and wakeable, to the wrong administrator

A favourite is added once and its subnet stored then. If the device later moves — a new lease in a
different subnet, a changed reservation — the favourites list, deleting a favourite and waking one all
still judged access on that stale stored value. An administrator scoped to subnet A who had favourited a
laptop still saw it, and could wake it, after it moved to subnet B; an administrator newly responsible for
subnet B would not see it at all. Every one of the three now judges the MAC's subnet as it is right now
(Jen's one precedence: a current lease, then a reservation, then the device's last known subnet), falling
back to the stored value only when the MAC has none currently — the list's display and the packet's
target broadcast domain move with it too.

### Fixed: re-adding an existing favourite could silently reassign it

"Add Favourite" for a MAC that already had one judged access on the MAC's current subnet and then
overwrote the existing row's subnet, address and label. An administrator who could see where the MAC is
now could take over — and relocate — a favourite an administrator for a different subnet had created,
without ever being checked against the row they were about to change. The existing row, when there is
one, is now authorised on its own subject first (current subnet, its own stored value as the fallback),
and this route never moves a favourite's subnet.

### Fixed: two smaller findings from the same audit

- The JSON API mapped a stored SecureOn password that could not be decrypted — a clear, caller-visible
  refusal ("enter it again") — to a 500, the same as an actual server fault. It is `409` now.
- `_wake_subject` (behind `wake_from_row` and the JSON API) had no exception handling around its
  database read at all; a failure there used to propagate into an uncaught error. It now degrades to
  judging the wake on the MAC's current subnet alone and logs the failure, rather than crashing.

### Changed

- The MAC check delegates to Jen's shared `normalize_mac()`.
- `tools/test_plugin.py` checks a favourite that moved into and out of the caller's subnet directly, that
  re-adding an existing favourite never changes its stored subnet, and the new 409 mapping.

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

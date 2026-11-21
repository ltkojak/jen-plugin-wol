"""
Wake & Actions plugin for Jen.
Wake-on-LAN from any lease, reservation, or device row, plus a
favorites list for the hosts you wake often — the first consumer of
Jen's Q73 row actions. Version lives in manifest.json — not
duplicated here.

Magic packet (v1.0.0)
──────────────────────
A standard Wake-on-LAN magic packet is exactly 102 bytes: six 0xFF
bytes followed by the target MAC address repeated 16 times (16 × 6 =
96 bytes). An optional SecureOn password — 4 or 6 raw bytes, a
vendor-specific anti-spoofing feature scoped to the local broadcast
domain — is appended after those 102 bytes when the target expects
one. It travels in clear with every wake, and it is stored encrypted
(v1.0.2) and never shown again. Sent via a `SO_BROADCAST` UDP socket
to port 9, at BOTH the target subnet's own directed broadcast address
(computed from the subnet's CIDR) and `255.255.255.255`. Jen is
usually on the same L2 as its subnets; a target on a different L2
needs directed broadcast explicitly allowed on the router in between,
which this plugin cannot make work by itself. Since v1.2.0 the wake
asks Jen's `subnet_context` whether Jen has an address in the target
subnet and says so when it has none (see `_jen_on_link`,
`sent_message`).

Rate limiting (v1.0.0)
────────────────────────
One wake packet per MAC per 5 seconds — a module-level
`{mac: last_sent_monotonic_time}` dict, checked and updated by the
route before sending. Jen runs single-process (ARCHITECTURE §6), so
this in-memory limiter is correct without any cross-process
coordination.
"""

import ipaddress
import logging
import os as _os
import re
import socket
import time

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from jen.plugin_api import is_admin_or_above, require_write

logger = logging.getLogger(__name__)

PLUGIN_ID = "wol"

bp = Blueprint(
    "wol",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/management/wol",
)

_WOL_PORT = 9
_RATE_LIMIT_WINDOW_S = 5

_VIEWER_MESSAGE = "Viewers can look at Wake & Actions but not send a wake packet."


# ── Pure: MAC/SecureOn parsing, the magic packet builder, broadcast math ──────


def _normalize_mac(raw):
    """'' for no MAC given or garbled input, the lowercase MAC for a valid one. Delegates to
    plugin_api's normalize_mac() (which returns None for both cases); this wrapper keeps this
    plugin's own '' convention so every existing call site is unchanged."""
    if not raw:
        return ""
    from jen.plugin_api import normalize_mac

    return normalize_mac(raw) or ""


def parse_mac_bytes(mac):
    """Pure: 'aa:bb:cc:dd:ee:ff' (any case/separator) -> the 6 raw
    address bytes, or None if it doesn't parse to a real MAC."""
    normalized = _normalize_mac(mac)
    if not normalized:
        return None
    return bytes.fromhex(normalized.replace(":", ""))


def parse_secureon(raw):
    """Pure: a SecureOn password ('aa:bb:cc:dd' or a full 6-byte
    MAC-style password, any separator) -> (bytes, None) | (None,
    reason). 4 or 6 bytes are the only two forms real hardware uses."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw or "")
    if not cleaned:
        return None, "empty SecureOn password"
    if len(cleaned) not in (8, 12):
        return None, "SecureOn password must be 4 or 6 bytes (8 or 12 hex digits)"
    return bytes.fromhex(cleaned), None


_ENCRYPTED_PREFIX = "v1:"


def is_encrypted_secureon(stored):
    """Pure: is a stored SecureOn value in Jen's encrypted format (`v1:...`)? Anything else is a
    legacy value from 1.0.0 and 1.0.1, which stored the password exactly as typed."""
    return bool(stored) and str(stored).startswith(_ENCRYPTED_PREFIX)


def build_magic_packet(mac, secureon=None):
    """Pure: the Wake-on-LAN magic packet for `mac` — 6×0xFF + 16×MAC
    (102 bytes) — with `secureon` (raw bytes, already parsed) appended
    if given. None if `mac` doesn't parse."""
    mac_bytes = parse_mac_bytes(mac)
    if mac_bytes is None:
        return None
    packet = b"\xff" * 6 + mac_bytes * 16
    if secureon:
        packet += secureon
    return packet


def directed_broadcast(cidr):
    """Pure: the directed broadcast address for a subnet CIDR, e.g.
    '10.0.0.0/24' -> '10.0.0.255'. None for a malformed CIDR."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return None
    return str(net.broadcast_address)


def wake_targets(subnet_cidr):
    """Pure: the set of addresses one wake is sent to - the limited broadcast always, and the subnet's directed
    broadcast when `subnet_cidr` resolves to one. `_send_wake` sends to exactly these; the API answer lists them."""
    targets = {"255.255.255.255"}
    if subnet_cidr:
        b = directed_broadcast(subnet_cidr)
        if b:
            targets.add(b)
    return targets


def sent_message(name, mac, subnet_id, broadcast, on_link):
    """Pure: (sentence, flash category) for a wake that was SENT (v1.2.0, WOL-1 and WOL-2). `sendto` succeeding says the
    packet left, not that it arrived, so the sentence says where it went:
    - no subnet known for the MAC: only the limited broadcast was targeted, which stays on Jen's own network;
    - Jen has no address in the target subnet (`on_link` False): the directed broadcast goes through a router, and
      most routers drop it;
    - Jen has an address there, or Jen could not be asked (`on_link` None): the sentence used before 1.2.0."""
    if subnet_id is None:
        return f"Wake packet sent on Jen's own network only: Jen does not know which subnet {mac} is on.", "warning"
    if on_link is False and broadcast:
        return (
            f"Wake packet sent toward {broadcast} for {mac}. Jen has no address in that subnet, so it arrives only "
            "if a router forwards directed broadcasts.",
            "warning",
        )
    return f"Wake packet sent to {name}.", "success"


def audit_detail(via, subnet_id, on_link, key_name=None):
    """Pure: the detail of a `WOL_SENT` audit row (v1.2.0, WOL-3): which entry point (`favorite`, `row`, `page`, `api`),
    the subnet the wake was sent on and whether Jen has an address in it. A wake through the API carries the key's name
    in the same `[api-key:<name>]` prefix Jen's own API writes use: a Bearer request has no session user, so without it
    the row named nobody."""
    link = {True: "yes", False: "no"}.get(on_link, "unknown")
    detail = f"via={via} subnet_id={subnet_id if subnet_id is not None else 'none'} on_link={link}"
    return f"[api-key:{key_name}] {detail}" if key_name is not None else detail


def rate_limited(last_sent_at, now, window_s=_RATE_LIMIT_WINDOW_S):
    """Pure: True if a wake last sent at `last_sent_at` (monotonic
    seconds, or None if never) should be REFUSED at `now` because it's
    still inside the rate-limit window."""
    if last_sent_at is None:
        return False
    return (now - last_sent_at) < window_s


def prune_rate_map(last_sent, now, keep_s=60):
    """Pure: `last_sent` ({mac: monotonic seconds}) without the entries older than
    `keep_s`. Only the last few seconds matter to the rate limit, so an entry older
    than a minute is dead weight — and the map used to grow by one entry per distinct
    MAC ever woken, for as long as Jen ran."""
    return {mac: at for mac, at in last_sent.items() if (now - at) < keep_s}


# ── DB helpers (same shape as every other bundled plugin) ──────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _can(subnet_id):
    """May the session user act on something in `subnet_id`? None ("no attributable
    subnet") is for unrestricted users only — plugin_api decides (v5.65.2)."""
    from jen.plugin_api import can_access_subnet

    return can_access_subnet(subnet_id)


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"Wake & Actions: audit failed: {e}")


def _derive_subnet_id(ip, subnet_map):
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for sid, info in subnet_map.items():
        try:
            if addr in ipaddress.IPv4Network(info["cidr"], strict=False):
                return sid
        except ValueError:
            continue
    return None


def _current_subnet_for_mac(mac):
    """The MAC's current subnet by Jen's ONE precedence (current lease, then reservation, then the
    device's last known subnet, else None): `plugin_api.client_subnet_for_mac`, v5.65.6. This plugin
    used to carry a private lookup (lease, then reservation only)."""
    from jen.plugin_api import client_subnet_for_mac

    return client_subnet_for_mac(mac)


class _LookupFailed(Exception):
    """The existence lookup itself raised: the third outcome, neither 'found' nor 'not found' (v1.1.3)."""


# v1.2.0 (WOL-4) - what a wake says when the saved favorite could not be READ. One sentence for every caller, whatever
# their scope, so it says nothing about whether a favorite exists.
WAKE_SETTINGS_REFUSAL = "Could not read the saved wake settings - nothing was sent. Try again in a moment."
WAKE_SETTINGS_API_ERROR = "The saved wake settings could not be read"


def _jen_on_link(subnet_id):
    """Does Jen have an address in `subnet_id`? Three answers, kept apart (v1.2.0, WOL-1): True (it has one), False (Jen's
    `subnet_context` answered and lists none), None (there is no subnet to ask about, or the context could not be asked:
    it raised, answered None for a subnet Jen no longer has, or carries no `jen_host_ips`). The exception is logged and
    never shown. This only words the answer; it never decides whether or where the packet is sent."""
    if subnet_id is None:
        return None
    try:
        from jen.plugin_api import subnet_context

        ctx = subnet_context(subnet_id)
    except Exception as e:
        logger.error(f"Wake & Actions: could not ask whether Jen has an address in subnet {subnet_id}: {e}")
        return None
    if not isinstance(ctx, dict) or ctx.get("jen_host_ips") is None:
        return None
    return bool(ctx["jen_host_ips"])


def wake_inputs(favorite, current_subnet_id, can):
    """Pure: (subnet_id, secureon, visible) a wake of one MAC is judged and sent with - TWO judgments, kept apart (v1.1.2).
    `visible` (v1.1.5) is whether a favorite exists AND the caller may see it: the only case in which the wake may stamp
    `last_woken_*` on it (a stamp on a favorite the caller may not see changed another scope's row and told its owner who
    woke the host).

    A WAKE is an act on a live host, so it goes where the host is now: `current_subnet_id`, and the caller needs that subnet.
    A favorite is a STORED object, judged on its own stored subnet and nothing else: `can(favorite subnet)` decides whether
    the caller may use anything it holds, and the SecureOn password is the thing it holds that matters most. A favorite the
    caller may not see contributes NOTHING to the wake - not its password (a hidden favorite's secret is never built into a
    packet the caller asked for), and not its stored subnet as a fallback - so the wake goes ahead without it and a NIC that
    wants the password simply ignores it; no word of the favorite reaches the caller. A MAC with no current subnet falls back
    to the stored subnet only of a favorite the caller may see."""
    visible = bool(favorite) and bool(can(favorite.get("subnet_id")))
    subnet_id = current_subnet_id
    if subnet_id is None and visible:
        subnet_id = favorite.get("subnet_id")
    return subnet_id, (favorite.get("secureon") if visible else None), visible


def _wake_subject(mac, can=None):
    """(subnet_id, secureon, visible) - what a wake of `mac` is judged and sent on (see `wake_inputs`). `can` is the caller's own
    predicate on a subnet id: the session user's `_can` by default, the API key's for the API. A value in the request is
    never the subject: the row action used to pass `subnet_id` in the query string and the route authorized THAT, while the
    packet always also went out on the limited broadcast to the Jen host's own segment - so naming a subnet you own woke any
    host.

    Raises _LookupFailed when the favorite lookup itself raises (v1.2.0, WOL-4). 1.0.3 to 1.1.7 went on as if there were
    no favorite: for a NIC that requires SecureOn the packet was then built without the password, the NIC ignored it, and
    the caller was told "sent". Found, not found and failed are three answers; the caller refuses the wake on the third."""
    can = can or _can
    favorite = None
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT subnet_id, secureon FROM wol_hosts WHERE mac=%s", (mac,))
            favorite = cur.fetchone()
    except Exception as e:
        logger.error(f"Wake & Actions: could not read the favorite for {mac}: {e}")
        raise _LookupFailed("favorite lookup failed") from e
    finally:
        if db:
            db.close()
    return wake_inputs(favorite, _current_subnet_for_mac(mac), can)


# ── Sending (impure: socket) ─────────────────────────────────────────────────

_last_sent: dict[str, float] = {}


def _send_wake(mac, subnet_cidr, secureon):
    """Impure: builds and sends the magic packet at both the target's
    directed broadcast (when `subnet_cidr` resolves to one) and the
    limited broadcast address. Raises ValueError on a bad mac/secureon
    rather than sending anything malformed."""
    packet = build_magic_packet(mac, secureon)
    if packet is None:
        raise ValueError(f"invalid MAC {mac!r}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for target in wake_targets(subnet_cidr):
            sock.sendto(packet, (target, _WOL_PORT))
    finally:
        sock.close()


def _decode_secureon(stored):
    """(plain, error) for a stored SecureOn value: decrypted when it is in Jen's encrypted format, taken
    as-is when it is a legacy plain value (which the next use re-encrypts, see _wake_mac)."""
    if not is_encrypted_secureon(stored):
        return stored, None
    try:
        from jen.plugin_api import decrypt_secret

        return decrypt_secret(stored), None
    except Exception as e:
        logger.error(f"Wake & Actions: could not decrypt a stored SecureOn password: {e}")
        return None, "The saved SecureOn password could not be decrypted; enter it again."


def _reencrypt_legacy_secureon(mac, plain):
    """A pre-1.0.2 favorite kept its SecureOn password in clear: encrypt it in place the first time it
    is used. Best effort - the wake has already been sent."""
    db = None
    try:
        from jen.plugin_api import encrypt_secret

        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE wol_hosts SET secureon=%s WHERE mac=%s AND secureon=%s",
                (encrypt_secret(plain), mac, plain),
            )
        db.commit()
    except Exception as e:
        logger.warning(f"Wake & Actions: could not re-encrypt a legacy SecureOn password for {mac}: {e}")
    finally:
        if db:
            db.close()


def _wake_mac(mac, subnet_id, secureon_raw, actor, stamp=False, *, via, key_name=None):
    """The shared impure core behind every wake entry point: rate
    limit, build+send, audit, emit. Returns (ok, error_message, sent): `sent` is None for a wake that was not sent and
    otherwise {"on_link": True | False | None, "targets": the addresses sent to, sorted as text, "broadcast": the
    directed broadcast that was targeted, or None} (v1.2.0).
    `secureon_raw` is the value as STORED (encrypted, or a legacy plain one).
    `via` (v1.2.0) is the entry point for the audit row: "favorite", "row", "page" or "api"; `key_name` is the API key's
    name for a wake through the API (see `audit_detail`).
    `stamp` (v1.1.5): True only when the favorite was judged VISIBLE to the caller (`wake_inputs`' third value);
    the default writes nothing to wol_hosts, so a hidden favorite is never touched by a wake of its host."""
    now = time.monotonic()
    global _last_sent
    _last_sent = prune_rate_map(_last_sent, now)
    if rate_limited(_last_sent.get(mac), now):
        return False, "Wake packet already sent for this MAC in the last 5 seconds.", None
    secureon, legacy_plain = None, None
    if secureon_raw:
        plain, err = _decode_secureon(secureon_raw)
        if err:
            return False, err, None
        secureon, err = parse_secureon(plain)
        if err:
            return False, err, None
        if not is_encrypted_secureon(secureon_raw):
            legacy_plain = secureon_raw
    cidr = _subnet_map().get(subnet_id, {}).get("cidr") if subnet_id is not None else None
    try:
        _send_wake(mac, cidr, secureon)
    except Exception as e:
        logger.error(f"Wake & Actions: could not send the wake packet for {mac}: {e}")
        return False, "Could not send the wake packet; the details are in Jen's log.", None
    _last_sent[mac] = now
    if legacy_plain:
        _reencrypt_legacy_secureon(mac, legacy_plain)
    db = None
    try:
        if stamp:
            db = _get_db()
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE wol_hosts SET last_woken_at=UTC_TIMESTAMP(), last_woken_by=%s WHERE mac=%s",
                    (actor, mac),
                )
            db.commit()
    except Exception as e:
        logger.warning(f"Wake & Actions: could not stamp last_woken_at for {mac}: {e}")
    finally:
        if db:
            db.close()
    # asked once per wake and after the send, so a slow or failing answer never delays or stops the packet
    on_link = _jen_on_link(subnet_id)
    _audit("WOL_SENT", mac, audit_detail(via, subnet_id, on_link, key_name))
    try:
        from jen.plugin_api import emit

        emit("plugin.wol.sent", mac=mac, subnet_id=subnet_id, actor=actor)
    except Exception as e:
        logger.warning(f"Wake & Actions: could not emit sent event: {e}")
    sent = {
        "on_link": on_link,
        "targets": sorted(wake_targets(cidr)),
        "broadcast": directed_broadcast(cidr) if cidr else None,
    }
    return True, "", sent


# ── Investigation provider (v1.1.0, Jen 5.68.0) ──────────────────────────────


def in_scope(subnet_id, accessible_subnet_ids, all_subnets):
    """Pure: may a caller with this scope see something whose subnet is `subnet_id`? An unrestricted caller may; a
    restricted one only for a subnet in its own set - and a subnet of None ("no attributable subnet") is for unrestricted
    callers only, never read as allow."""
    if all_subnets:
        return True
    return subnet_id is not None and subnet_id in set(accessible_subnet_ids or ())


def _when(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value) if value else ""


def subnet_label(subnet_id, subnet_map):
    """Pure: a subnet's name for a person ("Servers (10.0.1.0/24)"), its CIDR alone when it has no name, "" when Jen does not
    know it."""
    info = (subnet_map or {}).get(subnet_id)
    if not info:
        return ""
    name, cidr = info.get("name") or "", info.get("cidr") or ""
    return f"{name} ({cidr})" if name and cidr else name or cidr


def now_in(current_subnet_id, stored_subnet_id, subnet_map, accessible_subnet_ids, all_subnets):
    """Pure: where the client is NOW, as a fact to show beside a favorite saved in `stored_subnet_id` - "" when there is
    nothing to add (it is still there, Jen does not know, or the caller may not see that subnet: naming a subnet is access to
    it, so a hidden one is simply not said). It is only ever shown; what the caller may see of the favorite was decided on the
    stored subnet before this is asked."""
    if current_subnet_id is None or current_subnet_id == stored_subnet_id:
        return ""
    if not in_scope(current_subnet_id, accessible_subnet_ids, all_subnets):
        return ""
    return subnet_label(current_subnet_id, subnet_map)


def investigation_card(favorite, now_in_label=""):
    """Pure: the Investigation page's card from this MAC's favorite row, or None when it is not a favorite - a client that
    was never saved here has nothing for this plugin to say (a wake from a row leaves no record of its own to show)."""
    if not favorite:
        return None
    label = favorite.get("label") or ""
    woken = favorite.get("last_woken_at")
    by = favorite.get("last_woken_by") or ""
    summary = f"A favorite ({label})" if label else "A favorite"
    summary += f"; last woken {_when(woken)}" + (f" by {by}" if by else "") if woken else "; never woken from Jen"
    rows = [
        {"label": "Favorite", "value": label or "saved without a label"},
        {"label": "SecureOn password", "value": "set" if favorite.get("secureon") else "not set"},
        {"label": "Last woken", "value": _when(woken) if woken else "never"},
    ]
    if woken and by:
        rows.append({"label": "Woken by", "value": by})
    if now_in_label:
        rows.append({"label": "Now in", "value": now_in_label})
    return {"summary": summary, "status": "ok", "rows": rows}


def _favorite_for_mac(mac):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT label, subnet_id, secureon, last_woken_at, last_woken_by FROM wol_hosts WHERE mac=%s",
                (mac,),
            )
            return cur.fetchone()
    finally:
        if db:
            db.close()


def _investigate(subject, accessible_subnet_ids, all_subnets):
    """The Investigation page's card for the client Jen resolved. A favorite is a STORED object, so it is judged by its own
    stored subnet (v1.1.1): the subnet the client is in now is shown ("Now in ...") when the caller may see it, and never
    widens anything - a favorite saved in a subnet the caller cannot see is not shown just because the client has since moved
    into one they can. A favorite with no subnet is for an unrestricted caller only. (A WAKE is the other kind of act and is
    still judged on where the host is now: see _wake_subject.)"""
    mac = _normalize_mac(getattr(subject, "mac", "") or "")
    if not mac:
        return None
    favorite = _favorite_for_mac(mac)
    if not favorite:
        return None
    stored = favorite.get("subnet_id")
    if not in_scope(stored, accessible_subnet_ids, all_subnets):
        return None
    try:
        where_now = now_in(_current_subnet_for_mac(mac), stored, _subnet_map(), accessible_subnet_ids, all_subnets)
    except Exception as e:
        # only the "Now in" fact is lost: the favorite itself was already judged on its own subnet above
        logger.error(f"Wake & Actions: could not work out where {mac} is now: {e}")
        where_now = ""
    card = investigation_card(favorite, where_now)
    card["href"] = "/management/wol"
    return card


# ── Routes: page ────────────────────────────────────────────────────────────


def _favorite_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, mac, ip, subnet_id, label, secureon, last_woken_at, last_woken_by "
                "FROM wol_hosts ORDER BY label, mac"
            )
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Wake & Actions: index error: {e}")
        return []
    finally:
        if db:
            db.close()


def _candidate_hosts():
    """Reservations across the caller's subnets, for the Add Favorite picker (a global
    reservation belongs to no subnet, so it is for unrestricted callers)."""
    out = []
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS ident_hex, "
                "dhcp_identifier_type AS ident_type, dhcp4_subnet_id AS subnet_id FROM hosts "
                "WHERE ipv4_address IS NOT NULL AND ipv4_address > 0"
            )
            for row in cur.fetchall():
                if not row["ip"] or row.get("ident_type") != 0 or not row.get("ident_hex"):
                    continue
                sid = row.get("subnet_id") or None
                if not _can(sid):
                    continue
                hex_mac = row["ident_hex"]
                if len(hex_mac) != 12:
                    continue
                mac = ":".join(hex_mac[i : i + 2] for i in range(0, 12, 2)).lower()
                out.append({"mac": mac, "ip": row["ip"], "label": row.get("hostname") or "", "subnet_id": sid})
    except Exception as e:
        logger.warning(f"Wake & Actions: candidate hosts failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return out


LOOKUP_REFUSAL = "Could not check the existing record — nothing was changed."
# v1.1.5 - an existing favorite the caller may not see says only that it is not theirs to change: 1.1.4 answered "That MAC is not
# on a subnet you can access" for a MAC the caller CAN see that merely has a hidden favorite - a false sentence, and a way to learn
# that a favorite exists. A MAC with no favorite and no visible subnet keeps its own, true, sentence.
NOT_YOURS = "That favorite is not yours to change."
MAC_NOT_YOURS = "That MAC is not on a subnet you can access."
CHANGED_UNDERFOOT = "That favorite changed while you were saving it — nothing was changed. Try again."


def _save_favorite(db, mac, ip, label, secureon, on_write=None):
    """Judge and write one favorite in ONE transaction (v1.1.4). Returns ("ok", "") or ("refused", the flash text); the caller commits
    or rolls back. Raises _LookupFailed when the first SELECT raises (the third outcome: refuse, write nothing, audit nothing).

    The row is read `FOR UPDATE`, so nobody else can change or create it until this transaction ends. An existing favorite is
    authorized on its OWN stored subnet and updated with that owner as a predicate (`subnet_id <=> owner`) - the route never moves a
    favorite's subnet. A new one is a plain INSERT, never `ON DUPLICATE KEY UPDATE`: if another request created it first (error 1062,
    or a deadlock 1213 between two inserts of one MAC) the row that WON is locked and judged again. `on_write` is a test hook that runs
    after the judgment and before the write - the point where an interleaving request used to slip in."""
    with db.cursor() as cur:
        for attempt in (1, 2):
            try:
                cur.execute("SELECT subnet_id FROM wol_hosts WHERE mac=%s FOR UPDATE", (mac,))
                existing = cur.fetchone()
            except Exception as e:
                raise _LookupFailed(str(e)) from e
            if existing:
                owner = existing["subnet_id"]
                if not _can(owner):
                    return "refused", NOT_YOURS
                stored_ip = ip if ip and _derive_subnet_id(ip, _subnet_map()) == owner else ""
                if on_write:
                    on_write()
                cur.execute(
                    "UPDATE wol_hosts SET ip=%s, label=%s, secureon=IF(%s IS NULL, secureon, %s) "
                    "WHERE mac=%s AND subnet_id <=> %s",
                    (stored_ip or None, label, secureon, secureon, mac, owner),
                )
                if cur.rowcount == 1:
                    return "ok", ""
                # 0 rows: the values were already what is stored (MySQL counts CHANGED rows), or the row is no longer the one that
                # was judged. Look again under the lock this transaction holds; only the same owner is a success.
                cur.execute("SELECT subnet_id FROM wol_hosts WHERE mac=%s FOR UPDATE", (mac,))
                again = cur.fetchone()
                if again is not None and again["subnet_id"] == owner:
                    return "ok", ""
                return "refused", CHANGED_UNDERFOOT
            # The subnet is where the MAC is (a lease or reservation), never worked out from an address the caller typed: the
            # optional IP used to be enough to attach ANY MAC to a subnet the caller owns. A MAC Jen has never seen has no subnet
            # and is for unrestricted callers only.
            subnet_id = _current_subnet_for_mac(mac)
            if not _can(subnet_id):
                # 1.1.6: the SAME sentence as a hidden existing favorite. Saving is a write to the favorites list, so what it refuses is "that favorite", whether the
                # row exists (stored in a subnet the caller cannot see) or would have to be created for a MAC in one - two sentences told a scoped caller which MACs have
                # a hidden favorite. A WAKE probes no stored object and keeps MAC_NOT_YOURS.
                return "refused", NOT_YOURS
            stored_ip = ip if ip and _derive_subnet_id(ip, _subnet_map()) == subnet_id else ""
            if on_write:
                on_write()
            try:
                cur.execute(
                    "INSERT INTO wol_hosts (mac, ip, subnet_id, label, secureon) VALUES (%s, %s, %s, %s, %s)",
                    (mac, stored_ip or None, subnet_id, label, secureon),
                )
                return "ok", ""
            except Exception as e:
                if attempt == 1 and getattr(e, "args", (None,))[0] in (1062, 1213):
                    if getattr(e, "args", (None,))[0] == 1213:
                        db.rollback()  # InnoDB already rolled the deadlock victim back
                    continue  # another request created it first: lock and judge the row that won
                raise
    return "refused", CHANGED_UNDERFOOT


def _where_now(mac, stored_subnet_id, subnet_map):
    """The subnet the MAC is in NOW, as text, for a favorite stored in `stored_subnet_id` - "" when it has not moved, is not
    known, or is a subnet the caller may not see (naming a subnet is access to it). Only ever shown; it decides nothing."""
    try:
        current = _current_subnet_for_mac(mac)
    except Exception as e:
        logger.error(f"Wake & Actions: could not work out where {mac} is now: {e}")
        return ""
    if current is None or current == stored_subnet_id or not _can(current):
        return ""
    return subnet_label(current, subnet_map)


@bp.route("/")
@login_required
def index():
    # v1.1.2 - a favorite is a STORED object, judged on the subnet it was stored in and nothing else
    # (v1.0.3 judged it on where the MAC is now, the stored value only a fallback: a favorite saved in
    # subnet B - its label, whether a SecureOn password is set - listed for an A-scoped admin the moment
    # the client's lease moved to A). Where the MAC is now is shown as a fact, only when it is a subnet
    # the caller may see, and never widens what they are shown.
    rows = [r for r in _favorite_rows() if _can(r["subnet_id"])]
    subnet_map = _subnet_map()
    admin = is_admin_or_above()
    for r in rows:
        sid = r["subnet_id"]
        r["effective_subnet_id"] = sid
        r["subnet_name"] = subnet_map.get(sid, {}).get("name", "") if sid else "—"
        r["now_in"] = _where_now(r["mac"], sid, subnet_map)
        r["has_secureon"] = bool(r.get("secureon"))
    return render_template(
        "wol/index.html",
        rows=rows,
        candidates=_candidate_hosts() if admin else [],
        is_admin=admin,
    )


@bp.route("/favorites/add", methods=["POST"])
@login_required
@require_write(_VIEWER_MESSAGE, "wol.index")
def add_favorite():
    mac = _normalize_mac(request.form.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("wol.index"))
    ip = request.form.get("ip", "").strip()[:15]
    label = request.form.get("label", "").strip()[:100]

    # v1.0.3 - "Add Favorite" for a MAC that already has one used to judge access on the MAC's
    # CURRENT subnet alone and then overwrite the existing row's subnet_id/ip/label. An admin who can
    # see where the MAC is NOW could silently take over (and relocate) a favorite another admin had
    # created in a subnet they cannot see. v1.1.2: the existing row, if any, is a STORED object and is
    # authorized on its OWN stored subnet and nothing else (v1.0.3 let the MAC's current subnet stand in
    # for it, so a favorite saved in B was editable from A the moment the client moved to A) before
    # anything is written, and this route never moves a favorite's subnet.
    # v1.1.3 - THREE outcomes, never two: found, not found, FAILED. The lookup used to degrade to "no existing favorite" when it
    # raised, so with the database failing for this one SELECT the route went on as if the MAC were new, judged it on the client's
    # CURRENT subnet and let `INSERT ... ON DUPLICATE KEY UPDATE` rewrite the label, address and SecureOn of a favorite stored in
    # a subnet the caller cannot see. A lookup that raises is not "absent": refuse, write nothing, audit nothing.
    # v1.1.4 - and the judgment and the write are ONE transaction (`_save_favorite`): the row is read FOR UPDATE, judged, and written
    # with its judged owner as a predicate, so a favorite another admin creates or changes between "judge" and "write" can never be
    # rewritten by this request.
    secureon_raw = request.form.get("secureon", "").strip()
    secureon = None
    if secureon_raw:
        _parsed, err = parse_secureon(secureon_raw)
        if err:
            flash(err, "error")
            return redirect(url_for("wol.index"))
        from jen.plugin_api import encrypt_secret

        secureon = encrypt_secret(secureon_raw)  # encrypted at rest, like every other plugin credential

    db = None
    stage = "check"
    try:
        db = _get_db()
        outcome, refusal = _save_favorite(db, mac, ip, label, secureon)
        stage = "write"
        if outcome != "ok":
            db.rollback()
            flash(refusal, "error")
            return redirect(url_for("wol.index"))
        db.commit()
        flash(f"{label or mac} added to favorites.", "success")
        _audit("WOL_ADD_FAVORITE", mac, f"label={label}")
    except _LookupFailed as e:
        logger.error(f"Wake & Actions: could not check for an existing favorite: {e}")
        flash(LOOKUP_REFUSAL, "error")
    except Exception as e:
        logger.error(f"Wake & Actions: could not add favorite ({stage}): {e}")
        flash("Could not add the favorite; the details are in Jen's log.", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("wol.index"))


@bp.route("/favorites/<int:host_id>/delete", methods=["POST"])
@login_required
@require_write(_VIEWER_MESSAGE, "wol.index")
def delete_favorite(host_id):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            # v1.1.4: read FOR UPDATE, judged on its OWN subnet, deleted with that owner as a predicate and the count checked
            cur.execute("SELECT mac, subnet_id FROM wol_hosts WHERE id=%s FOR UPDATE", (host_id,))
            row = cur.fetchone()
            if row is None:
                flash("Favorite not found.", "error")
                return redirect(url_for("wol.index"))
            if not _can(row["subnet_id"]):  # a stored object: its own subnet, never where the MAC is now
                flash("Favorite not found.", "error")
                return redirect(url_for("wol.index"))
            cur.execute("DELETE FROM wol_hosts WHERE id=%s AND subnet_id <=> %s", (host_id, row["subnet_id"]))
            if cur.rowcount != 1:
                db.rollback()
                flash(CHANGED_UNDERFOOT, "error")
                return redirect(url_for("wol.index"))
        db.commit()
        flash("Favorite removed.", "success")
        _audit("WOL_DELETE_FAVORITE", str(host_id), "favorite removed")
    except Exception as e:
        logger.error(f"Wake & Actions: could not remove favorite: {e}")
        flash("Could not remove the favorite; the details are in Jen's log.", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("wol.index"))


@bp.route("/favorites/<int:host_id>/wake", methods=["POST"])
@login_required
@require_write(_VIEWER_MESSAGE, "wol.index")
def wake_favorite(host_id):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, subnet_id, secureon, label FROM wol_hosts WHERE id=%s", (host_id,))
            row = cur.fetchone()
    except Exception as e:
        # v1.2.0 (WOL-4): the favorite could not be read, so nothing is sent and the person is told so
        logger.error(f"Wake & Actions: could not read favorite {host_id}: {e}")
        flash(WAKE_SETTINGS_REFUSAL, "error")
        return redirect(url_for("wol.index"))
    finally:
        if db:
            db.close()
    # v1.1.2 - two judgments, in this order. The favorite is a STORED object: it must be in the caller's scope
    # by its own stored subnet, or it is "not found" (and its SecureOn password is never touched). The WAKE is an
    # act on a live host and goes where the host is now (the stored subnet only when the MAC has no current one), and
    # the caller needs THAT subnet too: a favorite saved in A for a host that has moved to a subnet the caller
    # cannot see is theirs to list and edit, and not theirs to wake.
    if not row or not _can(row["subnet_id"]):
        flash("Favorite not found.", "error")
        return redirect(url_for("wol.index"))
    subnet_id, secureon, visible = wake_inputs(row, _current_subnet_for_mac(row["mac"]), _can)
    if not _can(subnet_id):
        flash(MAC_NOT_YOURS, "error")
        return redirect(url_for("wol.index"))
    ok, err, sent = _wake_mac(row["mac"], subnet_id, secureon, current_user.username, stamp=visible, via="favorite")
    if not ok:
        flash(err, "error")
        return redirect(url_for("wol.index"))
    flash(*sent_message(row.get("label") or row["mac"], row["mac"], subnet_id, sent["broadcast"], sent["on_link"]))
    return redirect(url_for("wol.index"))


# ── Row action target: "Wake" (lease, reservation, device rows) ────────────────


@bp.route("/wake", methods=["POST"])
@login_required
@require_write(_VIEWER_MESSAGE, "wol.index")
def wake_from_row():
    # A gated viewer's denial path never touches `request` (the lesson jen-plugin-watchdog's
    # watch_from_row() learned first, and why this redirects to wol.index and never to
    # request.referrer): the gate is jen.plugin_api's require_write, which decides before this runs.
    mac = _normalize_mac(request.args.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("wol.index"))
    # the `subnet_id` in the query string is only what the row that linked here knew: it is
    # ignored, and the subnet is worked out from the MAC (see _wake_subject)
    try:
        subnet_id, secureon, visible = _wake_subject(mac)
    except _LookupFailed:
        flash(WAKE_SETTINGS_REFUSAL, "error")
        return redirect(url_for("wol.index"))
    if not _can(subnet_id):
        flash(MAC_NOT_YOURS, "error")
        return redirect(url_for("wol.index"))

    ok, err, sent = _wake_mac(mac, subnet_id, secureon, current_user.username, stamp=visible, via="row")
    if not ok:
        flash(err, "error")
        return redirect(url_for("wol.index"))
    flash(*sent_message(mac, mac, subnet_id, sent["broadcast"], sent["on_link"]))
    return redirect(url_for("wol.index"))


# ── JSON API (v1.0.0) ────────────────────────────────────────────────────────
# Undecorated on purpose: api_key_required() is applied in register(app), where each
# route is added to the blueprint.

api_bp = Blueprint("wol_api", __name__, url_prefix="/api/v1/plugins/wol")


def _api_wake():
    from flask import g

    from jen.plugin_api import api_key_can_access_subnet, json_object_body, str_field

    # v1.0.4 — `request.get_json(silent=True) or {}` let a JSON array or a bare string through
    # (only an empty/falsy body was rescued to {}); body.get("mac", "") then raised AttributeError
    # on a list, an unhandled 500 instead of a caller-visible refusal.
    body, err_response = json_object_body()
    if err_response is not None:
        return err_response
    mac = _normalize_mac(str_field(body, "mac"))
    if not mac:
        return jsonify({"error": "invalid mac"}), 400
    # v1.1.2 - the same two judgments as the page, with the KEY as the caller: the wake goes where the host is now
    # and the key needs that subnet; a stored favorite's SecureOn is used only when the key may see the favorite's own
    # stored subnet
    try:
        subnet_id, secureon, visible = _wake_subject(mac, lambda sid: api_key_can_access_subnet(g.api_key, sid))
    except _LookupFailed:
        # v1.2.0 (WOL-4): refused for every key, whatever its scope; the exception is in Jen's log
        return jsonify({"ok": False, "error": WAKE_SETTINGS_API_ERROR}), 503
    # a MAC with no attributable subnet is for an unrestricted key only — a scoped key read it as "allow"
    if not api_key_can_access_subnet(g.api_key, subnet_id):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    key_name = g.api_key["name"]
    ok, err, sent = _wake_mac(mac, subnet_id, secureon, f"api:{key_name}", stamp=visible, via="api", key_name=key_name)
    if not ok:
        # v1.0.3 — a stored SecureOn password that cannot be decrypted is a caller-visible refusal
        # ("enter it again"), not a server fault; it used to fall through to 500 like a genuine crash.
        if "5 seconds" in err:
            status = 400
        elif "could not be decrypted" in err:
            status = 409
        else:
            status = 500
        return jsonify({"error": err}), status
    return jsonify({"ok": True, "mac": mac, "on_link": sent["on_link"], "targets": sent["targets"]})


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import api_key_required, register_investigation_provider, register_row_action

    api_bp.add_url_rule("/wake", "api_wake", api_key_required(write=True)(_api_wake), methods=["POST"])
    app.register_blueprint(api_bp)

    for surface in ("lease", "reservation", "device"):
        register_row_action(
            PLUGIN_ID,
            surface,
            label="Wake",
            icon="zap",
            href="/management/wol/wake?mac={mac}",
            method="POST",
            confirm="Send a wake packet to {mac}?",
        )

    register_investigation_provider(PLUGIN_ID, title="Wake & Actions", fn=_investigate)

    logger.info("Wake & Actions plugin registered")

"""
Wake & Actions plugin for Jen.
Wake-on-LAN from any lease, reservation, or device row, plus a
favourites list for the hosts you wake often — the first consumer of
Jen's Q73 row actions. Version lives in manifest.json — not
duplicated here.

Magic packet (v1.0.0)
──────────────────────
A standard Wake-on-LAN magic packet is exactly 102 bytes: six 0xFF
bytes followed by the target MAC address repeated 16 times (16 × 6 =
96 bytes). An optional SecureOn password — 4 or 6 raw bytes, a
vendor-specific anti-spoofing feature scoped to the local broadcast
domain, not a real secret — is appended after those 102 bytes when
the target expects one. Sent via a `SO_BROADCAST` UDP socket to port
9, at BOTH the target subnet's own directed broadcast address
(computed from the subnet's CIDR) and `255.255.255.255`. Jen is
usually on the same L2 as its subnets; the README says plainly that a
target on a different L2 needs directed broadcast explicitly allowed
on the router in between — this plugin cannot make that work by
itself.

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

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


# ── Pure: MAC/SecureOn parsing, the magic packet builder, broadcast maths ──────


def _normalize_mac(raw):
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return ""
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else ""


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


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    if _is_admin():
        return True
    flash("Viewers can look at Wake & Actions but not send a wake packet.", "error")
    return False


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
    """The MAC's current subnet — a lease first, then a reservation
    (global reservations carry no useful subnet_id, so fall through),
    matching how the rest of Jen judges "where is this client now"."""
    hex_mac = mac.replace(":", "").upper()
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute("SELECT subnet_id FROM lease4 WHERE HEX(hwaddr)=%s AND state=0", (hex_mac,))
            row = cur.fetchone()
            if row:
                return row["subnet_id"]
            cur.execute(
                "SELECT dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp_identifier_type=0 AND HEX(dhcp_identifier)=%s",
                (hex_mac,),
            )
            row = cur.fetchone()
            if row and row["subnet_id"]:
                return row["subnet_id"]
    except Exception as e:
        logger.warning(f"Wake & Actions: lease/reservation subnet lookup failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return None


def _wake_subject(mac):
    """(subnet_id, secureon) — what a wake of `mac` is judged and sent on. The subnet is the
    one the MAC is in NOW (a lease, then a reservation); a MAC with neither falls back to the
    subnet stored on its favourite, which whoever added it had to be allowed to see. A value in
    the request is never the subject: the row action used to pass `subnet_id` in the query
    string and the route authorised THAT, while the packet always also went out on the limited
    broadcast to the Jen host's own segment — so naming a subnet you own woke any host."""
    secureon, stored_subnet = None, None
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT subnet_id, secureon FROM wol_hosts WHERE mac=%s", (mac,))
            row = cur.fetchone()
            if row:
                secureon, stored_subnet = row.get("secureon"), row.get("subnet_id")
    finally:
        if db:
            db.close()
    subnet_id = _current_subnet_for_mac(mac)
    if subnet_id is None:
        subnet_id = stored_subnet
    return subnet_id, secureon


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
    targets = {"255.255.255.255"}
    if subnet_cidr:
        b = directed_broadcast(subnet_cidr)
        if b:
            targets.add(b)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for target in targets:
            sock.sendto(packet, (target, _WOL_PORT))
    finally:
        sock.close()


def _wake_mac(mac, subnet_id, secureon_raw, actor):
    """The shared impure core behind every wake entry point: rate
    limit, build+send, audit, emit. Returns (ok, error_message)."""
    now = time.monotonic()
    global _last_sent
    _last_sent = prune_rate_map(_last_sent, now)
    if rate_limited(_last_sent.get(mac), now):
        return False, "Wake packet already sent for this MAC in the last 5 seconds."
    secureon = None
    if secureon_raw:
        secureon, err = parse_secureon(secureon_raw)
        if err:
            return False, err
    cidr = _subnet_map().get(subnet_id, {}).get("cidr") if subnet_id is not None else None
    try:
        _send_wake(mac, cidr, secureon)
    except Exception as e:
        return False, str(e)[:200]
    _last_sent[mac] = now
    db = None
    try:
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
    _audit("WOL_SENT", mac, f"subnet_id={subnet_id}")
    try:
        from jen.plugin_api import emit

        emit("plugin.wol.sent", mac=mac, subnet_id=subnet_id, actor=actor)
    except Exception as e:
        logger.warning(f"Wake & Actions: could not emit sent event: {e}")
    return True, ""


# ── Routes: page ────────────────────────────────────────────────────────────


def _favourite_rows():
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
    """Reservations across the caller's subnets, for the Add Favourite picker (a global
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


@bp.route("/")
@login_required
def index():
    rows = [r for r in _favourite_rows() if _can(r["subnet_id"])]
    subnet_map = _subnet_map()
    for r in rows:
        r["subnet_name"] = subnet_map.get(r["subnet_id"], {}).get("name", "") if r["subnet_id"] else "—"
        r["has_secureon"] = bool(r.get("secureon"))
    return render_template(
        "wol/index.html",
        rows=rows,
        candidates=_candidate_hosts() if _is_admin() else [],
        is_admin=_is_admin(),
    )


@bp.route("/favourites/add", methods=["POST"])
@login_required
def add_favourite():
    if not _require_write():
        return redirect(url_for("wol.index"))

    mac = _normalize_mac(request.form.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("wol.index"))
    ip = request.form.get("ip", "").strip()[:15]
    label = request.form.get("label", "").strip()[:100]
    # The subnet is where the MAC is (a lease or reservation), never worked out from an address
    # the caller typed: the optional IP used to be enough to attach ANY MAC to a subnet the caller
    # owns. A MAC Jen has never seen has no subnet and is for unrestricted callers only.
    subnet_id = _current_subnet_for_mac(mac)
    if not _can(subnet_id):
        flash("That MAC is not on a subnet you can access.", "error")
        return redirect(url_for("wol.index"))
    if ip and _derive_subnet_id(ip, _subnet_map()) != subnet_id:
        ip = ""  # a typed address that is not in the MAC's own subnet is not stored

    secureon_raw = request.form.get("secureon", "").strip()
    secureon = None
    if secureon_raw:
        _parsed, err = parse_secureon(secureon_raw)
        if err:
            flash(err, "error")
            return redirect(url_for("wol.index"))
        secureon = secureon_raw

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO wol_hosts (mac, ip, subnet_id, label, secureon) VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE ip=VALUES(ip), subnet_id=VALUES(subnet_id), label=VALUES(label), "
                "secureon=IF(VALUES(secureon) IS NULL, secureon, VALUES(secureon))",
                (mac, ip or None, subnet_id, label, secureon),
            )
        db.commit()
        flash(f"{label or mac} added to favourites.", "success")
        _audit("WOL_ADD_FAVOURITE", mac, f"label={label}")
    except Exception as e:
        flash(f"Could not add favourite: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("wol.index"))


@bp.route("/favourites/<int:host_id>/delete", methods=["POST"])
@login_required
def delete_favourite(host_id):
    if not _require_write():
        return redirect(url_for("wol.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT subnet_id FROM wol_hosts WHERE id=%s", (host_id,))
            row = cur.fetchone()
            if row is None or not _can(row["subnet_id"]):
                flash("Favourite not found.", "error")
                return redirect(url_for("wol.index"))
            cur.execute("DELETE FROM wol_hosts WHERE id=%s", (host_id,))
        db.commit()
        flash("Favourite removed.", "success")
        _audit("WOL_DELETE_FAVOURITE", str(host_id), "favourite removed")
    except Exception as e:
        flash(f"Could not remove favourite: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("wol.index"))


@bp.route("/favourites/<int:host_id>/wake", methods=["POST"])
@login_required
def wake_favourite(host_id):
    if not _require_write():
        return redirect(url_for("wol.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT mac, subnet_id, secureon, label FROM wol_hosts WHERE id=%s", (host_id,))
            row = cur.fetchone()
    finally:
        if db:
            db.close()
    if not row:
        flash("Favourite not found.", "error")
        return redirect(url_for("wol.index"))
    if not _can(row["subnet_id"]):
        flash("Favourite not found.", "error")
        return redirect(url_for("wol.index"))
    ok, err = _wake_mac(row["mac"], row["subnet_id"], row.get("secureon"), current_user.username)
    flash(f"Wake packet sent to {row.get('label') or row['mac']}." if ok else err, "success" if ok else "error")
    return redirect(url_for("wol.index"))


# ── Row action target: "Wake" (lease, reservation, device rows) ────────────────


@bp.route("/wake", methods=["POST"])
@login_required
def wake_from_row():
    # v1.0.0: redirects to wol.index always, never request.referrer — a
    # gated viewer's denial path must never touch `request` at all (the
    # same lesson jen-plugin-watchdog's watch_from_row() learned first).
    if not _require_write():
        return redirect(url_for("wol.index"))
    mac = _normalize_mac(request.args.get("mac", ""))
    if not mac:
        flash("Invalid MAC address.", "error")
        return redirect(url_for("wol.index"))
    # the `subnet_id` in the query string is only what the row that linked here knew: it is
    # ignored, and the subnet is worked out from the MAC (see _wake_subject)
    subnet_id, secureon = _wake_subject(mac)
    if not _can(subnet_id):
        flash("That MAC is not on a subnet you can access.", "error")
        return redirect(url_for("wol.index"))

    ok, err = _wake_mac(mac, subnet_id, secureon, current_user.username)
    flash(f"Wake packet sent to {mac}." if ok else err, "success" if ok else "error")
    return redirect(url_for("wol.index"))


# ── JSON API (v1.0.0) ────────────────────────────────────────────────────────
# Undecorated on purpose: api_key_required() is applied in register(app), not
# here, so plugin.py's top level never imports jen.plugin_api — the standalone
# harness (tools/test_plugin.py) stubs only flask/flask_login.

api_bp = Blueprint("wol_api", __name__, url_prefix="/api/v1/plugins/wol")


def _api_wake():
    from flask import g

    from jen.plugin_api import api_key_can_access_subnet

    body = request.get_json(silent=True) or {}
    mac = _normalize_mac(str(body.get("mac", "")))
    if not mac:
        return jsonify({"error": "invalid mac"}), 400
    subnet_id, secureon = _wake_subject(mac)
    # a MAC with no attributable subnet is for an unrestricted key only — a scoped key read it as "allow"
    if not api_key_can_access_subnet(g.api_key, subnet_id):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    ok, err = _wake_mac(mac, subnet_id, secureon, f"api:{g.api_key['name']}")
    if not ok:
        return jsonify({"error": err}), 400 if "5 seconds" in err else 500
    return jsonify({"ok": True, "mac": mac})


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import api_key_required, register_row_action

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

    logger.info("Wake & Actions plugin registered")

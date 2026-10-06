#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a network; every check exercises a PURE function of the
plugin with hand-built inputs, plus an end-to-end call of register(app)
against a stub jen.plugin_api (the Q89 lesson — a plugin's own
register() can be silently broken in a way nothing else catches).

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

        def add_url_rule(self, *a, **k):
            pass

    flask.Blueprint = Blueprint
    flask.g = types.SimpleNamespace()
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_normalize_mac(raw):
    import re as _re

    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = _re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return None
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) else None


INVESTIGATION_CALLS = []


def _stub_jen_plugin_api():
    """A stub `jen`/`jen.plugin_api` sufficient for register(app) to run
    end to end, with register_alert_type-style validation left out
    since this plugin never calls it — only register_row_action's
    'surface must be one of SURFACES' rule matters here, enforced the
    same way jen/services/row_actions.py does. Returns the list every
    register_row_action() call is recorded into."""
    row_action_calls = []
    _SURFACES = ("lease", "reservation", "device")

    def register_row_action(plugin_id, surface, **kwargs):
        if surface not in _SURFACES:
            raise ValueError(f"surface must be one of {_SURFACES}, got {surface!r}")
        row_action_calls.append((plugin_id, surface, kwargs))

    def api_key_required(write=False):
        return lambda fn: fn

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_row_action = register_row_action
    plugin_api.register_investigation_provider = lambda *a, **k: INVESTIGATION_CALLS.append((a, k))
    plugin_api.api_key_required = api_key_required
    plugin_api.normalize_mac = _stub_normalize_mac
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return row_action_calls


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("wol_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()

    # ── MAC normalisation ────────────────────────────────────────────────────
    _stub_jen_plugin_api()
    check(p._normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: uppercase colon form")
    check(p._normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: bare hex form")
    check(p._normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff", "_normalize_mac: hyphen-separated form")
    check(p._normalize_mac("not-a-mac") == "", "_normalize_mac: garbage is refused, not raised")
    check(p._normalize_mac("") == "", "_normalize_mac: empty input is refused")

    # ── the magic packet builder (hand-computed against a known MAC) ─────────
    packet = p.build_magic_packet("aa:bb:cc:dd:ee:ff")
    check(len(packet) == 102, f"build_magic_packet: exactly 102 bytes with no SecureOn (got {len(packet)})")
    check(packet[:6] == b"\xff" * 6, "build_magic_packet: starts with 6 sync bytes (0xFF)")
    mac_bytes = bytes.fromhex("aabbccddeeff")
    check(packet[6:12] == mac_bytes, "build_magic_packet: the MAC repeats starting right after the sync bytes")
    check(packet[6:] == mac_bytes * 16, "build_magic_packet: the MAC repeats exactly 16 times")
    check(
        p.build_magic_packet("not-a-mac") is None, "build_magic_packet: an invalid MAC returns None, not a bad packet"
    )

    with_secureon = p.build_magic_packet("aa:bb:cc:dd:ee:ff", secureon=bytes.fromhex("11223344"))
    check(
        len(with_secureon) == 106 and with_secureon[102:] == bytes.fromhex("11223344"),
        f"build_magic_packet: a 4-byte SecureOn password is appended after the 102 bytes (got len={len(with_secureon)})",
    )
    with_secureon6 = p.build_magic_packet("aa:bb:cc:dd:ee:ff", secureon=bytes.fromhex("112233445566"))
    check(
        len(with_secureon6) == 108,
        f"build_magic_packet: a 6-byte SecureOn password is also accepted (got len={len(with_secureon6)})",
    )

    # ── SecureOn password parsing ─────────────────────────────────────────────
    parsed, err = p.parse_secureon("aa:bb:cc:dd")
    check(parsed == bytes.fromhex("aabbccdd") and err is None, "parse_secureon: a 4-byte colon-separated password")
    parsed, err = p.parse_secureon("aabbccddeeff")
    check(parsed == bytes.fromhex("aabbccddeeff") and err is None, "parse_secureon: a bare 6-byte password")
    parsed, err = p.parse_secureon("aabbcc")
    check(parsed is None and "4 or 6 bytes" in err, "parse_secureon: 3 bytes is neither valid length, refused")
    parsed, err = p.parse_secureon("")
    check(parsed is None and err is not None, "parse_secureon: empty input is refused with a reason")

    # ── directed broadcast address computation ────────────────────────────────
    check(p.directed_broadcast("10.0.0.0/24") == "10.0.0.255", "directed_broadcast: a /24")
    check(p.directed_broadcast("192.168.1.0/25") == "192.168.1.127", "directed_broadcast: a /25")
    check(
        p.directed_broadcast("10.0.0.5/24") == "10.0.0.255",
        "directed_broadcast: a host address in the CIDR still resolves the network's broadcast",
    )
    check(p.directed_broadcast("not-a-cidr") is None, "directed_broadcast: garbage CIDR returns None, not an error")

    # ── rate-limit window ──────────────────────────────────────────────────────
    check(p.rate_limited(None, 100.0) is False, "rate_limited: never sent before is never rate-limited")
    check(p.rate_limited(100.0, 102.0, window_s=5) is True, "rate_limited: 2s after a send, inside the 5s window")
    check(p.rate_limited(100.0, 105.5, window_s=5) is False, "rate_limited: past the window, no longer limited")
    check(p.rate_limited(100.0, 105.0, window_s=5) is False, "rate_limited: exactly at the window edge is not limited")

    # ── write gate — viewers can look at Wake & Actions but not send a wake ──
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    for fn, args in (
        (p.add_favourite, ()),
        (p.delete_favourite, (1,)),
        (p.wake_favourite, (1,)),
        (p.wake_from_row, ()),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p._is_admin() is True, "admin role restored for the rest of the run")

    # ── 1.0.1: the rate-limit map stays bounded ──────────────────────────────
    stale = {"aa:aa:aa:aa:aa:01": 10.0, "aa:aa:aa:aa:aa:02": 95.0, "aa:aa:aa:aa:aa:03": 100.0}
    pruned = p.prune_rate_map(stale, 100.0)
    check(
        set(pruned) == {"aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:03"},
        f"prune_rate_map: an entry older than a minute is dropped, recent ones kept (got {sorted(pruned)})",
    )
    check(p.prune_rate_map({}, 1.0) == {}, "prune_rate_map: an empty map stays empty")

    # ── a fake database and request, to run the impure routes ────────────────
    class FakeDB:
        def __init__(self, selects=None, hook=None):
            self.statements = []
            self.selects = list(selects or [])
            self.rowcount = 1
            self.rolled_back = 0
            self.hook = (
                hook  # called with (kind, sql, params) after the statement is recorded; may raise or set rowcount
            )

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            kind = sql.split()[0].upper()
            self.statements.append((kind, sql, params))
            self.rowcount = 1
            if self.hook:
                self.hook(self, kind, sql, params)

        def rollback(self):
            self.rolled_back += 1

        def fetchone(self):
            return self.selects.pop(0) if self.selects else None

        def fetchall(self):
            return self.selects.pop(0) if self.selects else []

        def commit(self):
            pass

        def close(self):
            pass

        def kinds(self):
            return [s[0] for s in self.statements]

    only_one = lambda sid: sid == 1  # noqa: E731 - a subnet-restricted caller: subnet 1; None is not theirs
    everything = lambda sid: True  # noqa: E731 - an unrestricted caller
    flashed, sent = [], []
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/x"
    p.jsonify = lambda payload: payload
    p._require_write = lambda: True
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    p._send_wake = lambda mac, cidr, secureon: sent.append((mac, cidr, secureon))
    mac_subnet = {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2}  # a MAC Jen has never seen is absent
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.0.1: a wake from a row is judged on the MAC's own subnet ───────────
    p._can = only_one
    for label, mac, hint in (
        ("a MAC in subnet 2, the query string naming subnet 1", "aa:bb:cc:dd:ee:02", "1"),
        ("a MAC Jen has never seen, the query string naming subnet 1", "aa:bb:cc:dd:ee:99", "1"),
    ):
        sent.clear()
        p._last_sent.clear()
        p._get_db = lambda: FakeDB([None])  # no favourite row
        p.request = types.SimpleNamespace(args={"mac": mac, "subnet_id": hint, "ip": "10.1.0.5"})
        p.wake_from_row()
        check(sent == [], f"wake_from_row: {label} sends nothing")
    sent.clear()
    p._last_sent.clear()
    p._get_db = lambda: FakeDB([None, None])
    p.request = types.SimpleNamespace(args={"mac": "aa:bb:cc:dd:ee:01", "subnet_id": "2"})
    p.wake_from_row()
    check(
        sent == [("aa:bb:cc:dd:ee:01", "10.1.0.0/24", None)],
        f"wake_from_row: a MAC in the caller's subnet is woken on ITS subnet, not the one named in the URL (got {sent})",
    )
    # a MAC with no lease or reservation falls back to its favourite's stored subnet
    sent.clear()
    p._last_sent.clear()
    p._get_db = lambda: FakeDB([{"subnet_id": 1, "secureon": "aa:bb:cc:dd"}, None])
    p.request = types.SimpleNamespace(args={"mac": "aa:bb:cc:dd:ee:99"})
    p.wake_from_row()
    check(
        len(sent) == 1 and sent[0][1] == "10.1.0.0/24",
        "wake_from_row: a MAC with no lease uses its favourite's stored subnet",
    )
    sent.clear()
    p._last_sent.clear()
    p._can = everything
    p._get_db = lambda: FakeDB([None, None])
    p.request = types.SimpleNamespace(args={"mac": "aa:bb:cc:dd:ee:99"})
    p.wake_from_row()
    check(len(sent) == 1, "wake_from_row: an unrestricted caller may wake a MAC with no subnet")

    # ── 1.0.1: adding a favourite takes the subnet from the MAC, keeps SecureOn ─
    p._can = only_one
    for label, mac, ip in (
        ("a MAC in subnet 2, an address typed in subnet 1", "aa:bb:cc:dd:ee:02", "10.1.0.9"),
        ("a MAC Jen has never seen, an address typed in subnet 1", "aa:bb:cc:dd:ee:99", "10.1.0.9"),
    ):
        fdb = FakeDB()
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(form={"mac": mac, "ip": ip, "label": "x", "secureon": ""})
        p.add_favourite()
        check(
            "INSERT" not in fdb.kinds(),
            f"add_favourite: {label} is refused, nothing stored (got {fdb.kinds()})",
        )
    fdb = FakeDB()
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(form={"mac": "aa:bb:cc:dd:ee:01", "ip": "10.2.0.9", "label": "x", "secureon": ""})
    p.add_favourite()
    insert = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(insert) == 1 and insert[0][2] == ("aa:bb:cc:dd:ee:01", None, 1, "x", None),
        f"add_favourite: the subnet is the MAC's (1); an address in another subnet is not stored (got {insert and insert[0][2]})",
    )
    check(
        "ON DUPLICATE" not in insert[0][1], "add_favourite: a new favourite is a plain INSERT, never an upsert (1.1.4)"
    )
    fdb = FakeDB([{"subnet_id": 1}])  # a re-add: the row exists, in the caller's subnet
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "x", "secureon": ""})
    p.add_favourite()
    upd = [s for s in fdb.statements if s[0] == "UPDATE"]
    check(
        len(upd) == 1 and "IF(%s IS NULL, secureon, %s)" in upd[0][1],
        "add_favourite: a blank SecureOn on a re-add keeps the stored one",
    )
    check(
        "subnet_id=" not in upd[0][1].split("WHERE")[0] and "subnet_id <=> %s" in upd[0][1],
        "add_favourite: the UPDATE never sets subnet_id and is conditioned on the judged owner",
    )

    # ── 1.0.1: a favourite is judged on its own row ──────────────────────────
    # _current_subnet_for_mac returns None here so each case is judged on the row's own STORED
    # subnet, exactly as before the moved-favourite fix (that fix gets its own tests below).
    p._can = only_one
    p._current_subnet_for_mac = lambda mac: None
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check(
        "DELETE" not in fdb.kinds() and flashed[-1] == "Favourite not found.",
        "delete_favourite: a favourite in subnet 2 reads as not found to a caller scoped to subnet 1",
    )
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": None}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check("DELETE" not in fdb.kinds(), "delete_favourite: a favourite with no subnet is not a scoped caller's")
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check("DELETE" in fdb.kinds(), "delete_favourite: a favourite in the caller's own subnet is theirs to remove")
    p._can = everything
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": None}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check("DELETE" in fdb.kinds(), "delete_favourite: an unrestricted caller removes any favourite")
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.1.2: a favourite is a STORED object - judged on its OWN subnet; the wake on where the host is NOW ──
    p._can = only_one
    # stored in the caller's subnet 1, the MAC has since moved to subnet 2: the favourite is still theirs to edit and delete
    p._current_subnet_for_mac = lambda mac: 2
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check(
        "DELETE" in fdb.kinds(),
        "delete_favourite: stored in A, host now in B - the favourite is still the A caller's to remove",
    )
    # ...but not theirs to WAKE: the host is now on a network they cannot see, so nothing is sent
    fdb = FakeDB([{"subnet_id": 1, "secureon": None, "label": "x", "mac": "aa:bb:cc:dd:ee:01"}])
    p._get_db = lambda fdb=fdb: fdb
    sent.clear()
    p.wake_favourite(5)
    check(
        sent == [] and flashed[-1] == "That MAC is not on a subnet you can access.",
        f"wake_favourite: stored in A, host now in B - the A caller cannot wake it (got {sent}, {flashed[-1]!r})",
    )
    # the leak direction: stored in subnet 2 (not the caller's), the MAC is now in the caller's subnet 1
    p._current_subnet_for_mac = lambda mac: 1
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check(
        "DELETE" not in fdb.kinds() and flashed[-1] == "Favourite not found.",
        "delete_favourite: stored in B, host now in A - not found for the A caller, nothing deleted",
    )
    fdb = FakeDB([{"subnet_id": 2, "secureon": "aa:bb:cc:dd", "label": "x", "mac": "aa:bb:cc:dd:ee:01"}])
    p._get_db = lambda fdb=fdb: fdb
    sent.clear()
    p._last_sent.clear()
    p.wake_favourite(5)
    check(
        sent == [] and flashed[-1] == "Favourite not found.",
        f"wake_favourite: stored in B, host now in A - not found for the A caller, nothing sent (got {sent})",
    )
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # a favourite in the caller's own subnet, the host still there: the wake goes, with the favourite's SecureOn
    p._current_subnet_for_mac = lambda mac: 1
    fdb = FakeDB([{"subnet_id": 1, "secureon": "aa:bb:cc:dd", "label": "x", "mac": "aa:bb:cc:dd:ee:01"}])
    p._get_db = lambda fdb=fdb: fdb
    sent.clear()
    p._last_sent.clear()
    p.wake_favourite(5)
    check(
        len(sent) == 1 and sent[0][1] == "10.1.0.0/24" and sent[0][2] == bytes.fromhex("aabbccdd"),
        f"wake_favourite: stored in A, host in A - sent on A with the favourite's own SecureOn (got {sent})",
    )
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # the pure judgement: a wake and a stored favourite are two questions
    fav_b = {"subnet_id": 2, "secureon": "aa:bb:cc:dd"}
    fav_a = {"subnet_id": 1, "secureon": "aa:bb:cc:dd"}
    check(
        p.wake_inputs(fav_b, 1, only_one) == (1, None),
        "wake_inputs: stored in B, host now in A, an A caller - the wake goes on A and carries NO password",
    )
    check(
        p.wake_inputs(fav_a, 2, only_one) == (2, "aa:bb:cc:dd"),
        "wake_inputs: stored in A, host now in B - the favourite's password is the A caller's; the caller's scope then refuses B",
    )
    check(
        p.wake_inputs(fav_b, None, only_one) == (None, None)
        and p.wake_inputs(fav_a, None, only_one) == (1, "aa:bb:cc:dd"),
        "wake_inputs: a host with no current subnet falls back to the stored one only for a favourite the caller may see",
    )
    check(
        p.wake_inputs({"subnet_id": None, "secureon": "x"}, 1, only_one) == (1, None)
        and p.wake_inputs({"subnet_id": None, "secureon": "x"}, 1, everything) == (1, "x")
        and p.wake_inputs(None, 1, only_one) == (1, None),
        "wake_inputs: a favourite with no subnet is for an unrestricted caller only; no favourite, no password",
    )

    # add over an existing favourite: judged on the STORED subnet, both directions
    for label, stored, now, expect_insert in (
        ("stored in B, host now in A (the leak direction)", 2, 1, False),
        ("stored in A, host now in B", 1, 2, True),
        ("stored in A, host still in A", 1, 1, True),
    ):
        p._can = only_one
        p._current_subnet_for_mac = lambda mac, now=now: now
        fdb = FakeDB([{"subnet_id": stored}])
        p._get_db = lambda fdb=fdb: fdb
        p.request = types.SimpleNamespace(
            form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "renamed", "secureon": ""}
        )
        p.add_favourite()
        check(
            ("UPDATE" in fdb.kinds()) == expect_insert,
            f"add_favourite: {label} - the A caller {'may' if expect_insert else 'may not'} edit it (got {fdb.kinds()})",
        )
    p.request = None
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.0.3: add_favourite never moves an existing favourite's subnet ──────
    p._can = everything
    fdb = FakeDB([{"subnet_id": 2}])  # an existing row, stored in subnet 2
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "renamed", "secureon": ""})
    p.add_favourite()
    update = [s for s in fdb.statements if s[0] == "UPDATE"]
    check(
        len(update) == 1 and update[0][2][-1] == 2 and "INSERT" not in fdb.kinds(),
        f"add_favourite: re-adding an existing favourite keeps its STORED subnet, not the MAC's current one (got {update and update[0][2]})",
    )
    check(
        "SET subnet_id" not in update[0][1] and ", subnet_id" not in update[0][1].split("WHERE")[0],
        "add_favourite: subnet_id is not assigned by the UPDATE at all",
    )

    # ── 1.0.1: the wake API — a MAC with no subnet is for an unrestricted key only ─
    jen_api = types.ModuleType("jen.plugin_api")
    jen_api.normalize_mac = _stub_normalize_mac
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = jen_api
    sys.modules["jen"].plugin_api = jen_api

    def key_can(key, subnet_id, *, allow_unattributed=False):
        scope = key.get("subnet_ids")
        if scope is None:
            return True
        return subnet_id is not None and subnet_id in scope

    jen_api.api_key_can_access_subnet = key_can

    def _stub_json_object_body():
        body = sys.modules["flask"].request.get_json(silent=True)
        if isinstance(body, dict):
            return body, None
        return None, ("error-response", 400)

    def _stub_str_field(body, name, max_len=None):
        value = body.get(name) if isinstance(body, dict) else None
        if not isinstance(value, str):
            return ""
        value = value.strip()
        return value[:max_len] if max_len is not None else value

    jen_api.json_object_body = _stub_json_object_body
    jen_api.str_field = _stub_str_field
    for label, mac, key, expect in (
        ("a scoped key, MAC in its subnet", "aa:bb:cc:dd:ee:01", {"name": "k", "subnet_ids": [1]}, "ok"),
        ("a scoped key, MAC in another subnet", "aa:bb:cc:dd:ee:02", {"name": "k", "subnet_ids": [1]}, 403),
        ("a scoped key, MAC with no subnet", "aa:bb:cc:dd:ee:99", {"name": "k", "subnet_ids": [1]}, 403),
        ("an unrestricted key, MAC with no subnet", "aa:bb:cc:dd:ee:99", {"name": "all", "subnet_ids": None}, "ok"),
    ):
        sent.clear()
        p._last_sent.clear()
        p._get_db = lambda: FakeDB([None, None])
        sys.modules["flask"].g = types.SimpleNamespace(api_key=key)
        sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True, mac=mac: {"mac": mac})
        result = p._api_wake()
        got = result[1] if isinstance(result, tuple) else "ok"
        check(got == expect and (len(sent) == 1) == (expect == "ok"), f"_api_wake: {label} -> {expect}")

    # v1.0.4 — a malformed body (a JSON array, not an object) used to reach body.get(...) directly and
    # raise AttributeError, an unhandled 500; json_object_body() now refuses it with a real 400 first.
    sent.clear()
    p._get_db = lambda: FakeDB([None, None])
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "all", "subnet_ids": None})
    sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: [1, 2, 3])
    result = p._api_wake()
    check(
        isinstance(result, tuple) and result[1] == 400 and not sent,
        f"_api_wake: a JSON array body is refused with 400, not an uncaught 500 (got {result})",
    )
    p.request = None
    sys.modules["flask"].request = None

    # the never-built-into-a-packet test: a hidden favourite's SecureOn must not reach build_magic_packet, on any wake path
    built = []
    real_build = p.build_magic_packet

    def spy_build(mac, secureon=None):
        built.append(secureon)
        return real_build(mac, secureon)

    class _Sock:
        def setsockopt(self, *a):
            pass

        def sendto(self, packet, addr):
            pass

        def close(self):
            pass

    real_socket_mod = p.socket
    p.build_magic_packet = spy_build
    p.socket = types.SimpleNamespace(AF_INET=2, SOCK_DGRAM=2, SOL_SOCKET=1, SO_BROADCAST=6, socket=lambda *a: _Sock())
    import importlib.util as _ilu

    _spec = _ilu.spec_from_file_location("wol_plugin_raw", os.path.join(ROOT, "plugin.py"))
    _raw = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_raw)
    p._send_wake = types.FunctionType(_raw._send_wake.__code__, p.__dict__)  # the real one; the harness had stubbed it
    try:
        hidden = bytes.fromhex("aabbccdd")
        p._can = only_one
        p._current_subnet_for_mac = lambda mac: 1  # the host is in the caller's subnet; the favourite was saved in B
        p.request = types.SimpleNamespace(args={"mac": "aa:bb:cc:dd:ee:01"})
        p._last_sent.clear()
        p._get_db = lambda: FakeDB([{"subnet_id": 2, "secureon": "aa:bb:cc:dd"}, None])
        p.wake_from_row()
        check(
            built and hidden not in built,
            f"wake_from_row: a hidden favourite's SecureOn is never built into the packet (got {built})",
        )
        built.clear()
        p._last_sent.clear()
        sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": [1]})
        sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: {"mac": "aa:bb:cc:dd:ee:01"})
        p._get_db = lambda: FakeDB([{"subnet_id": 2, "secureon": "aa:bb:cc:dd"}, None])
        result = p._api_wake()
        check(
            result == {"ok": True, "mac": "aa:bb:cc:dd:ee:01"} and built and hidden not in built,
            f"_api_wake: a scoped key does not use a hidden favourite's SecureOn either (got {result}, {built})",
        )
        # the control: a favourite the caller may see DOES supply its password
        built.clear()
        p._last_sent.clear()
        p._get_db = lambda: FakeDB([{"subnet_id": 1, "secureon": "aa:bb:cc:dd"}, None])
        p._api_wake()
        check(built == [hidden], f"_api_wake: a favourite in the key's own scope supplies its SecureOn (got {built})")
        built.clear()
        p._last_sent.clear()
        p.request = types.SimpleNamespace(args={"mac": "aa:bb:cc:dd:ee:01"})
        p._get_db = lambda: FakeDB([{"subnet_id": 1, "secureon": "aa:bb:cc:dd"}, None])
        p.wake_from_row()
        check(built == [hidden], f"wake_from_row: ...and so does a session caller's own (got {built})")
        # the wake from the list, hidden favourite: refused before any packet
        built.clear()
        p._last_sent.clear()
        p._get_db = lambda: FakeDB(
            [{"subnet_id": 2, "secureon": "aa:bb:cc:dd", "label": "x", "mac": "aa:bb:cc:dd:ee:01"}]
        )
        p.wake_favourite(5)
        check(built == [], f"wake_favourite: a hidden favourite builds no packet at all (got {built})")
    finally:
        p.build_magic_packet = real_build
        p.socket = real_socket_mod
        p._send_wake = lambda mac, cidr, secureon: sent.append((mac, cidr, secureon))
        p.request = None
        sys.modules["flask"].request = None
        p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.0.1: sending prunes the rate map ───────────────────────────────────
    p._last_sent.clear()
    p._last_sent["aa:aa:aa:aa:aa:aa"] = -1000.0  # long dead
    p._get_db = lambda: FakeDB()
    p._wake_mac("aa:bb:cc:dd:ee:01", 1, None, "tester")
    check(
        "aa:aa:aa:aa:aa:aa" not in p._last_sent and "aa:bb:cc:dd:ee:01" in p._last_sent,
        "_wake_mac: a wake evicts long-dead rate entries and records the new one",
    )

    # ── 1.0.2: the SecureOn password is encrypted at rest ────────────────────
    check(p.is_encrypted_secureon("v1:gAAAA") is True, "is_encrypted_secureon: Jen's v1: format")
    check(
        p.is_encrypted_secureon("aa:bb:cc:dd") is False
        and p.is_encrypted_secureon("") is False
        and p.is_encrypted_secureon(None) is False,
        "is_encrypted_secureon: a legacy plain value, blank and None are not",
    )
    jen_api = types.ModuleType("jen.plugin_api")
    jen_api.encrypt_secret = lambda s: "v1:" + s[::-1]  # a stand-in with the same shape: reversible, prefixed
    jen_api.decrypt_secret = lambda s: s[3:][::-1]
    jen_api.normalize_mac = _stub_normalize_mac
    jen_api.json_object_body = _stub_json_object_body
    jen_api.str_field = _stub_str_field
    sys.modules["jen"] = types.ModuleType("jen")
    sys.modules["jen.plugin_api"] = jen_api
    sys.modules["jen"].plugin_api = jen_api
    p._can = everything
    p._current_subnet_for_mac = lambda mac: 1
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}}
    fdb = FakeDB()
    p._get_db = lambda: fdb
    p.request = types.SimpleNamespace(
        form={"mac": "aa:bb:cc:dd:ee:01", "label": "x", "secureon": "aa:bb:cc:dd"}, args={}
    )
    p.add_favourite()
    ins = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(ins) == 1 and ins[0][2][4] == "v1:" + "aa:bb:cc:dd"[::-1],
        "add_favourite: the SecureOn value stored is the ENCRYPTED form, never what was typed",
    )
    check(ins[0][2][4] != "aa:bb:cc:dd", "add_favourite: the plain text is not what reaches the database")
    # round trip: what add stored is what a wake decodes and sends
    stored = ins[0][2][4]
    sent.clear()
    p._last_sent.clear()
    fdb = FakeDB()
    p._get_db = lambda: fdb
    ok, err = p._wake_mac("aa:bb:cc:dd:ee:01", 1, stored, "tester")
    check(
        ok and len(sent) == 1 and sent[0][2] == bytes.fromhex("aabbccdd"),
        f"_wake_mac: an encrypted SecureOn round-trips to the 4 bytes that are sent (got {sent})",
    )
    check(
        not any(s[0] == "UPDATE" and "secureon" in s[1] for s in fdb.statements),
        "_wake_mac: an already-encrypted value is not rewritten",
    )
    # legacy: a plain value from 1.0.0/1.0.1 is accepted and re-encrypted on use
    sent.clear()
    p._last_sent.clear()
    fdb = FakeDB()
    p._get_db = lambda: fdb
    ok, err = p._wake_mac("aa:bb:cc:dd:ee:01", 1, "aa:bb:cc:dd", "tester")
    check(ok and sent[0][2] == bytes.fromhex("aabbccdd"), "_wake_mac: a legacy plain SecureOn value is still accepted")
    re_enc = [s for s in fdb.statements if s[0] == "UPDATE" and "secureon=%s" in s[1]]
    check(
        len(re_enc) == 1 and re_enc[0][2][0].startswith("v1:") and re_enc[0][2][2] == "aa:bb:cc:dd",
        "_wake_mac: ...and re-encrypted in place the first time it is used",
    )
    # a stored value that cannot be decrypted is a clear refusal, not a wake with no password
    jen_api.decrypt_secret = lambda s: (_ for _ in ()).throw(RuntimeError("wrong key marker-xyz"))
    sent.clear()
    p._last_sent.clear()
    ok, err = p._wake_mac("aa:bb:cc:dd:ee:01", 1, "v1:zzz", "tester")
    check(
        not ok and not sent and "marker-xyz" not in err,
        f"_wake_mac: an undecryptable SecureOn refuses the wake without leaking the exception (got {err!r})",
    )

    # ── 1.0.3: the API maps that same refusal to 409, not 500 ────────────────
    jen_api.api_key_can_access_subnet = lambda key, sid, **k: True
    sys.modules["flask"].g = types.SimpleNamespace(api_key={"name": "k", "subnet_ids": None})
    p._get_db = lambda: FakeDB([{"subnet_id": 1, "secureon": "v1:zzz"}])
    sys.modules["flask"].request = types.SimpleNamespace(get_json=lambda silent=True: {"mac": "aa:bb:cc:dd:ee:01"})
    result = p._api_wake()
    check(
        isinstance(result, tuple) and result[1] == 409,
        f"_api_wake: an undecryptable stored SecureOn is a 409, not a 500 (got {result})",
    )
    jen_api.decrypt_secret = lambda s: s[3:][::-1]

    # ── 1.0.2: the subnet comes from Jen's ONE precedence ────────────────────
    jen_api.client_subnet_for_mac = lambda mac: {"aa:bb:cc:dd:ee:09": 4}.get(mac)
    fresh = load_plugin()
    check(
        fresh._current_subnet_for_mac("aa:bb:cc:dd:ee:09") == 4
        and fresh._current_subnet_for_mac("aa:bb:cc:dd:ee:10") is None,
        "_current_subnet_for_mac: answered by plugin_api.client_subnet_for_mac, not a private copy",
    )

    # ── 1.1.2: the favourites list is judged on each favourite's STORED subnet ─
    p._can = only_one
    p._favourite_rows = lambda: [
        {
            "id": 1,
            "mac": "aa:bb:cc:dd:ee:01",
            "ip": "10.1.0.5",
            "subnet_id": 2,
            "label": "moved-in",
            "secureon": "v1:s",
        },
        {"id": 2, "mac": "aa:bb:cc:dd:ee:02", "ip": "10.2.0.5", "subnet_id": 1, "label": "moved-out", "secureon": None},
        {"id": 3, "mac": "aa:bb:cc:dd:ee:03", "ip": None, "subnet_id": None, "label": "no-subnet", "secureon": None},
    ]
    p._current_subnet_for_mac = lambda mac: {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2, "aa:bb:cc:dd:ee:03": 1}[
        mac
    ]
    p._subnet_map = lambda: {1: {"name": "A", "cidr": "10.1.0.0/24"}, 2: {"name": "B", "cidr": "10.2.0.0/24"}}
    p.render_template = lambda name, **kw: kw
    page = p.index()
    check(
        [r["label"] for r in page["rows"]] == ["moved-out"],
        f"index: stored in B (host now in A) and no-subnet are not listed for an A caller; stored in A (host now in B) is "
        f"(got {[r['label'] for r in page['rows']]})",
    )
    check(
        page["rows"][0]["subnet_name"] == "A" and page["rows"][0]["now_in"] == "",
        "index: the shown subnet is the STORED one, and a host now in a subnet the caller cannot see is not named",
    )
    p._can = lambda sid: sid in (1, 2)
    both = p.index()
    check(
        {r["label"]: r["now_in"] for r in both["rows"]}
        == {"moved-in": "A (10.1.0.0/24)", "moved-out": "B (10.2.0.0/24)"},
        f"index: a caller who may see both is told where each host is now (got {[(r['label'], r['now_in']) for r in both['rows']]})",
    )
    p._can = everything
    check(
        sorted(r["label"] for r in p.index()["rows"]) == ["moved-in", "moved-out", "no-subnet"],
        "index: an unrestricted caller sees every favourite, the one with no subnet included",
    )
    p._can = only_one

    # ── 1.0.2: a failed send does not put the exception text on the page ─────
    p._last_sent.clear()
    p._send_wake = lambda mac, cidr, secureon: (_ for _ in ()).throw(OSError("Network is unreachable marker-xyz"))
    ok, err = p._wake_mac("aa:bb:cc:dd:ee:01", 1, None, "tester")
    check(not ok and "marker-xyz" not in err, f"_wake_mac: a socket failure returns a generic message (got {err!r})")

    # ── register(): actually runs end to end against a stub jen.plugin_api ──
    row_action_calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    surfaces = sorted(c[1] for c in row_action_calls)
    check(
        surfaces == ["device", "lease", "reservation"],
        f"register(): a Wake row action is registered on all three surfaces (got {surfaces})",
    )
    check(
        all(c[2].get("confirm") == "Send a wake packet to {mac}?" for c in row_action_calls),
        "register(): every row action carries the same confirm sentence with {mac}",
    )
    check(
        len(INVESTIGATION_CALLS) == 1
        and INVESTIGATION_CALLS[0][0] == ("wol",)
        and INVESTIGATION_CALLS[0][1]["fn"] is p._investigate,
        "register(): exactly one investigation provider, the plugin's own",
    )

    # ── 1.1.0: the investigation provider ────────────────────────────────────
    check(
        p.in_scope(1, [1], False) and not p.in_scope(2, [1], False) and not p.in_scope(None, [1], False),
        "in_scope: a restricted caller sees only its own subnets, and None is never allow",
    )
    check(p.in_scope(None, [], True), "in_scope: an unrestricted caller sees an unattributed MAC")
    check(p.investigation_card(None) is None, "investigation_card: a client that is not a favourite adds no card")
    fav = {
        "label": "Media PC", "subnet_id": 1, "secureon": "v1:abc", "last_woken_at": None, "last_woken_by": None,
    }  # fmt: skip
    card = p.investigation_card(fav)
    check(
        "Media PC" in card["summary"] and "never woken" in card["summary"] and card["status"] == "ok",
        f"investigation_card: a favourite never woken says so (got {card['summary']!r})",
    )
    check(
        {"label": "SecureOn password", "value": "set"} in card["rows"]
        and all("v1:abc" not in str(r) for r in card["rows"]),
        "investigation_card: SecureOn is reported as set - the stored value never reaches the card",
    )
    check(
        {"label": "SecureOn password", "value": "not set"} in p.investigation_card(dict(fav, secureon=None))["rows"],
        "investigation_card: no SecureOn reads as not set",
    )
    import datetime as _dt

    woken = p.investigation_card(dict(fav, last_woken_at=_dt.datetime(2026, 10, 1, 8, 30), last_woken_by="admin"))
    check(
        "2026-10-01 08:30 UTC" in woken["summary"] and "by admin" in woken["summary"],
        f"investigation_card: the last wake and who sent it (got {woken['summary']!r})",
    )
    subject = types.SimpleNamespace(mac="AA:BB:CC:DD:EE:01")
    p._subnet_map = lambda: {1: {"name": "Servers", "cidr": "10.0.1.0/24"}, 2: {"name": "Lab", "cidr": "10.0.2.0/24"}}
    p._current_subnet_for_mac = lambda mac: 1
    fdb = FakeDB([dict(fav)])
    p._get_db = lambda: fdb
    got = p._investigate(subject, [1], False)
    check(
        got is not None and got["href"] == "/management/wol" and "Media PC" in got["summary"],
        f"_investigate: the card for a seeded favourite (got {got})",
    )
    check(
        "wol_hosts WHERE mac=%s" in fdb.statements[0][1] and fdb.statements[0][2] == ("aa:bb:cc:dd:ee:01",),
        "_investigate: the lookup is the one parameterised MAC query",
    )
    p._get_db = lambda: FakeDB([None])
    check(p._investigate(subject, [1], False) is None, "_investigate: a client that is not a favourite gets None")
    p._get_db = lambda: FakeDB([dict(fav)])
    check(
        p._investigate(subject, [2], False) is None,
        "_investigate: a favourite in a subnet outside the caller's set is None",
    )
    # ── 1.1.1: a STORED favourite is judged by its OWN subnet; where the client is now is only shown ──
    check(
        p.subnet_label(1, p._subnet_map()) == "Servers (10.0.1.0/24)"
        and p.subnet_label(9, p._subnet_map()) == ""
        and p.subnet_label(3, {3: {"name": "", "cidr": "10.0.3.0/24"}}) == "10.0.3.0/24",
        "subnet_label: name and CIDR, the CIDR alone when unnamed, nothing for an unknown subnet",
    )
    check(
        p.now_in(2, 1, p._subnet_map(), [1, 2], False) == "Lab (10.0.2.0/24)"
        and p.now_in(2, 1, p._subnet_map(), [], True) == "Lab (10.0.2.0/24)",
        "now_in: the subnet the client is in now, when the caller may see it and it differs from the stored one",
    )
    check(
        p.now_in(2, 1, p._subnet_map(), [1], False) == ""
        and p.now_in(1, 1, p._subnet_map(), [1], False) == ""
        and p.now_in(None, 1, p._subnet_map(), [1], False) == "",
        "now_in: nothing for a subnet the caller cannot see (naming it is access), an unchanged one, or an unknown one",
    )
    # the leak direction: saved in B, the client has since moved to A - a caller scoped to A must NOT see what was stored in B
    p._current_subnet_for_mac = lambda mac: 1
    p._get_db = lambda: FakeDB([dict(fav, subnet_id=2)])
    check(
        p._investigate(subject, [1], False) is None,
        "_investigate: a favourite saved in B is not shown to a caller scoped to A because the client is now in A",
    )
    p._get_db = lambda: FakeDB([dict(fav, subnet_id=2)])
    check(
        p._investigate(subject, [1, 2], False) is not None and p._investigate(subject, [], True) is not None,
        "_investigate: the same favourite is shown to a caller who may see B, and to an unrestricted one",
    )
    # the other direction: saved in A, the client is now in B - A's caller sees the favourite, but is not told B
    p._current_subnet_for_mac = lambda mac: 2
    p._get_db = lambda: FakeDB([dict(fav)])
    moved = p._investigate(subject, [1], False)
    check(
        moved is not None and all(r["label"] != "Now in" for r in moved["rows"]) and "Lab" not in str(moved),
        "_investigate: saved in A and now in B, a caller scoped to A sees the favourite and no word of B",
    )
    p._get_db = lambda: FakeDB([dict(fav)])
    both = p._investigate(subject, [1, 2], False)
    check(
        both is not None and {"label": "Now in", "value": "Lab (10.0.2.0/24)"} in both["rows"],
        "_investigate: a caller who may see both is told where the client is now",
    )
    p._current_subnet_for_mac = lambda mac: None  # no lease or reservation: nothing to add, the favourite still shows
    p._get_db = lambda: FakeDB([dict(fav)])
    check(
        p._investigate(subject, [1], False) is not None
        and all(r["label"] != "Now in" for r in p._investigate(subject, [1], False)["rows"]),
        "_investigate: a client with no current subnet still shows its favourite, with no Now in row",
    )
    p._current_subnet_for_mac = lambda mac: 1
    p._get_db = lambda: FakeDB([dict(fav)])
    check(
        all(r["label"] != "Now in" for r in p._investigate(subject, [1], False)["rows"]),
        "_investigate: a client still in the subnet it was saved in has no Now in row",
    )
    p._get_db = lambda: FakeDB([dict(fav, subnet_id=None)])
    check(
        p._investigate(subject, [1], False) is None and p._investigate(subject, [], True) is not None,
        "_investigate: a favourite with no stored subnet is for an unrestricted caller only - even when the client is now in one",
    )
    check(
        p._investigate(types.SimpleNamespace(mac=""), [1], True) is None
        and p._investigate(types.SimpleNamespace(mac="nope"), [1], True) is None,
        "_investigate: a subject with no (or an invalid) MAC gets None",
    )

    # ── 1.1.3: three-state lookups. A favourite stored in B (hidden), the client visible in A, the FIRST statement raising and every
    #    later write able to succeed: the route must refuse, write nothing and audit nothing ──
    class _FlakyFirst:
        def __init__(self, selects):
            self.calls, self.dbs, self.selects = 0, [], selects

        def __call__(self):
            self.calls += 1
            if self.calls == 1:
                bad = FakeDB()
                bad.execute = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down"))
                return bad
            db = FakeDB(list(self.selects))
            self.dbs.append(db)
            return db

    audits_h = []
    p._audit = lambda action, target, detail: audits_h.append((action, target, detail))
    sys.modules["jen.plugin_api"].encrypt_secret = lambda s: (
        "v1:" + s[::-1]
    )  # the route parses SecureOn before it looks anything up
    p._require_write = lambda: True
    p._can = only_one
    p._current_subnet_for_mac = lambda mac: 1
    flaky = _FlakyFirst([{"subnet_id": 2}])
    p._get_db = flaky
    flashed.clear()
    p.request = types.SimpleNamespace(
        form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "hijack", "secureon": "11:22:33:44"}, args={}
    )
    p.add_favourite()
    writes = [k for db in flaky.dbs for k in db.kinds() if k in ("INSERT", "UPDATE", "DELETE")]
    check(
        writes == []
        and audits_h == []
        and flashed == ["Could not check the existing record \u2014 nothing was changed."],
        f"add_favourite: a hidden favourite, the client visible in A, the lookup raising - refused, nothing written, nothing audited "
        f"(writes={writes}, audits={audits_h}, flashed={flashed})",
    )
    flaky2 = _FlakyFirst([{"subnet_id": 2}])
    p._get_db = flaky2
    flashed.clear()
    p.add_favourite()
    check(
        flaky2.calls == 1 and not flaky2.dbs,
        "add_favourite: after a failed lookup the route never even opens a second connection to write with",
    )

    # ── 1.1.4: authorization and mutation are ONE transaction. A B-owned row that appears or changes between the judgement
    #    and the write is never modified: the write is conditioned on the judged owner, the count is checked, a lost race is
    #    re-judged on the row that WON ──
    class _Dup(Exception):
        pass

    def duplicate(*a):
        err = _Dup("Duplicate entry")
        err.args = (1062, "Duplicate entry")
        return err

    def mutations(db):
        return [k for k in db.kinds() if k in ("INSERT", "UPDATE", "DELETE")]

    p._can = only_one  # the caller is an admin of subnet 1 (A); subnet 2 (B) is hidden from them
    p._current_subnet_for_mac = lambda mac: 1
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    audits_h.clear()

    # (a) judged as A's row, then the row is no longer A's when the UPDATE runs (0 rows match the owner predicate)
    def moved_to_b(db, kind, sql, params):
        if kind == "UPDATE":
            db.rowcount = 0  # nothing matched "subnet_id <=> 1"
            db.selects[:] = [{"subnet_id": 2}]  # what a look under the lock now finds

    race = FakeDB([{"subnet_id": 1}], hook=moved_to_b)
    p._get_db = lambda: race
    flashed.clear()
    p.request = types.SimpleNamespace(
        form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "x", "secureon": ""}, args={}
    )
    p.add_favourite()
    check(
        flashed == [p.CHANGED_UNDERFOOT] and race.rolled_back == 1 and audits_h == [],
        f"add_favourite: the row became B's between judge and write - the request refuses, rolls back, audits nothing (flashed={flashed})",
    )
    # (b) the same UPDATE that changes nothing (values already stored) is a success, not a refusal
    unchanged = FakeDB(
        [{"subnet_id": 1}],
        hook=lambda db, kind, sql, params: (
            (setattr(db, "rowcount", 0), db.selects.__setitem__(slice(None), [{"subnet_id": 1}]))
            if kind == "UPDATE"
            else None
        ),
    )
    p._get_db = lambda: unchanged
    flashed.clear()
    p.add_favourite()
    check(
        flashed and flashed[0].endswith("added to favourites.") and unchanged.rolled_back == 0,
        f"add_favourite: a re-save of identical values (MySQL counts 0 changed rows) is still a success (flashed={flashed})",
    )
    # (c) a new MAC: the INSERT loses the race (1062) to a B-owned favourite - the winner is locked and judged, never overwritten
    state = {"n": 0}

    def lose_to_b(db, kind, sql, params):
        if kind == "INSERT":
            db.selects[:] = [{"subnet_id": 2}]  # the row that won
            raise duplicate()

    lost = FakeDB([], hook=lose_to_b)
    p._get_db = lambda: lost
    flashed.clear()
    audits_h.clear()
    p.add_favourite()
    check(
        mutations(lost) == ["INSERT"] and flashed == [p.NOT_YOURS] and audits_h == [],
        f"add_favourite: lost the INSERT race to a B-owned favourite - judged again, refused, never UPDATEd (got {mutations(lost)}, {flashed})",
    )

    # (d) ... and a winner in the caller's own subnet is updated (with the owner predicate), not refused
    def lose_to_a(db, kind, sql, params):
        if kind == "INSERT":
            db.selects[:] = [{"subnet_id": 1}]
            raise duplicate()

    lost_a = FakeDB([], hook=lose_to_a)
    p._get_db = lambda: lost_a
    flashed.clear()
    p.add_favourite()
    check(
        mutations(lost_a) == ["INSERT", "UPDATE"]
        and lost_a.statements[-1][2][-1] == 1
        and flashed[0].endswith("added to favourites."),
        f"add_favourite: lost the INSERT race to a favourite in the caller's own subnet - updated under the owner predicate (got {mutations(lost_a)})",
    )

    # (e) a deadlock between two inserts of one MAC (1213) rolls back and is judged again the same way
    def deadlock(db, kind, sql, params):
        if kind == "INSERT" and state["n"] == 0:
            state["n"] = 1
            err = _Dup("Deadlock found")
            err.args = (1213, "Deadlock found")
            db.selects[:] = [{"subnet_id": 2}]
            raise err

    dead = FakeDB([], hook=deadlock)
    p._get_db = lambda: dead
    flashed.clear()
    p.add_favourite()
    check(
        mutations(dead) == ["INSERT"] and dead.rolled_back >= 1 and flashed == [p.NOT_YOURS],
        f"add_favourite: a deadlocked INSERT is rolled back and the winner (B's) re-judged and refused (got {mutations(dead)}, {flashed})",
    )
    # (f) every SELECT that judges a row locks it
    check(
        all("FOR UPDATE" in s[1] for s in race.statements if s[0] == "SELECT"),
        "add_favourite: every SELECT that judges the row is FOR UPDATE",
    )

    # (g) delete: the same discipline - FOR UPDATE, owner predicate, count checked
    def row_gone(db, kind, sql, params):
        if kind == "DELETE":
            db.rowcount = 0

    gone = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}], hook=row_gone)
    p._get_db = lambda: gone
    flashed.clear()
    audits_h.clear()
    p.delete_favourite(7)
    dels = [s for s in gone.statements if s[0] == "DELETE"]
    check(
        flashed == [p.CHANGED_UNDERFOOT]
        and audits_h == []
        and gone.rolled_back == 1
        and "subnet_id <=> %s" in dels[0][1]
        and dels[0][2] == (7, 1)
        and "FOR UPDATE" in gone.statements[0][1],
        f"delete_favourite: FOR UPDATE, deleted under the judged owner, a count that is not 1 refuses and audits nothing (flashed={flashed})",
    )

    # the control: the same call with a healthy lookup refuses too (hidden favourite), and a MAC with no favourite is added
    p._get_db = lambda: FakeDB([{"subnet_id": 2}])
    audits_h.clear()
    flashed.clear()
    p.add_favourite()
    check(
        audits_h == [] and flashed == ["That MAC is not on a subnet you can access."],
        "add_favourite: the healthy lookup refuses a hidden favourite",
    )
    p.request = None

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
        def __init__(self, selects=None):
            self.statements = []
            self.selects = list(selects or [])

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), sql, params))

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
        "IF(VALUES(secureon) IS NULL, secureon, VALUES(secureon))" in insert[0][1],
        "add_favourite: a blank SecureOn on a re-add keeps the stored one",
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

    # ── 1.0.3: a favourite is judged on where its MAC is NOW, stored only as a fallback ──
    p._can = only_one
    # stored subnet 1 (the caller's own), but the MAC has since moved to subnet 2
    p._current_subnet_for_mac = lambda mac: 2
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 1}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check(
        "DELETE" not in fdb.kinds(),
        "delete_favourite: a favourite that MOVED out of the caller's subnet is not theirs any more",
    )
    fdb = FakeDB([{"subnet_id": 1, "secureon": None, "label": "x", "mac": "aa:bb:cc:dd:ee:01"}])
    p._get_db = lambda fdb=fdb: fdb
    sent.clear()
    p.wake_favourite(5)
    check(
        sent == [],
        f"wake_favourite: a favourite that MOVED out of the caller's subnet cannot be woken by them (got {sent})",
    )
    # and the reverse: stored subnet 2 (not the caller's), but the MAC is now in the caller's subnet 1
    p._current_subnet_for_mac = lambda mac: 1
    fdb = FakeDB([{"mac": "aa:bb:cc:dd:ee:01", "subnet_id": 2}])
    p._get_db = lambda fdb=fdb: fdb
    p.delete_favourite(5)
    check(
        "DELETE" in fdb.kinds(),
        "delete_favourite: a favourite that moved INTO the caller's subnet is now theirs",
    )
    p._current_subnet_for_mac = lambda mac: mac_subnet.get(mac)

    # ── 1.0.3: add_favourite never moves an existing favourite's subnet ──────
    p._can = everything
    fdb = FakeDB([{"subnet_id": 2}])  # an existing row, stored in subnet 2
    p._get_db = lambda fdb=fdb: fdb
    p.request = types.SimpleNamespace(form={"mac": "aa:bb:cc:dd:ee:01", "ip": "", "label": "renamed", "secureon": ""})
    p.add_favourite()
    insert = [s for s in fdb.statements if s[0] == "INSERT"]
    check(
        len(insert) == 1 and insert[0][2][2] == 2,
        f"add_favourite: re-adding an existing favourite keeps its STORED subnet, not the MAC's current one (got {insert and insert[0][2]})",
    )
    check(
        "subnet_id=VALUES(subnet_id)" not in insert[0][1],
        "add_favourite: subnet_id is not in the UPDATE clause at all",
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
        p.request = types.SimpleNamespace(get_json=lambda silent=True, mac=mac: {"mac": mac})
        result = p._api_wake()
        got = result[1] if isinstance(result, tuple) else "ok"
        check(got == expect and (len(sent) == 1) == (expect == "ok"), f"_api_wake: {label} -> {expect}")
    p.request = None

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
    p.request = types.SimpleNamespace(get_json=lambda silent=True: {"mac": "aa:bb:cc:dd:ee:01"})
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

    # ── 1.0.3: the favourites list is judged on the MAC's CURRENT subnet ─────
    p._can = only_one
    p._favourite_rows = lambda: [
        {"id": 1, "mac": "aa:bb:cc:dd:ee:01", "ip": "10.1.0.5", "subnet_id": 2, "label": "moved-in", "secureon": None},
        {"id": 2, "mac": "aa:bb:cc:dd:ee:02", "ip": "10.2.0.5", "subnet_id": 1, "label": "moved-out", "secureon": None},
    ]
    p._current_subnet_for_mac = lambda mac: {"aa:bb:cc:dd:ee:01": 1, "aa:bb:cc:dd:ee:02": 2}[mac]
    p._subnet_map = lambda: {1: {"name": "A", "cidr": "10.1.0.0/24"}, 2: {"name": "B", "cidr": "10.2.0.0/24"}}
    p.render_template = lambda name, **kw: kw
    page = p.index()
    check(
        [r["label"] for r in page["rows"]] == ["moved-in"],
        f"index: judged on the MAC's current subnet, not the stale stored one (got {[r['label'] for r in page['rows']]})",
    )
    check(page["rows"][0]["subnet_name"] == "A", "index: the shown subnet name is the current one too")

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

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

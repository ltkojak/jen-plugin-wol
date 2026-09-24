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

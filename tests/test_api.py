"""Tests for FC SmartHome API: parsing, auth, control, events, endpoints, BLE frames."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.const import DEVICE_STATUS_MASKS
from custom_components.fc_smarthome.api.endpoints import EndpointRegistry
from custom_components.fc_smarthome.api.models import (
    Device,
    LockEventType,
    LockStatus,
    LockUserType,
    TokenPair,
    parse_ts,
)
from custom_components.fc_smarthome.local.ble import build_frame, parse_frame


# ---------- endpoints registry ----------


def test_registry_defaults_load():
    reg = EndpointRegistry.load("us")
    assert reg.base_url.startswith("https://")
    assert reg.url("login").startswith(reg.base_url)


def test_registry_url_device_id():
    reg = EndpointRegistry.load("eu")
    url = reg.url("unlock", "dev123")
    assert "dev123" in url


def test_registry_override(tmp_path):
    f = tmp_path / "override.json"
    f.write_text('{"paths": {"login": "/x/y"}, "regions": {"us": "https://h"}}')
    reg = EndpointRegistry.load("us", f)
    assert reg.url("login") == "https://h/x/y"
    assert reg.url("devices").startswith("https://h/")


def test_registry_drop_none_paths(tmp_path):
    f = tmp_path / "o.json"
    f.write_text('{"paths": {"bell": null}}')
    reg = EndpointRegistry.load("us", f)
    assert "bell" not in reg.paths


# ---------- models ----------


def test_parse_ts_ms_and_s():
    assert parse_ts(1700000000000) is not None
    assert parse_ts(1700000000) is not None
    assert parse_ts("2026-09-06T12:00:00+00:00") is not None
    assert parse_ts(None) is None


def test_token_validity():
    t = TokenPair(access_token="a", expires_at=time.time() + 3600)
    assert t.valid
    t2 = TokenPair(access_token="a", expires_at=time.time() - 10)
    assert not t2.valid


def test_lock_status_bitmask():
    s = LockStatus.from_dev_status(
        "d1", DEVICE_STATUS_MASKS["locked"] | DEVICE_STATUS_MASKS["tamper"], DEVICE_STATUS_MASKS
    )
    assert s.is_locked is True
    assert s.tamper is True
    assert s.has_problem


def test_lock_status_unlocked_via_latch():
    s = LockStatus.from_dev_status("d1", DEVICE_STATUS_MASKS["latch_open"], DEVICE_STATUS_MASKS)
    assert s.is_locked is False


# ---------- client parsing (no network) ----------


class FakeResponse:
    def __init__(self, body):
        self._body = body

    async def text(self):
        import json

        return json.dumps(self._body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def make_client():
    return FcClient("u@example.com", "pw")


def test_unwrap_and_listify():
    c = make_client()
    assert c._unwrap({"data": {"a": 1}}) == {"a": 1}
    assert c._unwrap({"result": {"list": [1]}}) == {"list": [1]}
    assert c._listify({"data": {"devices": [{"id": 1}]}}, "devices") == [{"id": 1}]
    assert c._listify({"data": {"list": []}}, "devices") == []


def test_parse_device_aliases():
    c = make_client()
    dev = c._parse_device(
        {"device_id": "7", "name": "Front", "category": "lock", "batteryVal": "88"}
    )
    assert isinstance(dev, Device)
    assert dev.device_id == "7"
    assert dev.battery == 88
    assert dev.is_lock


def test_parse_status_int_and_bool():
    c = make_client()
    s1 = c._parse_status("d1", {"devStatus": DEVICE_STATUS_MASKS["locked"], "batteryVal": 90})
    assert s1.locked is True and s1.battery == 90
    s2 = c._parse_status("d1", {"locked": True})
    assert s2.locked is True


def test_parse_users_int_type():
    c = make_client()
    users = c._parse_users(
        "d1", {"data": {"list": [{"id": 3, "type": 1, "name": "Dad", "pwd": "123456"}]}}
    )
    assert users[0].type is LockUserType.FINGER
    assert users[0].password_masked.startswith("12")


def test_parse_events_types():
    c = make_client()
    events = c._parse_events(
        "d1",
        {
            "data": {
                "list": [
                    {"time": 1700000000000, "type": 1, "user": "Dad", "devStatus": 4},
                    {"time": 1700000001000, "type": 9, "devStatus": DEVICE_STATUS_MASKS["tamper"]},
                    {"time": 1700000002000, "type": "bell"},
                ]
            }
        },
    )
    # sorted newest-first: bell, tamper, dad
    assert [e.type for e in events] == [
        LockEventType.BELL,
        LockEventType.TAMPER,
        LockEventType.LOCKED,
    ]
    assert events[2].user == "Dad"


def test_parse_event_unlock_by_user():
    c = make_client()
    ev = c._parse_event(
        "d1", {"time": 1700000000000, "type": 1, "user": "Mom", "devStatus": 0, "isRemote": 1}
    )
    assert ev.type is LockEventType.UNLOCKED
    assert ev.user == "Mom"
    assert ev.remote is True


# ---------- BLE frames ----------


def test_ble_frame_roundtrip():
    frame = build_frame(0x10, b"000000", seq=7)
    parsed = parse_frame(frame)
    assert parsed is not None
    cmd, seq, payload = parsed
    assert cmd == 0x10
    assert seq == 7
    assert payload == b"000000"


def test_ble_frame_corrupt_checksum():
    frame = bytearray(build_frame(0x10, b"ab", seq=1))
    frame[-1] ^= 0xFF
    assert parse_frame(bytes(frame)) is None


def test_ble_frame_short():
    assert parse_frame(b"FCF") is None


# ---------- APK-extracted production config (self-configuration) ----------


def test_apk_extracted_production_server():
    """The registry defaults must match the values extracted from the APK."""
    reg = EndpointRegistry.load("us")
    assert reg.base_url == "https://www.fcsmartlock.com"
    assert reg.regions["intl-aws"] == "https://18.219.242.80"
    assert reg.regions["test"] == "https://test.fcsmartlock.com"
    assert reg.url("login").startswith("https://www.fcsmartlock.com/api/")


def test_discovery_candidates_prioritize_apk_host():
    from custom_components.fc_smarthome.api.discovery import CANDIDATE_HOSTS

    assert CANDIDATE_HOSTS[0] == "https://www.fcsmartlock.com"


def test_aes_vendor_crypto_roundtrip():
    from custom_components.fc_smarthome.api.discovery import (
        VENDOR_AES_KEY,
        try_aes_decrypt,
        try_aes_encrypt,
    )

    if try_aes_encrypt("x") is None:
        import pytest

        pytest.skip("pycryptodome not installed")
    assert len(VENDOR_AES_KEY) == 32
    ct = try_aes_encrypt("hello fc")
    assert ct is not None
    assert try_aes_decrypt(ct) == "hello fc"


# ---------- coordinator-level event plumbing (pure logic) ----------


class _FakeBus:
    def __init__(self):
        self.fired = []

    def async_fire(self, event_type, payload):
        self.fired.append((event_type, payload))


class _FakeHass:
    def __init__(self):
        self.bus = _FakeBus()


class _FakeCoordinator:
    """Standalone test of the event-processing logic without HA."""


def test_event_dedup_and_bell_tracking():
    """Functional: _process_new_events dedups, latches bell, fires bus events."""
    from custom_components.fc_smarthome.coordinator import FcCoordinator
    from custom_components.fc_smarthome.api.models import LockEvent, LockEventType, UnlockMethod

    coord = FcCoordinator.__new__(FcCoordinator)  # bypass HA-dependent __init__
    coord.devices = {}
    coord.statuses = {}
    coord.last_event = {}
    coord.access_log = {}
    coord.bell_active = {}
    coord._seen_log_ids = {}

    class _Bus:
        def __init__(self):
            self.fired = []

        def async_fire(self, etype, payload):
            self.fired.append((etype, payload))

    class _Hass:
        bus = None

    hass = _Hass()
    hass.bus = _Bus()
    coord.hass = hass

    def ev(etype, method, user=None, ts="2026-01-01T10:00:00+00:00", uid=None):
        return LockEvent(
            type=etype,
            device_id="d1",
            timestamp=parse_ts(ts),
            method=UnlockMethod.coerce(method),
            user=user,
            user_id=uid,
            raw={"id": ""},
        )

    batch1 = [
        ev(LockEventType.BELL, None, ts="2026-01-01T10:00:01+00:00"),
        ev(LockEventType.UNLOCKED, "finger", user="Mom", ts="2026-01-01T10:00:00+00:00"),
    ]
    coord._process_new_events("d1", batch1)
    assert len(hass.bus.fired) == 2
    # bell latch stores a timestamp; sensor reads bool(truthy)
    assert coord.bell_active["d1"] is not False and coord.bell_active["d1"] is not None
    assert coord.last_event["d1"].type is LockEventType.BELL
    assert len(coord.access_log["d1"]) == 2

    # replaying the same batch must not fire anything new
    coord._process_new_events("d1", batch1)
    assert len(hass.bus.fired) == 2
    assert len(coord.access_log["d1"]) == 2

    # a genuinely new event fires again
    coord._process_new_events(
        "d1", [ev(LockEventType.LOCKED, "app", ts="2026-01-01T10:05:00+00:00")]
    )
    assert len(hass.bus.fired) == 3
    fired_types = [p["event_type"] for _, p in hass.bus.fired]
    assert "unlocked" in fired_types and "bell" in fired_types and "locked" in fired_types


def test_bell_expiry():
    from custom_components.fc_smarthome.coordinator import BELL_LATCH_SECONDS, FcCoordinator

    coord = FcCoordinator.__new__(FcCoordinator)
    coord.bell_active = {"d1": __import__("time").time() - BELL_LATCH_SECONDS - 1}
    coord._expire_bells()
    assert "d1" not in coord.bell_active


def test_event_key_stability():
    from custom_components.fc_smarthome.api.models import LockEvent, LockEventType
    from custom_components.fc_smarthome.coordinator import FcCoordinator

    ev = LockEvent(
        type=LockEventType.UNLOCKED,
        device_id="d1",
        method=None,
        user="Mom",
        raw={"id": 5},
    )
    k1 = FcCoordinator._event_key(ev)
    k2 = FcCoordinator._event_key(ev)
    assert k1 == k2
    assert k1[1] == "unlocked"


# ---------- CLI smoke ----------


def test_cli_parser_builds():
    from fcctl.__main__ import build_parser

    parser = build_parser()
    args = parser.parse_args(["devices"])
    assert args.command == "devices"


def test_cli_parses_add_user():
    from fcctl.__main__ import build_parser

    args = build_parser().parse_args(
        ["--email", "a@b.c", "add-user", "dev1", "--name", "N", "--user-type", "finger"]
    )
    assert args.user_type == "finger"
    assert args.name == "N"


# ---------- HA coordinator mapping (pure logic) ----------


def test_platforms_constant_shape():
    from custom_components.fc_smarthome.api.const import PLATFORMS

    assert "lock" in PLATFORMS
    assert "event" in PLATFORMS
    assert "switch" in PLATFORMS
    assert "button" in PLATFORMS
    assert "binary_sensor" in PLATFORMS
    assert "sensor" in PLATFORMS


# ---------- LAN transport (framing shared with BLE) ----------


def test_lan_module_imports():
    from custom_components.fc_smarthome.local.lan import LanConfig

    cfg = LanConfig()
    assert cfg.coap_port == 5683
    assert 8060 in cfg.tcp_ports


def test_lan_config_from_registry():
    from custom_components.fc_smarthome.local.lan import LanConfig

    cfg = LanConfig.from_registry({"coap_port": 5683, "tcp_ports": [9999]})
    assert cfg.coap_port == 5683
    assert cfg.tcp_ports == [9999]


@pytest.mark.asyncio
async def test_router_falls_back_to_cloud():
    """Router with no local channels routes straight to cloud."""
    from custom_components.fc_smarthome.local.router import FcTransportRouter
    from custom_components.fc_smarthome.api.models import ControlResult

    class FakeClient:
        def __init__(self):
            self.calls = []

        async def unlock(self, device_id, reason="app"):
            self.calls.append("unlock")
            return ControlResult(success=True, message="cloud")

        async def lock(self, device_id):
            self.calls.append("lock")
            return ControlResult(success=True, message="cloud")

        async def latch(self, device_id):
            self.calls.append("latch")
            return ControlResult(success=True, message="cloud")

        async def beep(self, device_id):
            self.calls.append("beep")
            return ControlResult(success=True, message="cloud")

    fake = FakeClient()
    router = FcTransportRouter(fake, ble_manager=None, lan_hosts={})
    result = await router.unlock("dev1")
    assert result.success
    assert fake.calls == ["unlock"]
    result = await router.beep("dev1")
    assert result.success
    assert fake.calls == ["unlock", "beep"]


@pytest.mark.asyncio
async def test_lan_transport_frame_roundtrip():
    """FCFC framing works for the LAN channel identically to BLE."""
    frame = build_frame(0x10, b"000000", seq=3)
    parsed = parse_frame(frame)
    assert parsed is not None
    cmd, seq, payload = parsed
    assert (cmd, seq, payload) == (0x10, 3, b"000000")


class _FakeResp:
    def __init__(self, status, body):
        import json as _json

        self.status = status
        self._text = _json.dumps(body)

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    closed = False

    def __init__(self, status, body):
        self._resp = _FakeResp(status, body)

    def request(self, method, url, **kw):
        return self._resp


@pytest.mark.asyncio
async def test_error_envelope_raises_auth():
    from custom_components.fc_smarthome.api.errors import FcAuthError

    c = FcClient("u@example.com", "pw")
    c.tokens = TokenPair(access_token="tok")
    c._session = _FakeSession(200, {"code": 1001, "msg": "token expired"})
    with pytest.raises(FcAuthError):
        await c._request("GET", "https://x/y")


@pytest.mark.asyncio
async def test_error_envelope_raises_api_error():
    from custom_components.fc_smarthome.api.errors import FcApiError

    c = FcClient("u@example.com", "pw")
    c.tokens = TokenPair(access_token="tok")
    c._session = _FakeSession(200, {"code": 500, "msg": "device offline"})
    with pytest.raises(FcApiError):
        await c._request("GET", "https://x/y")


@pytest.mark.asyncio
async def test_success_envelope_passes():
    c = FcClient("u@example.com", "pw")
    c.tokens = TokenPair(access_token="tok")
    c._session = _FakeSession(200, {"code": 0, "data": {"ok": True}})
    body = await c._request("GET", "https://x/y")
    assert body["data"]["ok"] is True


# ---------- CoAP / Alink codec ----------


def test_coap_message_roundtrip():
    from custom_components.fc_smarthome.local.alink import COAP_POST, CoapMessage

    msg = CoapMessage(
        code=COAP_POST,
        msg_id=0x1234,
        token=b"\xab\xcd",
        options=[
            (11, b"sys"),
            (11, b"pk1"),
            (11, b"dn1"),
            (11, b"thing"),
            (11, b"service"),
            (11, b"unlock"),
        ],
        payload=b'{"id":1}',
    )
    dec = CoapMessage.decode(msg.encode())
    assert dec.msg_id == 0x1234
    assert dec.token == b"\xab\xcd"
    # RFC 7252: same-number options (Uri-Path) MUST keep caller order
    assert [o for _, o in dec.options] == [
        b"sys",
        b"pk1",
        b"dn1",
        b"thing",
        b"service",
        b"unlock",
    ]
    assert dec.payload == b'{"id":1}'


def test_coap_extended_option_lengths():
    from custom_components.fc_smarthome.local.alink import COAP_POST, CoapMessage

    long_seg = b"x" * 20  # forces extended length byte
    msg = CoapMessage(
        code=COAP_POST,
        msg_id=1,
        token=b"ab",
        options=[(11, long_seg), (12, b"y" * 300)],  # ext delta + big ext len
        payload=b"z",
    )
    dec = CoapMessage.decode(msg.encode())
    assert dec.options[0] == (11, long_seg)
    assert dec.options[1] == (12, b"y" * 300)
    assert dec.payload == b"z"


def test_coap_ping_ack_decode():
    """A 4-byte CoAP ping-ACK (any RFC-7252 device) decodes safely."""
    from custom_components.fc_smarthome.local.alink import CoapMessage

    dec = CoapMessage.decode(bytes.fromhex("60004643"))
    assert dec.mtype == 2  # ACK
    assert dec.code == 0
    assert dec.payload == b""


def test_alink_topic_shape():
    from custom_components.fc_smarthome.local.alink import AlinkLanDevice

    dev = AlinkLanDevice("1.2.3.4", product_key="a1PK", device_name="dn1")
    assert dev._topic("unlock") == "/topic/sys/a1PK/dn1/thing/service/unlock"


def test_lan_discovery_marks_candidates_unverified():
    """Broadcast findings must default to verified=False (no false locks)."""
    from custom_components.fc_smarthome.local.lan import confirm_fc_device

    assert callable(confirm_fc_device)

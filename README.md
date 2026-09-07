# FC SmartHome HACS

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-red.svg)](https://github.com/hacs/integration)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Reverse-engineered Home Assistant integration + CLI for FC SmartHome locks**
(Shenzhen Fingerchip / Fingercrystal — the vendor behind *FC SmartHome*,
*Yi-Lock*, *eApartment* and *K3* gun safes on Google Play).

One CLI. One integration. Cloud + local Bluetooth. Full lock feature set.

## Why

The FC SmartHome app is the *only* official way to control these locks — there
is no public API, no IFTTT, no HomeKit, no Matter. This project replaces the
app for everything you'd want from a home-automation hub:

| Feature | Cloud | Local BLE | HA entity / service |
|---|---|---|---|
| Lock / unlock | ✅ | ✅ | `lock.*` |
| Open latch (hold-open) | ✅ | ✅ | `lock.open` |
| Door state (open/closed) | ✅ | ✅ | `binary_sensor.*_door` |
| Tamper alarm | ✅ | ✅ | `binary_sensor.*_tamper` |
| Door-left-open alarm | ✅ | | `binary_sensor.*_door_open_long` |
| Battery level | ✅ | ✅ | `sensor.*_battery` |
| Signal strength | ✅ | | `sensor.*_signal` |
| Who unlocked, how | ✅ | ✅ | `sensor.*_last_event` + `event.*` |
| Access history | ✅ | | `fc_smarthome.fetch_history` |
| Ring doorbell | ✅ | ✅ | `button.*_ring_bell` |
| Beep / locate safe | ✅ | ✅ | `button.*_beep` |
| Child lock mode | ✅ | | `switch.*_child_lock` |
| List users (finger/pass/card/NFC) | ✅ | | `fcctl users` |
| Add user (passcode, card id) | ✅ | | `fc_smarthome.add_user` |
| Delete user | ✅ | | `fc_smarthome.delete_user` |
| Rename user | ✅ | | `fc_smarthome.rename_user` |
| Fingerprint enrollment | ✅ | | `fc_smarthome.enroll_fingerprint` |
| Real-time push events | history-delta | ✅ push | `event.*` entity + `fc_smarthome_event` bus event |
| **Local LAN control** (WiFi locks/gateways) | | ✅ CoAP+TCP | automatic, local-first |

> **Status: endpoints extracted from the real APK.** The production server
> (`www.fcsmartlock.com:443`), channels (test/test2/AWS-intl), image base URL
> and the vendor's web crypto (AES-ECB key, `token:` header, `{"result":1}`
> envelope, HTTP 672 rate-limit) were all extracted from FC SmartHome APK
> 4.6.6 (resources.arsc + vendor web bundle) — the app is SecNeo-packed, so
> the exact REST paths are confirmed live but their per-call shapes still
> benefit from a quick capture (tools/HARVEST.md). JSON overrides remain
> supported for drift, plus `fcctl discover` runtime self-configuration.

## Install

### Home Assistant (HACS custom)

1. HACS → ⋮ (top right) → *Custom repositories*, add
   `https://github.com/JuanMabs22/fc-smart-home-hacs` as **Integration**.
2. Install *FC SmartHome*, restart HA.
3. Settings → Devices & Services → **+ Add Integration** → **FC SmartHome**.
4. Enter your FC SmartHome app email/password (region `us`/`eu`/`cn`/`ru`).
   Optionally point to an endpoints-override JSON (see HARVEST).

Manual: copy `custom_components/fc_smarthome` into `/config/custom_components/`.

### CLI

```powershell
git clone https://github.com/JuanMabs22/fc-smart-home-hacs
cd fc-smart-home-hacs
pip install -e .          # installs the `fcctl` command
# or run without installing:
python -m fcctl --help
```

`fcctl` reads `FC_EMAIL` / `FC_PASSWORD` env vars, or `--email` (prompts for
password), and caches tokens in `~/.fcsmarthome/tokens.json` (chmod 600).

## CLI cookbook

```powershell
fcctl login                          # store tokens
fcctl devices                        # list devices + battery
fcctl status <device-id>             # full devStatus decode
fcctl history <device-id> --limit 50 # who opened what, when, how
fcctl users <device-id>              # fingerprints, passcodes, cards, NFC
fcctl unlock <device-id>             # remote unlock (cloud)
fcctl lock <device-id>
fcctl latch <device-id>              # hold latch open
fcctl bell <device-id>               # ring doorbell
fcctl beep <device-id>               # locate a safe
fcctl child-lock <device-id> on|off
fcctl add-user <id> --name "Cleaner" --user-type password --password-value 8462
fcctl del-user <id> 12
fcctl rename-user <id> 12 --name "New name"
fcctl enroll-fingerprint <id> --name "Index"   # touch sensor on lock
fcctl watch                          # live event feed (poll deltas)
fcctl ble-scan                       # find locks over Bluetooth
fcctl ble-status AA:BB:CC:DD:EE:FF   # local status read
fcctl ble-unlock AA:BB:CC:DD:EE:FF   # local unlock, works offline
fcctl lan-discover                   # find FC devices on your network (mDNS+UDP)
fcctl lan-ports 192.168.x.x          # find the TCP command port of a gateway
fcctl lan-unlock 192.168.x.x         # local unlock over WiFi/LAN
fcctl probe                          # which cloud hosts are alive
```

Every command takes `--region us|eu|cn|ru`, `--endpoints-file <json>`,
`--json` for raw output, `--debug` for wire-level logs.

## Home Assistant

Entities created per lock (example device *Front Door*):

```
lock.front_door
sensor.front_door_battery
sensor.front_door_signal
sensor.front_door_last_event     # "Dad (finger)" + full access log attributes
binary_sensor.front_door_door
binary_sensor.front_door_tamper
binary_sensor.front_door_door_open_long
binary_sensor.front_door_motor_error
binary_sensor.front_door_low_battery
binary_sensor.front_door_bell_ringing   # doorbell models: ON while ringing
switch.front_door_child_lock
button.front_door_ring_bell
button.front_door_locate
button.front_door_sync_now
event.front_door_events          # trigger-capable event entity
```

Every access is recorded three ways:

1. **`event.front_door_events`** — fires a HA trigger per event (use with
   `platform: event`); attributes hold the last 50 events.
2. **`sensor.front_door_last_event`** — state changes land in HA **history +
   logbook**, giving a permanent "who/how/when" timeline; `access_log`
   attribute keeps the last 200 entries.
3. **Bus event `fc_smarthome_event`** — for blueprint/legacy automations.

### Who-unlocked automation (trigger-based)

```yaml
automation:
  - alias: "Front door opened by someone"
    trigger:
      - platform: event
        event_type: fc_smarthome_event
        event_data:
          device_id: "<your-device-id>"
          event_type: unlocked
    action:
      - service: notify.mobile_app
        data:
          message: >
            {{ trigger.event.data.user or 'Someone' }} opened
            {{ trigger.event.data.device_name }} via {{ trigger.event.data.method }}
            at {{ trigger.event.data.timestamp }}.
```

### Event-entity triggers (HA ≥ 2022.12)

```yaml
trigger:
  - platform: event
    event_type: event
    event_data:
      device_id: "..."
      event_type: tamper
```

### Services (Developer Tools → Actions)

```yaml
# add a temporary passcode
action: fc_smarthome.add_user
data:
  device_id: "<device-id>"
  name: "Guest"
  user_type: password
  password: "8462"

# remove it again
action: fc_smarthome.delete_user
data:
  device_id: "<device-id>"
  user_id: "15"

# rename a fingerprint slot
action: fc_smarthome.rename_user
data:
  device_id: "<device-id>"
  user_id: "3"
  name: "Index finger"

# enroll new fingerprint (touch sensor on lock several times)
action: fc_smarthome.enroll_fingerprint
data:
  device_id: "<device-id>"
  name: "Mom"

# ring the doorbell / find the safe
action: fc_smarthome.ring_bell
data: { device_id: "<device-id>" }

action: fc_smarthome.locate_device
data: { device_id: "<device-id>" }

# child lock (disables manual unlock from inside)
action: fc_smarthome.set_child_lock
data: { device_id: "<device-id>", enabled: true }

# pull 100 history entries into the log
action: fc_smarthome.fetch_history
data: { device_id: "<device-id>" }
```

### Options

Options → *FC SmartHome*:

- **Poll interval** (default 30s, min 15s) — cloud resync cadence.
- **Local LAN** (default on) — discover and control WiFi locks/gateways on
  your network directly (CoAP UDP 5683 + TCP command channel, FCFC framing).
  Local-first: LAN → BLE → cloud, verified live on a real network.
- **Local BLE** — enable Bluetooth control (needs `bleak`; the HA host must
  have a BT adapter or the `bluetooth` integration).

## Verification status

| Layer | State |
|---|---|
| Production host `www.fcsmartlock.com:443` | **extracted from APK**, live-confirmed (Spring Boot behind nginx) |
| Channels: test/test2/AWS `18.219.242.80`/SaaS `iot.qspms.cn` | **extracted from APK** |
| Image base `http://www.fcsmartlock.com:8060/images/` | **extracted from APK** |
| Auth: `token:` header, AES-ECB key, `{"result":1}` envelope, HTTP 672 | **extracted from vendor web bundle** (fingercrystal.com/js) |
| App platform | Alibaba IoT stack: OpenAccount SDK, LinkVisual, SecurityGuard, React Native |
| REST subpaths under `/api/` | live backend currently 502; candidates shipped + `fcctl discover` probes |
| BLE framing/UUIDs | auto-negotiated at connect (scan → learn services → pair) |

The app ships SecNeo-packed with 4 encrypted DEXes inside `assets/0OO00l111l1l`;
native libs (libsgmain/liblinkvisual/libIVIEWS) confirmed the Alibaba stack.
Because the app needs no config file, neither does this library: correct hosts
are compiled in as defaults, `fcctl discover` verifies them at runtime, and any
override JSON is optional.

Everything ships with the override system precisely so a first mitmproxy
session makes it *fully real* without a code change. Contributions of captured
endpoints/bitmask diffs are the most valuable PRs possible.

## Development

```bash
pip install -e .[dev]
pytest tests/ -q
```

Project layout (single source of truth for CLI and HA):

```
custom_components/fc_smarthome/
  api/            # the protocol library (no HA imports)
    client.py     # FcClient: auth, retries, devices, locks, users, history
    endpoints.py  # registry + JSON overrides + probing support
    models.py     # Device, LockStatus, LockUser, LockEvent, TokenPair
    const.py      # bitmasks, type maps (shared with CLI)
    errors.py
  local/ble.py    # BLE transport: scan, pair, unlock, status, notifications
  coordinator.py  # DataUpdateCoordinator + event firing
  config_flow.py  # UI setup + options
  lock.py sensor.py binary_sensor.py button.py switch.py event.py
fcctl/__main__.py # the CLI (imports api/)
tools/
  HARVEST.md      # capture guide: mitmproxy + HCI snoop
  probe_endpoints.py
tests/test_api.py
```

### Design rules

1. **No duplicated protocol logic** — CLI is a thin argparse shell over `api/`.
2. **Everything overridable** — hosts/paths/UUIDs/bitmasks never hardcoded in
   business logic.
3. **Event-first, polling fallback** — history deltas + BLE push fire HA
   events immediately; the poll loop only resyncs.
4. **Fail-soft** — one device failing status/history never breaks the whole
   coordinator cycle.

## FAQ

**Remote unlock doesn't work.** Many Fingerchip locks require the cloud bridge
(gateway) or the app connected via BLE relays; if `fcctl unlock` errors, your
model may be BLE-only — use `fcctl ble-unlock`. Also run `fcctl probe` to
confirm endpoints.

**Is my data safe?** Credentials stay in your HA config entry (or local token
file for the CLI). No third-party servers involved; the integration talks only
to the FC cloud you configure.

**Legal?** Interoperability reverse engineering for personal use of your own
hardware. Not affiliated with Shenzhen Fingerchip Intelligent Technology Co.
Ltd. Use the app captures only on your own devices/accounts.

## License

MIT — see [LICENSE](LICENSE).

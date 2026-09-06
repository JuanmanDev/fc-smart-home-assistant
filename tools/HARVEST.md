# HARVEST: confirming the real endpoints

This integration ships with **hypothesis defaults** for the FC SmartHome
(Fingerchip / Fingercrystal) cloud: the app has no public API docs, so every
host/path/bitmask here must be confirmed against the official app. This guide
is the exact procedure. Once done, no code changes are needed — write a JSON
override file and point the integration/CLI at it.

## Step 1 — Capture the app traffic (HTTPS)

```powershell
pip install mitmproxy
mitmproxy --listen-port 8080
```

On the phone: Settings → Wi-Fi → your network → proxy → manual →
`<PC-IP>:8080`, then visit `http://mitm.it` on the phone and install the CA
(Android 7+ additionally needs the CA in the system store, or use an emulator
with a writable system image, or a rooted device with Magisk module
"MoveCertificate").

Login in the FC SmartHome app, list devices, open the lock page, tap unlock,
open history. Save the flows (`mitmdump -w fc.flows` or export HAR from the
UI) and note, for each request:

- exact host (e.g. `api.xxx.fingercrystal.com`)
- path + method for: login, refresh, device list, device status, unlock,
  lock, users list, add/remove user, fingerprint enroll, history, bell
- the auth header format (Bearer? custom `token:` header? sign?)
- the JSON field names (we already accept many aliases, but add yours in
  `endpoints.py` if different)
- the `devStatus` bitmask values: lock the door, unlock by finger, unlock by
  password, card, leave door open, tamper — record the integer each time and
  XOR-diff to learn the bits; update `DEVICE_STATUS_MASKS` in
  `custom_components/fc_smarthome/api/const.py`

## Step 2 — Write the override file

Create `fc_smarthome_endpoints.json` next to your HA config (or anywhere):

```json
{
  "regions": { "us": "https://api-realhost.example" },
  "paths": {
    "login": "/real/login/path",
    "devices": "/real/device/list",
    "unlock": "/real/device/{id}/unlock"
  },
  "websocket": { "enabled": true, "path": "/real/ws" }
}
```

Only the keys you want to override are needed; everything else keeps the
default. Then either:

- HA: add the file path in the integration config flow ("endpoints file"), or
- CLI: `fcctl --endpoints-file fc_smarthome_endpoints.json devices`

## Step 3 — Capture the BLE traffic (local control)

1. Enable Bluetooth HCI snoop on the phone (Developer options → Bluetooth HCI
   snoop log), pair the lock in the app, do: connect, unlock, lock, beep,
   fingerprint enrollment.
2. Pull the btsnoop file (`adb bugreport`), open in Wireshark.
3. Note: the GATT service/characteristic UUIDs, the framing of writes
   (magic bytes? length? checksum? rolling counter?), the unlock command
   payload, how the app authenticates (pair code? derived key?).
4. Update `custom_components/fc_smarthome/local/ble.py`: `CMD_*` ids, frame
   layout in `build_frame`/`parse_frame`, and the UUIDs in
   `endpoints.py:DEFAULT_BLE`.

## Step 4 — Verify

```bash
fcctl probe                      # which hosts are alive
fcctl login
fcctl devices
fcctl history <device-id>
fcctl ble-scan
```

Anything that fails with `FcApiError 404` means the path is still a hypothesis
— fix it in the JSON, not in code.

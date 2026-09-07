# HARVEST: confirming the real endpoints

Everything below reflects the **actual state** after static APK analysis
(v4.6.6, SecNeo-packed) and live probing. Two capture paths remain; both
take under an hour on your own hardware and make the integration fully
operational without guesswork.

## What is already confirmed (no capture needed)

Extracted from `resources.arsc` (string table) of the real APK:

```
fingercrystal_server        = www.fcsmartlock.com    (production)
fingercrystal_gatewayPort   = 443
fingercrystal_appSystemPort = 443
fingercrystal119_server     = test.fcsmartlock.com
fingercrystaltest2_server   = test2.fcsmartlock.com
fingercrystal_amazon_server = 18.219.242.80          (AWS channel)
fingercrystal_image_base_url = http://www.fcsmartlock.com:8060/images/
test_server                 = iot.qspms.cn (SaaS PMS)
```

Extracted from the vendor's own web bundle (fingercrystal.com/js/app-*.js):

- auth header: `token: <hex>` (not `Authorization: Bearer`)
- response envelope: `{"result":1,"data":…,"message":…}` (1 = success)
- AES-128-ECB PKCS7, key `687bbcd7f666afbcc1c44e6c9e86987c`[:16]
- custom HTTP statuses: 672 (rate limit, "retry in 3 min"), 692 (signature gate)

Live-verified against the real servers:

- `www.fcsmartlock.com` = Spring Boot behind nginx; `/api/*` exists but
  upstream returns **502** (backend down at probe time — retest!)
- `iot.qspms.cn/api/*` = **live**, answers **692** with empty body to
  unsigned requests → the mobile API is behind a request-signature gate
  (Alibaba SecurityGuard signs each request with the app's secret).
- **TLS**: the cloud requires TLS1.2 + legacy renegotiation + `AES128-SHA`.
  Python/aiohttp defaults fail with `SSLV3_ALERT_HANDSHAKE_FAILURE`
  (this is why the app ships Alibaba's custom `libitls`). The client in
  this repo already ships a matching connector.

## Path A — mitmproxy capture of the app (30–60 min)

This is now the *only* way to get: the exact REST subpaths, the request
signing scheme (header names + algorithm), and the real login payload.

1. `pip install mitmproxy; mitmproxy --listen-port 8080`
2. Phone Wi-Fi proxy → `<PC-IP>:8080`, install CA from `http://mitm.it`
   (Android 7+ needs the CA in the system store — use an emulator with
   writable system image, or Magisk "MoveCertificate" on a rooted device).
3. In the FC SmartHome app: login, list devices, open the lock page, tap
   unlock, open history, add a password, enroll a fingerprint.
4. Note for each request: exact path, headers (esp. any `sign`/`nonce`/
   `timestamp`), body shape, and the `devStatus` bitmask integers while
   you lock/unlock/tamper (record 3-4 values and XOR-diff to learn bits).
5. Write the findings into `fc_smarthome_endpoints.json` (only the keys
   that differ from the defaults) and set the file path in the HA options
   — no code changes required.

## Path B — BLE HCI capture (for the local channel)

1. Developer options → enable "Bluetooth HCI snoop log".
2. In the app: connect to lock, unlock, lock, beep, enroll fingerprint.
3. `adb bugreport`, open the btsnoop in Wireshark.
4. Update `local/ble.py`: GATT UUIDs, `CMD_*` ids, frame layout
   (`build_frame`/`parse_frame`), and how the app authenticates
   (pair code? derived key from account?).

## Path C — LAN/Alink capture (WiFi locks & gateways)

WiFi locks pair to a gateway. In the app, "连接閘道" (connect gateway)
configures the lock's WiFi; the gateway then talks CoAP on UDP 5683.
The capture from Path A also reveals the Alink topic URIs
(`/sys/{productKey}/{deviceName}/thing/...`) with your device's real
pk/dn. Then:

```
fcctl lan-register 192.168.x.x --product-key a1XXXX --device-name YYYY
fcctl alink-call 192.168.x.x --product-key a1XXXX --device-name YYYY \
  --method thing.deviceInfo.get
```

The CoAP stack in this repo (RFC 7252 codec + Alink RPC client in
`local/alink.py`) is complete and unit-tested; only the pk/dn and the
service names (`thing.service.unlock` etc.) need confirming.

> Pitfall we already hit so you don't have to: any RFC-7252 device will
> ping-ACK a 4-byte UDP "FCFC" probe (your "FC" bytes are read as a
> CoAP message-id). LAN discovery in this repo therefore only marks
> devices verified when they answer a real Alink JSON RPC.

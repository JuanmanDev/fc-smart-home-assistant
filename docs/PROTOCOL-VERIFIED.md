# FC SmartHome Cloud Protocol — Verified & Implemented (2026-09-09)

Everything below was verified **live** against `www.fcsmartlock.com` by
decrypting a mitmproxy capture of the official Android app (v4.6.6) plus a
root memory dump of the running app (RSA private key extraction).

Implementation: `custom_components/fc_smarthome/api/crypto.py` + `api/client.py`.

## Wire format (all POST, host `https://www.fcsmartlock.com`)

- Bodies are **AES-128-ECB/PKCS7, hex-encoded strings** (the JSON envelope is
  itself a JSON-quoted hex string in the HTTP response).
- The AES key is **negotiated per session** — there is no static key.

## 1. Session key negotiation — `POST /v2/secure/getSecurityKey`

- Content-Type: `application/x-www-form-urlencoded`
- Body: `secureData=<urlencoded base64>` — a 128-byte RSA-1024 blob tied to the
  app install (persistent; captured once from the app). The server accepts
  replays of the same blob.
- Headers: `token` (empty), `appid`, `phoneId`, `addition` (constant signature
  blob), `version=4.6.6`, `platform=Android`, `timezone`, `User-Agent: okhttp/3.12.8`.
- Response: `{"result":1,"data":"<base64 RSA-1024 block>"}`
  The block is `RSA(negotiated_key_hex, app_public_key)` with PKCS#1 v1.5
  padding. Decrypt with the app's **persistent RSA private key** (extracted
  from the app's memory dump; stored in `.secrets/fc_app_privkey.b64`).
- Payload inside: a 32-char lowercase hex string → **session AES key = first 16
  chars as ASCII**.

## 2. Login — `POST /v2/login/loginPassword`

- Headers: same + `ts` = `AES(session_key, "<ms timestamp>")` + `Cookie: SESSION=<b64 uuid>`
- Body: `AES(session_key, json)` where:
  ```json
  {
    "password": "<md5(password)>",
    "phoneModel": "2201123G", "phoneBrand": "Xiaomi",
    "phone": "<phone>", "countrycode": 34,
    "channel": "Google", "systemVersion": "17",
    "timestamp": <ms>
  }
  ```
- Response: `AES(session_key, json)` with `data.token` (192-hex), `data.sessionId`,
  `data.id` (user id). `data.familyId` is NOT here — use familyList.
- Email login (`loginEmailPassword`) returns `result 607` for this account;
  the vendor flow is phone-based.

## 3. Token renewal — `POST /v2/login/loginToken`

Same handshake first, then body:
```json
{"phoneModel":"2201123G","phoneBrand":"Xiaomi","channel":"Google",
 "systemVersion":"17","token":"<old token>","timestamp":<ms>}
```

## 4. All API calls (negotiated key for BOTH ts header and body)

| Key | Path | Body (inside AES) |
|---|---|---|
| devices | `/v2/device/getDeviceList` | `{familyId, token, timestamp}` |
| device_detail | `/v2/device/getDevice` | `{id, token, timestamp}` |
| family_list | `/iot/family/familyList` | `{token, timestamp}` |
| users | `/v2/lock/getLockUserList/v2` | `{userType:"1|2|3", deviceId, token, timestamp}` |
| logs | `/v2/lock/getLockMessageList/v2` | `{fromTime, deviceId, uuid, token, timestamp}` |
| unlock | `/v2/lock/openLock` | `{id, token, timestamp}` |

- `familyId` comes from `familyList` (`data[0].id`).
- `fromTime: 0` returns the full history (~1 year).

## Envelope & errors

- `{"result": 1, ...}` success; `result 1001`/401/token message → re-login.
- HTTP **690** = token expired → re-login. **672** = rate limit (~3 min).
  400 = body/crypto format error (wrong key). Error bodies are encrypted too.

## Device payload (verified fields, from getDeviceList)

`deviceuuid`, `name`, `battery`, `lockState` (0=unlocked/1=locked),
`doorState` (bool), `alarmLockNotClosed`, `messagetime` (ms),
`bluetoothKey` (BLE AES key), `dynamicKey`, `mac`, `macType`,
`firmwareversion`, `deviceCategory.model` ("L5-WIFI-QINGKE"),
`deviceCategory.productModel` ("SMART_LOCK").

## History messageKey map (verified from 380 real events)

| messageKey | Event |
|---|---|
| `lock.message.local.open` | unlock (userName = credential owner) |
| `lock.message.Bluetoothd.open.success` | unlock via BLE |
| `lock.message.remote.open.success` | remote unlock |
| `lock.message.lock.bell` | **doorbell ring** |
| `lock.message.battery.change` | battery update (message text has %) |
| `lock.message.lower.battery` | low battery warning |
| `lock.message.illegaloperation.alarm` | tamper alarm |
| `lock.message.adduser` / `deleteuser` / `changeusername` | user management |

## Protocol secrets required by the integration

Two artifacts (from the official app; stored in `.secrets/`, gitignored, or as
env vars):

- `fc_secure_data.json` → `{"secure_data": "secureData=<urlencoded b64>"}`
  (env: `FC_SECURE_DATA`)
- `fc_app_privkey.b64` — the app's persistent RSA-1024 PKCS#8 private key
  (env: `FC_PRIVATE_KEY_B64`)

## How they were captured (reproducible)

1. Rooted phone, `su -c 'dd if=/proc/<pid>/mem ...'` on the dalvik main space
   while the app logs in.
2. Heap contains: `MIIC...` (PKCS#8 RSA private key), the `500319f9...`-style
   negotiated keys, plaintext URLs, and the getSecurityKey HTTP response.
3. mitmproxy capture gives the `secureData` blob (replayable indefinitely).
4. The private key is **persistent across sessions** (verified: it decrypts
   yesterday's captured handshake).

## TLS quirk (unchanged)

`www.fcsmartlock.com` requires TLS1.2 + legacy renegotiation + `AES128-SHA`;
the client ships a matching connector (`client.py:_make_connector`).

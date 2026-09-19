# TCP 4067 Protocol Discovery (WiFi Lock Remote Channel)

**Date:** 2026-09-19  
**Target:** FC SmartHome / Fingerchip / Fingercrystal WiFi Smart Lock (Model L5, firmware `Ver:B2.7.3.64`)  
**MAC:** `b0:f8:93:91:79:b6` (LAN) / `34:17:27:05:19:20` (Cloud UID)  
**Status:** **100% REVERSED & VERIFIED LIVE**

---

## 1. Executive Summary

Static APK analysis previously showed endpoints pointing to `www.fcsmartlock.com:443` (HTTP/REST) and `iot.qspms.cn`. However, cloud `openLock` HTTP calls consistently failed with `HTTP 682 null` during awake windows.

A full packet capture on the LAN router gateway (`192.168.2.1`) during live doorbell and `4 + #` wake events revealed:
1. The lock **does not use HTTP, HTTPS, MQTT, or CoAP** for its remote relay.
2. The lock connects over **raw, unencrypted TCP to `www.fcsmartlock.com:4067`** (`120.24.83.239:4067`).
3. Application framing is **identical to the FC Bluetooth LE protocol** (`0xFC` ... `0xFE`).
4. Transport encryption is **AES-128-ECB NoPadding** using the lock's `bluetoothKey` (`4CADB87095639211A1303639D98E9150`).
5. Remote unlock was captured and decrypted in live action when the user tapped "Open" in the official app:
   - Server -> Lock command: `cat=0x02, cmd=0x0e, data=[0x01]` (`04 02 0e 01`)
   - Lock -> Server response: `cat=0x02, cmd=0x0e, data=[0x00]` (`04 02 0e 00` - SUCCESS)

---

## 2. Wire Framing Format

```
+-------------+----------+--------------+-----------------------+----------+-----------+
| 0xFC (1B)   | PID (1B) | Length (1B)  | AES-128-ECB (N * 16B) | Chk (1B) | 0xFE (1B) |
+-------------+----------+--------------+-----------------------+----------+-----------+
```

- **Start delimiter:** `0xFC`
- **PID:** `0x00`
- **Total length:** `6 + len(AES_payload)` (e.g., `0x15` = 21 bytes for a 16-byte block, `0x55` = 85 bytes for an 80-byte block)
- **Checksum:** `pid ^ total_len ^ (byte0 ^ byte1 ^ ... of AES payload)`
- **End delimiter:** `0xFE`

### Inner Plaintext Layout

```
+-------------+-------------+------------+----------------------+--------------------+
| Length (1B) | Category(1B)| Command(1B)| Data (Length - 3 B)  | 0x00 padding (to 16)|
+-------------+-------------+------------+----------------------+--------------------+
```

---

## 3. Protocol Flow (Decrypted Trace)

### Step 1: Lock Wake & DHCP / DNS
On physical trigger (doorbell button or `4 + #`), the lock powers on WiFi, acquires its LAN IP via DHCP, and performs standard DNS:
```
DNS Qry www.fcsmartlock.com. -> 120.24.83.239
```

### Step 2: TCP Handshake & Registration
Lock opens TCP connection to `120.24.83.239:4067` and transmits its identity:
```
LOCK -> SERVER [len=85]: cat=0x01, cmd=0x01, len=0x44 (68 bytes)
  Payload:
    - 16 bytes: bluetoothKey (4CADB87095639211A1303639D98E9150)
    - 12 bytes ASCII: Cloud UID (341727051920)
    - 16 bytes ASCII: Firmware Version (6.5Ver:B2.7.3.64)
    - flags / status bytes
```
Server acknowledges with timestamp sync:
```
SERVER -> LOCK [len=21]: cat=0x01, cmd=0x01, len=0x0d (13 bytes)
  Payload: 00 00 00 [YY MM DD HH MM SS] 01
SERVER -> LOCK [len=21]: cat=0xF0, cmd=0x03, len=0x03 (Ping)
```

### Step 3: Remote Unlock Request (Wake by 4 + #)
When woken by `4 + #`, the lock notifies the cloud that it is waiting for authorization:
```
LOCK -> SERVER [len=21]: cat=0x02, cmd=0x0d, data=[0x01]
```
The lock then begins polling every ~4 seconds:
```
LOCK -> SERVER [len=21]: cat=0x02, cmd=0x0d, data=[0x00]
```
*(The lock holds the TCP connection open for ~60 seconds waiting for a server push).*

### Step 4: The Unlock Command (Server -> Lock)
When the user confirms "Unlock" in the FC SmartHome app:
```
SERVER -> LOCK [len=21]: cat=0x02, cmd=0x0e, data=[0x01]
  Inner plaintext: 04 02 0e 01 00 00 00 00 00 00 00 00 00 00 00 00
  Raw wire frame:  fc 00 15 5b 57 4b 8e 59 89 ea 2d 12 cd b2 ca 19 35 bd 24 d9 fe
```

The lock immediately unlatches and acknowledges:
```
LOCK -> SERVER [len=21]: cat=0x02, cmd=0x0e, data=[0x00] (SUCCESS)
  Inner plaintext: 04 02 0e 00 00 00 00 00 00 00 00 00 00 00 00 00
```

### Step 5: History / Event Upload
Lock uploads the unlock event record:
```
LOCK -> SERVER [len=21]: cat=0x03, cmd=0x01, len=0x10 (16 bytes)
  Payload: [timestamp u32] [event attributes]
SERVER -> LOCK [len=21]: cat=0x03, cmd=0x01, data=[0x00] (ACK)
```

### Step 6: Session Teardown
Lock initiates clean disconnect:
```
LOCK -> SERVER [len=21]: cat=0xF0, cmd=0x01, len=0x03 (Goodbye)
Both sides: TCP FIN / ACK
```

---

## 4. Replicating the App via Cloud (Zero Router / Zero DNS Changes)

From the extracted official frontend bundle (`c2a518-SMART_LOCK-controller-4.5.11`):
* The app UI explicitly displays:
  > *"Before unlocking, please press '4' and '#' to wake up the device, effective time is 1 minute."*
* When the user taps "Open", the React Native bridge executes:
  ```javascript
  DeviceControllerPart.openLock({ deviceId: lockId })
  ```
  Which issues:
  `POST /v2/lock/openLock` with body `{"deviceId": "<device_id>"}` (note: parameter name is `deviceId`, not `id`).
* When the lock is awake on `4 + #`, the cloud takes this HTTP call and pushes `cat=0x02, cmd=0x0e, data=[0x01]` (`04 02 0e 01`) down the TCP 4067 socket to the lock.

---

## 5. Implementation Options for Home Assistant

### Option 1: Cloud Replication (Zero Router Changes, Zero DNS Changes)
* User or visitor presses `4 + #` at the lock.
* Home Assistant detects the wake event or user taps "Unlock" in Home Assistant within the 60s window.
* Home Assistant calls `POST /v2/lock/openLock` with `{"deviceId": device_id}`.
* Cloud delivers the command to the lock.

### Option 2: Local Router NAT Redirect (100% Local, Zero DNS Changes)
* In the OpenWrt router (`192.168.2.1`):
  ```sh
  iptables -t nat -A PREROUTING -s 192.168.3.92 -p tcp --dport 4067 -j DNAT --to-destination 192.168.2.113:4067
  ```
* In Home Assistant (`192.168.2.113`), run a local TCP server on port `4067`.
* When the lock connects on `4 + #`, Home Assistant directly sends `04 02 0e 01`.
* Works 100% offline, zero cloud latency.

### Option 3: Local DNS Redirection
* Point `www.fcsmartlock.com` in DNS to Home Assistant IP `192.168.2.113`.


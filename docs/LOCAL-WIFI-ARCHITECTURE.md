# Local WiFi Architecture & Integration Options for FC Smart Locks

**Date:** 2026-09-19  
**Target Hardware:** Fingerchip / Fingercrystal WiFi Locks (L5 / MXCHIP WiFi, firmware `Ver:B2.7.3.64`)  
**Network Identity:** MAC `b0:f8:93:91:79:b6` / Cloud UID `341727051920`  

---

## 1. Overview of Hardware & Protocol Behavior

Unlike always-on IoT gadgets, battery-operated smart locks sleep aggressively to preserve battery life:
* **Deep Sleep:** The lock's WiFi chip and network stack are powered **completely off** while idle. The lock consumes microamps.
* **Wake Triggers:** The WiFi radio only powers on when an external physical event occurs:
  1. Pressing the **Doorbell button** on the lock exterior.
  2. Entering **`4 + #`** on the keypad (Remote Unlock Request mode).
  3. Fingerprint, PIN, or Card authentication.
* **Awake Window:** Upon wake, the lock requests/renews its LAN IP via DHCP, resolves `www.fcsmartlock.com`, and establishes an outbound TCP connection to **port 4067**. It holds this connection open for **~60 seconds**, polling every ~4 seconds.
* **No Inbound Listening Ports:** The lock operates strictly as a TCP client. It does not run an HTTP, SSH, CoAP, or TCP listening server on the LAN.

---

## 2. The TCP 4067 Protocol (Fully Reversed)

All remote operations ride an unencrypted TCP socket to `www.fcsmartlock.com:4067` (`120.24.83.239:4067`). Application payloads are encrypted using **AES-128-ECB NoPadding** with the lock's `bluetoothKey` (`4CADB87095639211A1303639D98E9150`).

### Frame Layout
```
+-------------+----------+--------------+-----------------------+----------+-----------+
| 0xFC (1B)   | PID (1B) | Length (1B)  | AES-128-ECB (N * 16B) | Chk (1B) | 0xFE (1B) |
+-------------+----------+--------------+-----------------------+----------+-----------+
```
* **Start:** `0xFC`
* **PID:** `0x00`
* **Length:** `0x15` (21 bytes total for standard 16-byte payload)
* **Checksum:** `pid ^ length ^ (payload bytes...)`
* **End:** `0xFE`

### Core Commands
| Category | Command | Direction | Inner Plaintext (Hex) | Purpose |
|---|---|---|---|---|
| `0x01` | `0x01` | Lock -> Cloud | `44 01 01 <key> <uid> <firmware>` | Initial registration & handshake |
| `0x01` | `0x01` | Cloud -> Lock | `0d 01 01 00 00 00 <timestamp> 01` | Time synchronization & ACK |
| `0x02` | `0x0d` | Lock -> Cloud | `04 02 0d 01` / `04 02 0d 00` | Remote unlock request / Polling keepalive |
| `0x02` | `0x0e` | Cloud -> Lock | `04 02 0e 01 00 00 00...` | **REMOTE UNLOCK COMMAND** |
| `0x02` | `0x0e` | Lock -> Cloud | `04 02 0e 00 00 00 00...` | **UNLOCK SUCCESS CONFIRMATION** |
| `0x03` | `0x01` | Lock -> Cloud | `10 03 01 <epoch> <data>` | Access / history record upload |
| `0xF0` | `0x01` | Lock -> Cloud | `03 f0 01` | Session goodbye / power down |

---

## 3. Four Architecture Options for Integration

### Architecture A: Concurrent Bluetooth + Cloud Unlock (Built-in, Zero Network Setup)
* **How it works:**
  When Home Assistant unlocks the door, it executes **both channels simultaneously**:
  - **Channel 1 (BLE):** Attempts an immediate BLE connection via any local ESP32 Bluetooth proxy. If the lock is in range, BLE wakes the lock and opens it in **~1.5 seconds**.
  - **Channel 2 (Cloud / WiFi):** At the exact same moment, the cloud unlock retry loop begins watching for the lock. If a visitor pressed `4 + #`, the lock connects to the cloud and Home Assistant triggers `POST /v2/lock/openLock {"deviceId": "<device_id>"}`.
  - Whichever channel unlatches the door first wins and cancels the other!
* **Requirements:** None. Zero router changes, zero DNS modifications.
* **Configuration:** Enabled in Home Assistant via **Settings -> Devices & Services -> FC SmartHome -> Configure -> "Try Bluetooth and WiFi/Cloud simultaneously"**.

---

### Architecture B: OpenWrt Router NAT Redirection (100% Local, Zero DNS Changes)
Because the OpenWrt router (`192.168.2.1`) is the default gateway for the lock subnet (`192.168.0.0/22`), the router sees every packet the lock sends.

* **How it works:**
  A single firewall NAT rule intercepts any outbound packet from the lock directed at port 4067 and transparently forwards it to Home Assistant (`192.168.2.113:4067`):
  ```sh
  iptables -t nat -A PREROUTING -s 192.168.3.92 -p tcp --dport 4067 -j DNAT --to-destination 192.168.2.113:4067
  ```
  *(To persist across reboots, add this line to `/etc/firewall.user` on OpenWrt).*
* **Lock Behavior:**
  The lock still resolves `www.fcsmartlock.com` normally via DNS, but the TCP connection lands on Home Assistant instead of China.
* **Advantages:**
  - **100% Local & Offline:** Works even if the internet is down.
  - **Blazing Fast:** Unlock latency is under **50 ms**.
  - **Zero DNS changes:** No DNS rewrites or Pi-hole/AdGuard overrides needed.

---

### Architecture C: Local DNS Rewriting (Alternative Local Path)
* **How it works:**
  In your local DNS server (Pi-hole, AdGuard Home, or OpenWrt `dnsmasq`):
  ```
  address=/www.fcsmartlock.com/192.168.2.113
  ```
* **Pros & Cons:**
  - Simple to configure if you already use local DNS sinkholing.
  - Note: If other devices on your LAN talk to `www.fcsmartlock.com` (e.g. the phone app logging in via HTTPS), those requests would also hit Home Assistant unless the DNS override is scoped strictly to the lock's IP / MAC.

---

### Architecture D: Router Transparent Proxy (Local Intercept + Cloud Forwarding)
* **How it works:**
  A lightweight script on the OpenWrt router intercepts TCP 4067:
  1. Forwards lock packets upstream to the real cloud server (`120.24.83.239:4067`) so the vendor mobile app continues to work identically.
  2. Listens for local unlock triggers from Home Assistant (via a local UDP or REST hook).
  3. Injects the raw 21-byte frame (`fc00155b574b8e5989ea2d12cdb2ca1935bd24d9fe`) directly into the active TCP socket while the lock is awake.

---

## 4. Local TCP 4067 Server Implementation (Reference Code)

Below is a standalone Python daemon that can run inside Home Assistant or on the LAN to act as the local lock server:

```python
"""Local FC Smart Lock TCP Server (Port 4067)."""
import asyncio
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

AES_KEY = bytes.fromhex("4CADB87095639211A1303639D98E9150")

def encrypt_frame(plaintext: bytes) -> bytes:
    pad_len = (16 - (len(plaintext) % 16)) % 16
    padded = plaintext + b"\x00" * pad_len
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor().update(padded)
    total_len = 6 + len(enc)
    chk = 0 ^ total_len
    for b in enc:
        chk ^= b
    return bytes([0xFC, 0x00, total_len]) + enc + bytes([chk, 0xFE])

def decrypt_frame(frame: bytes) -> bytes:
    if not (frame.startswith(b"\xfc") and frame.endswith(b"\xfe")):
        return b""
    enc = frame[3:-2]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(enc)

async def handle_lock(reader, writer):
    print("[TCP 4067] Lock connected!")
    while True:
        data = await reader.read(1024)
        if not data:
            break
        dec = decrypt_frame(data)
        if not dec:
            continue
        cmd_len, cat, cmd = dec[0], dec[1], dec[2]
        print(f"Lock -> Server: cat={cat:02x}, cmd={cmd:02x}")

        # Handshake registration (cat=01, cmd=01)
        if cat == 0x01 and cmd == 0x01:
            # Reply with time sync: 0d 01 01 00 00 00 [YY MM DD HH MM SS] 01
            sync = bytes([0x0D, 0x01, 0x01, 0x00, 0x00, 0x00, 0x1A, 0x09, 0x13, 0x11, 0x2E, 0x00, 0x01])
            writer.write(encrypt_frame(sync))
            await writer.drain()

        # Unlock request polling (cat=02, cmd=0d)
        elif cat == 0x02 and cmd == 0x0D:
            # To unlock immediately, send cat=02 cmd=0e data=[01]:
            unlock_cmd = bytes([0x04, 0x02, 0x0E, 0x01])
            writer.write(encrypt_frame(unlock_cmd))
            await writer.drain()
            print("[TCP 4067] Sent UNLOCK command to lock!")

async def main():
    server = await asyncio.start_server(handle_lock, "0.0.0.0", 4067)
    print("Serving FC Lock TCP server on port 4067...")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
```

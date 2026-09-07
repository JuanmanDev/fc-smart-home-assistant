"""Deeper CoAP probing: Accept option, blockwise, Alink discovery topics,
and FC-specific paths observed in the app strings."""

from __future__ import annotations

import asyncio
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.local.alink import (
    COAP_GET,
    COAP_POST,
    CoapMessage,
)
import json
import socket


async def raw_coap(ip, msg, timeout=2.5):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, msg.encode(), (ip, 5683))
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=timeout)
        reply = CoapMessage.decode(data)
        code = f"{reply.code >> 5}.{reply.code & 0x1F:02d}"
        body = reply.payload.decode("utf-8", "replace") if reply.payload else ""
        return f"{code} opts={reply.options} body={body[:250]!r}"
    except asyncio.TimeoutError:
        return "timeout"
    except ConnectionResetError:
        return "reset"
    finally:
        sock.close()


async def main():
    ips = ["192.168.3.90", "192.168.3.91"]

    print("== GET / with Accept: application/link-format (40) ==")
    for ip in ips:
        msg = CoapMessage(
            code=COAP_GET,
            msg_id=random.randint(1, 0xFFFF),
            token=bytes([1, 2]),
            options=[(6, b"")],  # Observe 0
        )
        print(f"  {ip} OBS /: {await raw_coap(ip, msg)}")
        msg = CoapMessage(
            code=COAP_GET,
            msg_id=random.randint(1, 0xFFFF),
            token=bytes([3, 4]),
            options=[(6, b""), (11, b".well-known"), (11, b"core")],
        )
        print(f"  {ip} OBS wkc: {await raw_coap(ip, msg)}")

    print("== Alink discovery/registration topic shapes ==")
    topics = [
        ["sys", "awss", "device", "list"],
        ["sys", "discover"],
        ["discover"],
        ["sys", "a1FCDEMO", "discover"],
        ["device", "discover"],
        ["sys", "productKey", "deviceName", "thing", "deviceInfo", "get"],
        ["ext", "discover"],
        ["fc", "discover"],
        ["fc", "status"],
        ["status"],
        ["dev", "status"],
        ["sys", "dev", "status"],
    ]
    body = json.dumps({"id": 1, "version": "1.0", "method": "discover", "params": {}}).encode()
    for ip in ips:
        print(f"  -- {ip} --")
        for parts in topics:
            msg = CoapMessage(
                code=COAP_POST,
                msg_id=random.randint(1, 0xFFFF),
                token=bytes([random.randint(0, 255), random.randint(0, 255)]),
                options=[(11, p.encode()) for p in parts],
                payload=body,
            )
            r = await raw_coap(ip, msg)
            if "4.04" not in r:
                print(f"  POST {'/'.join(parts)}: {r}")
            else:
                pass
        print("  (only non-4.04 shown)")

    print("== payload echo test: does any short path 2.05-echo the payload? ==")
    for ip in ips:
        for leaf in ["echo", "test", "debug", "info", "id", "who"]:
            msg = CoapMessage(
                code=COAP_POST,
                msg_id=random.randint(1, 0xFFFF),
                token=bytes([random.randint(0, 255), random.randint(0, 255)]),
                options=[(11, leaf.encode())],
                payload=b'{"id":1}',
            )
            r = await raw_coap(ip, msg)
            if "4.04" not in r:
                print(f"  {ip} POST {leaf}: {r}")


if __name__ == "__main__":
    asyncio.run(main())

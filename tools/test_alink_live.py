"""Live test: alink discovery + CoAP codec + device RPCs."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.local.alink import (
    COAP_POST,
    AlinkLanDevice,
    CoapMessage,
    alink_discover,
)


async def main() -> None:
    print("== alink JSON discovery ==")
    found = await alink_discover(timeout=3.0)
    for d in found:
        print(" ", d)

    print("== CoAP codec roundtrip ==")
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
    enc = msg.encode()
    dec = CoapMessage.decode(enc)
    assert dec.msg_id == 0x1234
    assert dec.token == b"\xab\xcd"
    assert [o for _, o in dec.options] == [
        b"sys",
        b"pk1",
        b"dn1",
        b"thing",
        b"service",
        b"unlock",
    ]
    assert dec.payload == b'{"id":1}'
    print("  codec OK:", enc.hex()[:80])

    print("== live CoAP against devices ==")
    for ip in ["192.168.3.90", "192.168.3.91"]:
        dev = AlinkLanDevice(ip, product_key="a1XXXXXXXX", device_name="dev1")
        try:
            info = await dev.get_device_info()
            print(f"  {ip} deviceInfo: {info}")
        except Exception as err:
            print(f"  {ip}: {type(err).__name__}: {str(err)[:100]}")


if __name__ == "__main__":
    asyncio.run(main())

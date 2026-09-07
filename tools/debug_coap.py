"""Debug the CoAP codec roundtrip."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.local.alink import COAP_POST, CoapMessage

msg = CoapMessage(
    code=COAP_POST,
    msg_id=0x1234,
    token=bytes([0xAB, 0xCD]),
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
print("encoded:", enc.hex())
dec = CoapMessage.decode(enc)
print("decoded options:", dec.options)
print("decoded payload:", dec.payload)
print("decoded msg_id:", hex(dec.msg_id), "token:", dec.token.hex())

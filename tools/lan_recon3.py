"""Definitive CoAP fingerprint via /.well-known/core + fixed TLS recon."""

from __future__ import annotations

import random
import socket
import ssl
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def udp_txn(host: str, port: int, frame: bytes, timeout: float = 2.0) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(frame, (host, port))
        return s.recvfrom(4096)[0]
    except socket.timeout:
        return None
    except ConnectionResetError:
        return None
    finally:
        s.close()


def coap_get(host: str, uri: str, port: int = 5683, observe: bool = False) -> bytes | None:
    """CoAP CON GET with Uri-Path options and optional Observe."""
    msg_id = random.randint(1, 0xFFFF)
    header = struct.pack("!BBH", 0x42, 0x01, msg_id)  # ver1 CON GET tkl=2
    token = bytes([random.randint(0, 255), random.randint(0, 255)])
    opts = b""
    prev_num = 0
    parts = [p for p in uri.strip("/").split("/") if p]
    if observe:
        # Observe option 6, value 0 (register)
        delta = 6 - prev_num
        opts += bytes([(delta << 4) | 0])  # length 0 -> value 0
        prev_num = 6
    for part in parts:
        pb = part.encode()
        delta = 11 - prev_num if prev_num < 11 else 0
        prev_num = 11
        if len(pb) < 13:
            opts += bytes([(delta << 4) | len(pb)]) + pb
        else:
            opts += bytes([(delta << 4) | 13]) + bytes([len(pb) - 13]) + pb
    pkt = header + token + opts
    return udp_txn(host, port, pkt)


def parse(data: bytes) -> str:
    if not data:
        return "empty"
    ver = data[0] >> 6
    typ = (data[0] >> 4) & 3
    code = f"{data[1] >> 5}.{data[1] & 0x1F:02d}"
    body = ""
    try:
        marker = data.index(b"\xff", 4)
        body = data[marker + 1 :].decode("utf-8", "replace")[:400]
    except ValueError:
        pass
    return f"ver{ver} t{typ} {code} len={len(data)} body={body!r}"


def main() -> None:
    import os
    ips = sys.argv[1:] or [i.strip() for i in os.environ.get("FC_LAN_IPS", "").split(",") if i.strip()]

    print("== /.well-known/core (the CoAP standard fingerprint) ==")
    for ip in ips:
        for uri in ("/.well-known/core", "/fault", "/"):
            r = coap_get(ip, uri)
            if r:
                print(f"  {ip} GET {uri}:")
                print(f"    {parse(r)}")

    print("\n== observe /resource dir candidates ==")
    for ip in ips:
        for uri in ("/15001/", "/15005/", "/15006/", "/sys/", "/devices"):
            r = coap_get(ip, uri, observe=True)
            if r and data_is_not_404(r):
                print(f"  {ip} OBS {uri}: {parse(r)}")


def data_is_not_404(data: bytes) -> bool:
    if not data:
        return False
    code = (data[1] >> 5, data[1] & 0x1F)
    return code != (4, 4)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

    print("\n== TLS fingerprint of www.fcsmartlock.com (what aiohttp must handle) ==")
    host = "www.fcsmartlock.com"
    tests = [
        ("python default", lambda ctx: None),
        (
            "legacy renegotiation + seclevel0",
            lambda ctx: (
                setattr(ctx, "options", ctx.options | 0x4),
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0"),
            ),
        ),
        (
            "TLS1.2 forced + all ciphers",
            lambda ctx: (
                setattr(
                    ctx,
                    "minimum_version",
                    ssl.TLSVersion.TLSv1_2,
                ),
                setattr(ctx, "maximum_version", ssl.TLSVersion.TLSv1_2),
                ctx.set_ciphers("ALL:@SECLEVEL=0"),
                setattr(ctx, "check_hostname", False),
                setattr(ctx, "verify_mode", ssl.CERT_NONE),
                setattr(ctx, "options", ctx.options | 0x4),
            ),
        ),
    ]
    for name, tune in tests:
        try:
            ctx = ssl.create_default_context()
            tune(ctx)
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    print(f"  {name}: OK {tls.version()} {tls.cipher()[0]}")
        except Exception as err:
            print(f"  {name}: {type(err).__name__}: {str(err)[:90]}")

    print("\n== aiohttp with legacy TLS ==")
    import asyncio

    async def aio():
        import aiohttp

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            try:
                async with session.post(
                    "https://www.fcsmartlock.com/api/app/login",
                    json={"email": "probe@invalid.test", "password": "x"},
                ) as resp:
                    print(f"  POST login: {resp.status} {(await resp.text())[:120]!r}")
            except Exception as err:
                print(f"  POST login: {type(err).__name__}: {str(err)[:120]}")

    asyncio.run(aio())

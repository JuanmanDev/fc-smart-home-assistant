"""Live recon of FC devices on the LAN + cloud state.

Run from repo root: python tools/lan_recon.py [--ips 192.168.3.90,192.168.3.91]
"""

from __future__ import annotations

import argparse
import asyncio
import random
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def coap_request(host: str, path: str, payload: bytes, method: str = "POST",
                 port: int = 5683, timeout: float = 2.5) -> bytes | None:
    """Raw CoAP request: ver1, CON, token 2B, Uri-Path options, payload."""
    codes = {"GET": 0x01, "POST": 0x02, "PUT": 0x03, "DELETE": 0x04}
    msg_id = random.randint(1, 0xFFFF)
    header = struct.pack("!BBH", 0x42, codes.get(method, 0x02), msg_id)
    token = bytes([random.randint(0, 255), random.randint(0, 255)])
    opts = b""
    prev = 0
    for part in [p for p in path.strip("/").split("/") if p]:
        pb = part.encode()
        delta = 11 - prev if prev < 11 else 0
        prev = 11
        if len(pb) < 13:
            opts += bytes([(delta << 4) | len(pb)]) + pb
        else:
            opts += bytes([(delta << 4) | 13]) + bytes([len(pb) - 13]) + pb
    pkt = header + token + opts + bytes([0xFF]) + payload
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        return s.recvfrom(2048)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def parse_coap(data: bytes) -> str:
    ver = data[0] >> 6
    typ = (data[0] >> 4) & 3
    code = f"{data[1] >> 5}.{data[1] & 0x1F:02d}"
    body = ""
    # find payload marker
    try:
        marker = data.index(b"\xff", 4)
        body = data[marker + 1 :].decode("utf-8", "replace")[:200]
    except ValueError:
        pass
    return f"ver{ver} t{typ} code={code} len={len(data)} body={body!r} hex={data[:32].hex()}"


async def port_scan(host: str, ports: list[int]) -> list[int]:
    open_ports = []

    async def try_port(port):
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=2.0)
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    await asyncio.gather(*[try_port(p) for p in ports])
    return open_ports


def http_fingerprint(host: str) -> None:
    for port in (80, 443, 8080, 8060, 9999):
        try:
            s = socket.socket()
            s.settimeout(2)
            if port == 443:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            data = s.recv(512)
            print(f"  HTTP {port}: {data[:200]!r}")
            s.close()
            return
        except Exception:
            continue
    print("  HTTP: no response on 80/443/8080/8060/9999")


def mdns_query_names(host: str) -> None:
    """Reverse-DNS style: ask mDNS for services, print any A records for host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        # PTR query _services._dns-sd._udp.local
        q = (
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        )
        s.sendto(q, ("224.0.0.251", 5353))
        try:
            while True:
                data, addr = s.recvfrom(2048)
                print(f"  mDNS from {addr[0]}: {data[:80].hex()} {data[:60]!r}")
                if addr[0] != host:
                    break
        except socket.timeout:
            pass
        s.close()
    except Exception as err:
        print(f"  mDNS failed: {err}")


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ips", default="192.168.3.90,192.168.3.91")
    parser.add_argument("--full-port-scan", action="store_true")
    args = parser.parse_args()
    ips = [i.strip() for i in args.ips.split(",") if i.strip()]

    from custom_components.fc_smarthome.local.lan import discover_lan_devices

    print("== UDP broadcast discovery ==")
    found = await discover_lan_devices(timeout=4.0)
    for d in found:
        print(f"  {d['ip']} via {d['source']} payload={d['payload'][:60]}")

    alink_body = (
        b'{"id":1,"version":"1.0","method":"thing.deviceInfo.get",'
        b'"params":{},"sys":{"ack":1}}'
    )
    paths = [
        "/sys/discover",
        "/sys/a1XXXXXXXX/device/discover",
        "/sys/device/info",
        "/deviceinfo",
        "/sys/config",
        "/setup/deviceinfo",
        "/sys/awss/device/list",
        "/sys/thing/deviceInfo/get",
        "/sys/a/b/thing/deviceInfo/get",
        "/thing/service/deviceInfo/get",
        "/post",
        "/dtls",
        "/sys/a/b/thing/service/localControl",
    ]

    common_ports = [
        80, 443, 554, 1883, 5683, 8000, 8060, 8080, 8443, 8883, 8886,
        9000, 9999, 10000, 3000, 2000, 8666, 6668, 8053, 8100,
    ]

    for ip in ips:
        print(f"\n=== {ip} ===")
        print("  -- fingerprint --")
        http_fingerprint(ip)
        mdns_query_names(ip)
        ports = await port_scan(ip, common_ports)
        print(f"  open TCP ports: {ports}")
        if args.full_port_scan:
            wide = await port_scan(ip, range(1, 1100))
            print(f"  wide scan 1-1100: {wide}")

        print("  -- CoAP paths --")
        for p in paths:
            r = coap_request(ip, p, alink_body, method="POST")
            if r is None:
                r2 = coap_request(ip, p, alink_body, method="GET")
                if r2 is not None:
                    print(f"  POST {p}: timeout | GET {p}: {parse_coap(r2)}")
                continue
            print(f"  POST {p}: {parse_coap(r)}")

        # try the classic Alink registration/topic shape
        for topic in (
            "/sys/+/thing/deviceInfo/get",
            "/ext/+/+/thing/discovery",
        ):
            r = coap_request(ip, topic, alink_body)
            if r is not None:
                print(f"  topic {topic}: {parse_coap(r)}")

    print("\n== cloud re-check ==")
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for path in ("/", "/api/", "/api/app/login"):
        url = f"https://www.fcsmartlock.com{path}"
        req = urllib.request.Request(
            url,
            data=b"{}" if "login" in path else None,
            headers={"Content-Type": "application/json"},
            method="POST" if "login" in path else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read()[:150]
                print(f"  {path}: {resp.status} {body!r}")
        except urllib.error.HTTPError as err:
            print(f"  {path}: HTTP {err.code} {err.read()[:120]!r}")
        except Exception as err:
            print(f"  {path}: {type(err).__name__} {err}")


if __name__ == "__main__":
    asyncio.run(main())

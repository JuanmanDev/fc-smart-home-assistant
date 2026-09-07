"""Deep-dive 192.168.2.3 (ports 2000+3000 = APK gatewayPort+appSystemPort).

Tests: HTTP on each port, TLS, then FCFC/TCP framing, Alink CoAP.
Also checks .2.4 and .2.110 (port 3000).
"""

from __future__ import annotations

import random
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.local.ble import build_frame


def http_probe(host: str, port: int, use_tls: bool = False) -> None:
    try:
        s = socket.create_connection((host, port), timeout=3)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(512)
        print(f"  HTTP{'S' if use_tls else ''} {port}: {data[:250]!r}")
        s.close()
    except Exception as err:  # noqa: BLE001
        print(f"  HTTP{'S' if use_tls else ''} {port}: {type(err).__name__}: {str(err)[:80]}")


def tcp_raw(host: str, port: int, payload: bytes, label: str) -> None:
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(payload)
        s.settimeout(3)
        data = s.recv(1024)
        print(f"  {label}: {data[:80].hex()} | {data[:60]!r}")
        s.close()
    except Exception as err:  # noqa: BLE001
        print(f"  {label}: {type(err).__name__}: {str(err)[:60]}")


def banner_grab(host: str, port: int) -> None:
    """Connect and just listen for a banner."""
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.settimeout(4)
        try:
            data = s.recv(256)
            print(f"  banner {port}: {data[:100].hex()} | {data[:60]!r}")
        except socket.timeout:
            print(f"  banner {port}: (silent, waits for client first)")
        s.close()
    except Exception as err:  # noqa: BLE001
        print(f"  banner {port}: {type(err).__name__}")


def coap_probe(host: str, port: int = 5683) -> None:
    import struct

    msg_id = random.randint(1, 0xFFFF)
    pkt = struct.pack("!BBH", 0x40, 0x00, msg_id)  # CON ping

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(2048)
        print(f"  CoAP ping: {data.hex()}")
    except Exception as err:  # noqa: BLE001
        print(f"  CoAP ping: {type(err).__name__}")
    finally:
        s.close()


def main() -> None:
    targets = [
        ("192.168.2.3", [80, 443, 2000, 3000, 8080, 8443]),
        ("192.168.2.4", [3000]),
        ("192.168.2.110", [3000]),
    ]
    for host, ports in targets:
        print(f"\n=== {host} ===")
        for port in ports:
            http_probe(host, port, use_tls=(port in (443, 8443)))
        banner_grab(host, 2000 if 2000 in ports else ports[0])
        # FCFC framing attempts on the APK-named ports
        if 2000 in ports:
            tcp_raw(host, 2000, build_frame(0x03, b"", seq=1), "FCFC-status@2000")
            tcp_raw(host, 2000, build_frame(0x01, b"000000", seq=2), "FCFC-pair@2000")
        if 3000 in ports:
            tcp_raw(host, 3000, build_frame(0x03, b"", seq=3), "FCFC-status@3000")
            tcp_raw(
                host,
                3000,
                b'{"id":1,"version":"1.0","method":"thing.deviceInfo.get","params":{}}',
                "json-rpc@3000",
            )
            tcp_raw(
                host,
                3000,
                b"POST /api/app/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                "http-login@3000",
            )
        coap_probe(host)


if __name__ == "__main__":
    main()

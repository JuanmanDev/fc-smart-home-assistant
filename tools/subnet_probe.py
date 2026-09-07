"""Deep probe of the local 192.168.2.x subnet: find the FC gateway/lock.

1. ARP-scan-like sweep: ICMP ping all 254 addresses (fast, parallel)
2. For live hosts: CoAP probe (5683/UDP) + common port scan
3. Special attention to the gateway .2.1 (RST'd a CoAP probe before)
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import random
import socket
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def ping(host: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "500", host],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return "TTL=" in result.stdout
    except Exception:  # noqa: BLE001
        return False


def coap_probe(host: str, port: int = 5683, timeout: float = 1.5) -> dict | None:
    """RFC-7252 empty GET to / — CoAP stacks answer ACK."""
    msg_id = random.randint(1, 0xFFFF)
    pkt = struct.pack("!BBH", 0x42, 0x01, msg_id) + bytes([1, 2]) + bytes([11, 0])
    # GET / : single Uri-Path option with empty value? Use plain ping instead:
    pkt = struct.pack("!BBH", 0x40, 0x00, msg_id)  # CON PING
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        data, addr = s.recvfrom(2048)
        code = f"{data[1] >> 5}.{data[1] & 0x1F:02d}"
        return {
            "ip": host,
            "port": port,
            "type": (data[0] >> 4) & 3,
            "code": code,
            "len": len(data),
        }
    except (socket.timeout, ConnectionResetError):
        return None
    finally:
        s.close()


def tcp_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    open_ports = []
    for p in ports:
        try:
            s = socket.create_connection((host, p), timeout=timeout)
            s.close()
            open_ports.append(p)
        except OSError:
            continue
    return open_ports


async def main() -> None:
    subnet = "192.168.2"
    print(f"== ping sweep {subnet}.1-254 ==")
    hosts: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(ping, f"{subnet}.{i}"): f"{subnet}.{i}" for i in range(1, 255)}
        for fut in concurrent.futures.as_completed(futures):
            if fut.result():
                hosts.append(futures[fut])
    hosts.sort(key=lambda h: int(h.split(".")[-1]))
    print(f"  live: {hosts}")

    interesting_ports = [80, 443, 554, 1900, 2000, 3000, 5683, 5684, 8060, 8080, 8443, 8883, 9999]

    print("\n== per-host detail ==")
    for host in hosts:
        coap = coap_probe(host)
        ports = tcp_ports(host, interesting_ports)
        marker = ""
        if coap:
            marker = f" CoAP({coap['code']})"
        if ports or coap:
            print(f"  {host}: ports={ports}{marker}")

    # deep-dive the router/gateway
    print("\n== gateway 192.168.2.1 deep dive ==")
    gw_ports = tcp_ports("192.168.2.1", [21, 22, 23, 53, 80, 443, 1900, 5353, 5683, 8080, 8081, 8443, 9999])
    print(f"  ports: {gw_ports}")
    for p in (80, 8080):
        try:
            s = socket.create_connection(("192.168.2.1", p), timeout=2)
            s.sendall(f"GET / HTTP/1.1\r\nHost: 192.168.2.1\r\n\r\n".encode())
            data = s.recv(256)
            print(f"  HTTP {p}: {data[:180]!r}")
            s.close()
            break
        except OSError:
            continue


if __name__ == "__main__":
    asyncio.run(main())

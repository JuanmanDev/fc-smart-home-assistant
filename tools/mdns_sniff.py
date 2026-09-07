"""Passive mDNS sniffer: find Alink/FC announcements on the LAN.

Listens on 224.0.0.251:5353 for 60s (or --timeout), decodes all PTR/SRV/TXT/A
records, and prints anything FC/Alink/lock-related plus every unique
hostname+IP pair (to catch lock announcements regardless of service name).
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumps = 0
    while True:
        if offset >= len(data):
            return ".".join(labels), offset
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if jumps > 5:
                return ".".join(labels), offset + 2
            ptr = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            label, _ = decode_name(data, ptr)
            labels.append(label)
            offset += 2
            jumps += 1
            break
        labels.append(data[offset + 1 : offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return ".".join(labels), offset


def parse_mdns(data: bytes) -> list[tuple[str, str, str]]:
    """Return [(name, rtype, value)] from an mDNS packet."""
    if len(data) < 12:
        return []
    qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    out: list[tuple[str, str, str]] = []
    pos = 12
    for _ in range(qdcount):
        _, pos = decode_name(data, pos)
        pos += 4
    for _ in range(ancount + nscount + arcount):
        name, pos = decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        rdata = data[pos + 10 : pos + 10 + rdlen]
        pos += 10 + rdlen
        type_names = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}
        tname = type_names.get(rtype, str(rtype))
        if rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 16:
            # TXT: sequence of length-prefixed key=value
            parts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1 : i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            value = " | ".join(parts)
        elif rtype == 12:
            value, _ = decode_name(data, pos - rdlen)
        elif rtype == 33 and len(rdata) >= 6:
            prio, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = decode_name(rdata, 6)
            value = f"{target}:{port}"
        else:
            value = rdata.hex()
        out.append((name, tname, value))
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--all", action="store_true", help="print every record")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", 5353))
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", 5353))
    mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(args.timeout)

    seen: dict[tuple, set] = defaultdict(set)
    print(f"listening on mDNS 224.0.0.251:5353 for {args.timeout}s ...")
    try:
        while True:
            data, addr = sock.recvfrom(8192)
            for name, rtype, value in parse_mdns(data):
                interesting = any(
                    k in name.lower()
                    for k in ("alink", "fc", "lock", "smart", "ali", "iot", "_alive", "thing", "lvc")
                )
                if interesting or args.all:
                    key = (addr[0], name, rtype)
                    if value not in seen[key]:
                        seen[key].add(value)
                        print(f"  {addr[0]:<16} {rtype:<4} {name} -> {value}")
    except socket.timeout:
        pass
    print("\nsummary of unique FC/alink names:")
    names = {name for (_, name, _), vals in seen.items() for _ in vals}
    for n in sorted(names):
        print("  ", n)


if __name__ == "__main__":
    main()

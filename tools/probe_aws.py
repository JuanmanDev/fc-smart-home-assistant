"""Probe the AWS international channel (fingercrystal_amazon_server)."""

from __future__ import annotations

import asyncio
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


async def main() -> None:
    host = "18.219.242.80"
    print(f"== TCP port scan on {host} ==")
    ports = [21, 22, 80, 443, 2000, 3000, 3306, 5683, 8060, 8080, 8081, 8443, 8883, 9000, 9999]
    open_ports = [p for p in ports if tcp_open(host, p)]
    print(f"  open: {open_ports}")

    if 443 in open_ports:
        print("\n== TLS on 443 ==")
        for sni in (host, "www.fcsmartlock.com", "fcsmartlock.com", "qspms.cn"):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                        cert = tls.getpeercert(binary_form=False)
                        print(f"  SNI {sni!r}: {tls.version()} cipher={tls.cipher()[0]}")
                        if cert:
                            print(f"    subject: {cert.get('subject')}")
            except Exception as err:
                print(f"  SNI {sni!r}: {type(err).__name__}: {str(err)[:90]}")

    print("\n== HTTP requests ==")
    from custom_components.fc_smarthome.api.client import FcClient
    from custom_components.fc_smarthome.api.errors import FcError

    client = FcClient("x", "x")
    try:
        targets = []
        for scheme in ("http", "https"):
            for port in (80, 443, 8080, 8060, 3000):
                targets.append(f"{scheme}://{host}:{port}")
        for base in targets:
            for path in ("/", "/api/app/login", "/login"):
                try:
                    body = await client._request(
                        "POST",
                        f"{base}{path}",
                        payload={"phone": "000000000", "countryCode": "34", "password": "x"},
                        auth=False,
                        retries=1,
                    )
                    print(f"  POST {base}{path}: 200 {str(body)[:200]}")
                except FcError as err:
                    msg = str(err)
                    if "404" not in msg:  # show everything except boring 404s
                        print(f"  POST {base}{path}: {msg[:130]}")
                except Exception as err:  # noqa: BLE001
                    print(f"  POST {base}{path}: {type(err).__name__} {str(err)[:60]}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())

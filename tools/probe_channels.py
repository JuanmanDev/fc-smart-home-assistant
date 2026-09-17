"""Probe all FC channels for a live login route."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.errors import FcError

HOSTS = [
    "https://www.fcsmartlock.com",
    "https://test.fcsmartlock.com",
    "https://test2.fcsmartlock.com",
    "https://18.219.242.80",
    "https://iot.qspms.cn",
]
PATHS = [
    "/",
    "/api/app/login",
    "/api/login",
    "/appSystem/login",
    "/gateway/login",
    "/api/app/version",
    "/api/app/config",
]


async def main() -> None:
    for host in HOSTS:
        print(f"=== {host} ===")
        client = FcClient("probe@invalid.test", "x")
        try:
            for path in PATHS:
                try:
                    body = await client._request(
                        "POST",
                        f"{host}{path}",
                        payload={"email": "probe@invalid.test", "password": "x"},
                        auth=False,
                        retries=1,
                    )
                    print(f"  {path}: 200 {str(body)[:140]}")
                except FcError as err:
                    msg = str(err)
                    if "502" in msg:
                        print(f"  {path}: 502 (route exists, backend down)")
                    elif "404" not in msg:
                        print(f"  {path}: {msg[:90]}")
        finally:
            await client.close()


if __name__ == "__main__":
    asyncio.run(main())

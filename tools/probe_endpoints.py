"""Probe FC SmartHome cloud endpoint candidates.

Sends harmless GET/HEAD requests (no credentials) to candidate hosts/paths
and records which answer, with what status/shape. Use after a mitmproxy
capture (tools/HARVEST.md) to confirm the real endpoints, then write them
into fc_smarthome_endpoints.json and drop --endpoints-file.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aiohttp

from custom_components.fc_smarthome.api.endpoints import EndpointRegistry

COMMON_HOSTS = [
    "https://api.fingercrystal.com",
    "https://api.fingercrystal.cn",
    "https://euapi.fingercrystal.com",
    "https://api-eu.fingercrystal.com",
    "https://api-cn.fingercrystal.com",
    "https://openapi.fingercrystal.com",
    "https://fc-api.fingercrystal.com",
    "https://api.fcsmartlife.com",
    "https://api.fcsmarthome.com",
    "https://fcapi.yilock.com",
    "https://api.yilock.com",
]

COMMON_PATHS = [
    "/",
    "/api",
    "/api/app/login",
    "/v1/auth/login",
    "/v2/user/login",
    "/user/login",
    "/api/user/login",
    "/app/login",
]


async def probe_all(registry: EndpointRegistry) -> dict:
    results: list[dict] = []
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=8),
        headers={"User-Agent": "FCSmartHome/25.7.17 (Android 15)"},
    ) as session:
        for host in COMMON_HOSTS + [registry.base_url]:
            for path in COMMON_PATHS:
                url = host.rstrip("/") + path
                try:
                    async with session.get(url) as resp:
                        text = (await resp.text())[:120]
                        results.append(
                            {
                                "url": url,
                                "status": resp.status,
                                "server": resp.headers.get("Server", ""),
                                "body": text,
                            }
                        )
                except aiohttp.ClientError as err:
                    results.append({"url": url, "error": type(err).__name__})
                except asyncio.TimeoutError:
                    results.append({"url": url, "error": "timeout"})
                await asyncio.sleep(0.2)
    return {
        "alive": [r for r in results if r.get("status") not in (None, 404)],
        "all": results,
    }


async def main() -> int:
    parser = argparse.ArgumentParser(description="Probe FC cloud endpoints")
    parser.add_argument("--region", default="us", choices=["us", "eu", "cn", "ru"])
    parser.add_argument("--endpoints-file")
    args = parser.parse_args()
    registry = EndpointRegistry.load(args.region, args.endpoints_file)
    report = await probe_all(registry)
    out = Path("endpoint_probe_report.json")
    out.write_text(json.dumps(report, indent=2))
    alive = report["alive"]
    print(f"Probed {len(report['all'])} candidates, {len(alive)} responded.")
    for item in alive:
        print(f"  {item['url']} -> {item['status']} {item.get('server', '')}")
    print(f"Full report: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

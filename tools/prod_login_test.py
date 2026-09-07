"""Production login test — credentials from environment variables ONLY.

Required env vars (never hardcode, never commit):
    FC_PHONE      your phone number (digits only)
    FC_CC         country code digits, e.g. 34
    FC_PASSWORD   the account password

Usage (PowerShell, local only):
    $env:FC_PHONE="..."; $env:FC_CC="34"; $env:FC_PASSWORD="..."
    python tools/prod_login_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from custom_components.fc_smarthome.api.client import FcClient
from custom_components.fc_smarthome.api.errors import FcError


def _cred(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        print(f"missing env var {name} — set it locally, never commit it")
        sys.exit(2)
    return value


async def try_login(client: FcClient, host: str, path: str, payload: dict) -> dict:
    try:
        body = await client._request(
            "POST", f"{host}{path}", payload=payload, auth=False, retries=1
        )
        return {"ok": True, "body": body}
    except FcError as err:
        return {"ok": False, "err": str(err)[:220]}
    except Exception as err:  # noqa: BLE001
        return {"ok": False, "err": f"{type(err).__name__}: {str(err)[:120]}"}


async def main() -> None:
    phone = _cred("FC_PHONE")
    cc = os.environ.get("FC_CC", "34")
    password = _cred("FC_PASSWORD")

    login_shapes = [
        {"phone": phone, "countryCode": cc, "password": password},
        {"mobile": phone, "areaCode": cc, "password": password},
        {"account": phone, "password": password},
        {"loginId": phone, "password": password, "countryCode": cc},
    ]
    paths = [
        "/api/app/login",
        "/api/login",
        "/api/user/login",
    ]
    hosts = ["https://www.fcsmartlock.com", "https://iot.qspms.cn"]

    client = FcClient(phone, password)
    try:
        for host in hosts:
            for path in paths:
                r = await try_login(client, host, path, {"ping": 1})
                err = r.get("err", "")
                if "502" in err:
                    print(f"  {host}{path}: 502 backend down")
                    continue
                if "404" in err:
                    print(f"  {host}{path}: 404")
                    continue
                if "692" in err:
                    print(f"  {host}{path}: 692 signature gate")
                    continue
                for shape in login_shapes:
                    r = await try_login(client, host, path, shape)
                    if r["ok"]:
                        print(f"  SUCCESS {host}{path} keys={sorted(shape)}")
                        # redact sensitive values before printing
                        body = json.dumps(r["body"], ensure_ascii=False, default=str)
                        print("  body:", body[:400])
                        return
                    print(f"  {host}{path} {sorted(shape)}: {r.get('err', '')[:100]}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())

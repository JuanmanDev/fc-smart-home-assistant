"""FC SmartHome cloud client.

Async HTTP client for the Fingerchip/Fingercrystal smart lock cloud.
All network paths go through EndpointRegistry so every host/path can be
hot-swapped from a capture file without code changes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any, Callable

import aiohttp

from .endpoints import EndpointRegistry
from .errors import FcApiError, FcAuthError, FcConnectionError, FcError
from .models import (
    ControlResult,
    Device,
    LockEvent,
    LockEventType,
    LockStatus,
    LockUser,
    LockUserType,
    TokenPair,
    UnlockMethod,
    parse_ts,
)
from .const import DEVICE_STATUS_MASKS, UNLOCK_METHOD_LABELS, USER_TYPE_INT_MAP
from .discovery import APP_VERSION, VENDOR_AES_KEY, try_aes_decrypt, try_aes_encrypt

_LOGGER = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_BACKOFF = 1.5
REQUEST_TIMEOUT = 15
RATE_LIMIT_STATUS = 672  # vendor-specific: too many requests, retry in 3 min


class FcClient:
    """Low-level cloud client: auth, transport, endpoints, retries.

    Protocol details mirror the vendor's own stack (ZHIXIN web platform):
    - auth header: ``token: <hex>`` (not Bearer)
    - response envelope: ``{"result": 1, "data": ..., "message": ...}``
      where result==1 means success
    - optional AES-ECB/PKCS7 payload crypto with the vendor web key
    - HTTP 672 = vendor rate limit (wait ~3 minutes)
    """

    def __init__(
        self,
        email: str,
        password: str,
        region: str = "us",
        endpoints: EndpointRegistry | None = None,
        session: aiohttp.ClientSession | None = None,
        on_token_refreshed: Callable[[TokenPair], None] | None = None,
        use_vendor_crypto: bool = True,
    ) -> None:
        self.email = email
        self._password = password
        self.endpoints = endpoints or EndpointRegistry.load(region)
        self.endpoints.region = region
        self._session = session
        self._own_session = session is None
        self.tokens: TokenPair | None = None
        self._on_token_refreshed = on_token_refreshed
        self._user_cache: dict[str, dict[str, LockUser]] = {}
        self._last_events: dict[str, list[LockEvent]] = {}
        self._use_vendor_crypto = use_vendor_crypto

    # ---------- transport ----------

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                headers=self._base_headers(),
            )
            self._own_session = True
        return self._session

    def _base_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"FCSmartHome/{APP_VERSION} (Android 15)",
            "timezone": "0",  # minutes offset, like the web app
            "version": "1.0.4R",
            "Accept-Language": "en",
            "X-Platform": "android",
            "X-App-Version": APP_VERSION,
        }

    async def close(self) -> None:
        if self._own_session and self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def _request(
        self,
        method: str,
        url: str,
        payload: dict | None = None,
        params: dict | None = None,
        auth: bool = True,
        retries: int = MAX_RETRIES,
    ) -> Any:
        session = await self._ensure_session()
        headers: dict[str, str] = {}
        if auth:
            if not self.tokens or not self.tokens.access_token:
                raise FcAuthError("Not logged in")
            # vendor stack uses a plain `token:` header (ZHIXIN web app)
            headers["token"] = self.tokens.access_token
        last_error: Exception | None = None
        for attempt in range(retries):
            try:
                async with session.request(
                    method, url, json=payload, params=params, headers=headers
                ) as resp:
                    body_text = await resp.text()
                    if resp.status in (429, RATE_LIMIT_STATUS, 500, 502, 503, 504) and attempt < retries - 1:
                        await asyncio.sleep(min(RETRY_BACKOFF**attempt, 8))
                        continue
                    try:
                        body = json.loads(body_text) if body_text else {}
                    except json.JSONDecodeError:
                        body = {"_raw": body_text}
                    if resp.status == 401:
                        raise FcAuthError(f"401 from {url}: {body_text[:200]}")
                    if resp.status >= 400:
                        raise FcApiError(
                            f"HTTP {resp.status} from {url}",
                            code=resp.status,
                            payload=body,
                        )
                    if isinstance(body, dict):
                        # ZHIXIN envelope: {"result":1|0, "data":..., "message":...}
                        if "result" in body:
                            if body.get("result") != 1:
                                msg = str(body.get("message") or body_text[:200])
                                if "token" in msg.lower() or body.get("result") in (672, 401, 1001):
                                    raise FcAuthError(f"API result {body.get('result')}: {msg}")
                                raise FcApiError(
                                    f"API result {body.get('result')}: {msg}",
                                    code=body.get("result") if isinstance(body.get("result"), int) else resp.status,
                                    payload=body,
                                )
                            return body
                        # fallback: generic Chinese-cloud code envelope
                        err_code = body.get("code")
                        if err_code is None:
                            err_code = body.get("errcode")
                        if err_code is None:
                            err_code = body.get("error")
                        if err_code is not None and str(err_code) not in ("0", "200", "success", "ok"):
                            msg = str(body.get("msg") or body.get("message") or body_text[:200])
                            if "token" in msg.lower() or str(err_code) in ("401", "1001", "1002"):
                                raise FcAuthError(
                                    f"API error {err_code} from {url}: {msg}"
                                )
                            raise FcApiError(
                                f"API error {err_code} from {url}: {msg}",
                                code=err_code if isinstance(err_code, int) else resp.status,
                                payload=body,
                            )
                    return body
            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                last_error = err
                if attempt < retries - 1:
                    await asyncio.sleep(min(RETRY_BACKOFF**attempt, 8))
        raise FcConnectionError(f"Request to {url} failed: {last_error}")

    # ---------- auth ----------

    async def login(self) -> TokenPair:
        """Login; on unknown-host/404, self-configure via discovery first."""
        try:
            return await self._login_once()
        except (FcConnectionError, FcApiError) as err:
            _LOGGER.debug("login failed on current endpoints (%s); trying discovery", err)
            from .discovery import auto_configure

            registry = await auto_configure(self.endpoints)
            if registry.source_file == "discovered":
                return await self._login_once()
            raise

    async def _login_once(self) -> TokenPair:
        payload = {
            "email": self.email,
            "password": self._password,
            "platform": "android",
            "appVersion": APP_VERSION,
            "deviceName": "home-assistant",
        }
        # The vendor web stack encrypts the password with the shared
        # AES-ECB key; many endpoints require it, plain JSON for others.
        if self._use_vendor_crypto:
            encrypted = try_aes_encrypt(self._password)
            if encrypted:
                payload["password"] = encrypted
                payload["encryptType"] = "aes"
        body = await self._request(
            "POST", self.endpoints.url("login"), payload=payload, auth=False
        )
        data = self._unwrap(body)
        # vendor web stack sometimes returns AES-hex-encrypted payloads
        for key in ("data", "result_data"):
            value = data.get(key) if isinstance(data, dict) else None
            if isinstance(value, str) and len(value) % 32 == 0 and len(value) >= 32:
                decrypted = try_aes_decrypt(value)
                if decrypted and decrypted.startswith(("{", "[")):
                    try:
                        data = {**data, key: json.loads(decrypted)}
                    except json.JSONDecodeError:
                        pass
        token = data.get("token") or data.get("access_token") or data.get("accessToken")
        if not token:
            raise FcAuthError(f"No token in login response: {body}")
        self.tokens = TokenPair(
            access_token=str(token),
            refresh_token=data.get("refresh_token") or data.get("refreshToken"),
            user_id=str(data.get("user_id") or data.get("userId") or data.get("uid") or "") or None,
            expires_at=(
                data["expires_at"]
                if isinstance(data.get("expires_at"), (int, float))
                else (time.time() + data["expires_in"]) if isinstance(data.get("expires_in"), int) else 0.0
            ),
        )
        return self.tokens

    async def refresh_tokens(self) -> TokenPair:
        if not self.tokens or not self.tokens.refresh_token:
            return await self.login()
        body = await self._request(
            "POST",
            self.endpoints.url("refresh"),
            payload={"refresh_token": self.tokens.refresh_token},
            auth=False,
        )
        data = self._unwrap(body)
        token = data.get("token") or data.get("access_token")
        if token:
            self.tokens.access_token = str(token)
            new_refresh = data.get("refresh_token") or data.get("refreshToken")
            if new_refresh:
                self.tokens.refresh_token = str(new_refresh)
            exp = data.get("expires_in")
            if isinstance(exp, int):
                self.tokens.expires_at = time.time() + exp
            if self._on_token_refreshed:
                self._on_token_refreshed(self.tokens)
            return self.tokens
        # refresh endpoint didn't give us anything usable: full re-login
        return await self.login()

    async def ensure_logged_in(self) -> None:
        if self.tokens and self.tokens.valid:
            return
        try:
            if self.tokens and self.tokens.refresh_token:
                await self.refresh_tokens()
                return
        except FcError:
            pass
        await self.login()

    async def logout(self) -> None:
        if self.tokens:
            with contextlib.suppress(FcError):
                await self._request("POST", self.endpoints.url("logout"))
        self.tokens = None

    def set_tokens(self, tokens: TokenPair) -> None:
        self.tokens = tokens

    # ---------- helpers ----------

    @staticmethod
    def _unwrap(body: Any) -> dict:
        if isinstance(body, dict):
            for key in ("data", "result", "payload"):
                inner = body.get(key)
                if isinstance(inner, dict):
                    return inner
            return body
        return {}

    @staticmethod
    def _listify(body: Any, *keys: str) -> list[dict]:
        data = FcClient._unwrap(body)
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                for sub in ("list", "items", "records", "rows"):
                    if isinstance(value.get(sub), list):
                        return value[sub]
        for value in data.values():
            if isinstance(value, list):
                return value
        return []

    # ---------- devices ----------

    async def get_devices(self) -> list[Device]:
        body = await self._request("GET", self.endpoints.url("devices"))
        devices: list[Device] = []
        seen: set[str] = set()
        raw_lists: list[dict] = []
        data = self._unwrap(body)
        for value in data.values():
            if isinstance(value, list):
                raw_lists.extend(v for v in value if isinstance(v, dict))
        if not raw_lists:
            raw_lists = self._listify(body, "devices", "device_list", "list")
        for item in raw_lists:
            dev = self._parse_device(item)
            if dev and dev.device_id not in seen:
                seen.add(dev.device_id)
                devices.append(dev)
        return devices

    def _parse_device(self, item: dict) -> Device | None:
        device_id = item.get("device_id") or item.get("dev_id") or item.get("id")
        if not device_id:
            return None
        category = str(item.get("category") or item.get("type") or "").lower()
        battery = item.get("battery")
        if battery is None:
            battery = item.get("batteryVal")
        if battery is None:
            battery = item.get("power")
        if isinstance(battery, str) and battery.isdigit():
            battery = int(battery)
        raw_status = item.get("dev_status")
        dev = Device(
            device_id=str(device_id),
            name=str(item.get("name") or item.get("device_name") or device_id),
            model=str(item.get("product_key") or item.get("model") or ""),
            category=category,
            manufacturer=str(item.get("public_name") or item.get("brand") or ""),
            online=bool(item.get("online", True)),
            battery=int(battery) if isinstance(battery, int) else None,
            signal=item.get("rssi") if isinstance(item.get("rssi"), int) else None,
            last_update=parse_ts(item.get("last_push_time") or item.get("update_time")),
            raw=item,
        )
        if isinstance(raw_status, dict):
            merged = dict(raw_status)
            merged.setdefault("device_id", dev.device_id)
            dev.raw["dev_status"] = merged
        return dev

    async def get_device_status(self, device_id: str) -> LockStatus:
        body = await self._request("GET", self.endpoints.url("device_status", device_id))
        data = self._unwrap(body)
        status = self._parse_status(device_id, data)
        return status

    def _parse_status(self, device_id: str, data: dict) -> LockStatus:
        dev_status = data.get("devStatus")
        if dev_status is None:
            dev_status = data.get("dev_status")
        status: LockStatus
        if isinstance(dev_status, (int, float)):
            status = LockStatus.from_dev_status(device_id, int(dev_status), DEVICE_STATUS_MASKS)
        else:
            status = LockStatus(device_id=device_id)
            locked = data.get("locked")
            if locked is None:
                locked = data.get("is_locked")
            if isinstance(locked, bool):
                status.locked = locked
        battery = data.get("batteryVal")
        if battery is None:
            battery = data.get("battery")
        if isinstance(battery, int):
            status.battery = battery
        elif isinstance(battery, str) and battery.isdigit():
            status.battery = int(battery)
        signal = data.get("rssi")
        if isinstance(signal, int):
            status.signal = signal
        status.raw = data
        return status

    # ---------- lock control ----------

    async def _control(self, key: str, device_id: str, payload: dict | None = None) -> ControlResult:
        body = await self._request(
            "POST", self.endpoints.url(key, device_id), payload=payload or {}
        )
        data = self._unwrap(body)
        return ControlResult(
            success=True,
            message=str(data.get("message") or data.get("msg") or "ok"),
            command_id=str(data.get("cmd_id") or data.get("commandId") or "") or None,
            raw=data,
        )

    async def lock(self, device_id: str) -> ControlResult:
        return await self._control("lock", device_id)

    async def unlock(self, device_id: str, reason: str = "app") -> ControlResult:
        return await self._control("unlock", device_id, {"reason": reason})

    async def latch(self, device_id: str) -> ControlResult:
        return await self._control("latch", device_id)

    async def ring_bell(self, device_id: str) -> ControlResult:
        return await self._control("bell", device_id)

    async def beep(self, device_id: str) -> ControlResult:
        return await self._control("beep", device_id)

    async def set_child_lock(self, device_id: str, enabled: bool) -> ControlResult:
        return await self._control("child_lock", device_id, {"enabled": bool(enabled)})

    async def control_capability(
        self, device_id: str, code: str, value: Any
    ) -> ControlResult:
        body = await self._request(
            "POST",
            self.endpoints.url("control", device_id),
            payload={"code": code, "value": value},
        )
        data = self._unwrap(body)
        return ControlResult(
            success=True,
            message=str(data.get("message") or "ok"),
            command_id=str(data.get("cmd_id") or "") or None,
            raw=data,
        )

    # ---------- users ----------

    async def get_users(self, device_id: str) -> list[LockUser]:
        body = await self._request("GET", self.endpoints.url("users", device_id))
        users = self._parse_users(device_id, body)
        self._user_cache[device_id] = {u.user_id: u for u in users}
        return users

    def _parse_users(self, device_id: str, body: Any) -> list[LockUser]:
        items = self._listify(body, "users", "user_list", "list", "members")
        users: list[LockUser] = []
        for item in items:
            user = self._parse_user(item)
            if user:
                users.append(user)
        return users

    def _parse_user(self, item: dict) -> LockUser | None:
        user_id = item.get("user_id") or item.get("id") or item.get("userNo")
        if user_id is None:
            return None
        type_raw = item.get("type")
        if isinstance(type_raw, int):
            user_type = LockUserType.coerce(USER_TYPE_INT_MAP.get(type_raw, "unknown"))
        else:
            user_type = LockUserType.coerce(type_raw)
        pwd = item.get("pwd") or item.get("password")
        return LockUser(
            user_id=str(user_id),
            name=str(item.get("name") or item.get("nick_name") or f"{user_type.value}_{user_id}"),
            type=user_type,
            active=str(item.get("status", "1")).lower() not in ("0", "disabled", "false"),
            password_masked=self._mask(str(pwd)) if pwd else None,
            card_id=str(item.get("cardId") or item.get("keyNo") or "") or None,
            created_at=parse_ts(item.get("time") or item.get("create_time")),
            last_used=parse_ts(item.get("last_use_time")),
            raw=item,
        )

    @staticmethod
    def _mask(secret: str) -> str:
        if len(secret) <= 4:
            return "*" * len(secret)
        return f"{secret[:2]}…{secret[-2:]}"

    async def add_user(
        self,
        device_id: str,
        name: str,
        user_type: LockUserType,
        password: str | None = None,
        card_id: str | None = None,
    ) -> ControlResult:
        reverse = {v: k for k, v in USER_TYPE_INT_MAP.items()}
        payload: dict[str, Any] = {
            "name": name,
            "type": reverse.get(user_type, 0),
        }
        if password:
            payload["pwd"] = password
        if card_id:
            payload["cardId"] = card_id
        body = await self._request(
            "POST", self.endpoints.url("users_add", device_id), payload=payload
        )
        data = self._unwrap(body)
        return ControlResult(
            success=True,
            message="user added",
            command_id=str(data.get("user_id") or data.get("id") or "") or None,
            raw=data,
        )

    async def delete_user(self, device_id: str, user_id: str) -> ControlResult:
        body = await self._request(
            "POST",
            self.endpoints.url("users_delete", device_id),
            payload={"user": int(user_id) if str(user_id).isdigit() else user_id},
        )
        data = self._unwrap(body)
        self._user_cache.get(device_id, {}).pop(user_id, None)
        return ControlResult(success=True, message="user deleted", raw=data)

    async def rename_user(
        self, device_id: str, user_id: str, name: str
    ) -> ControlResult:
        body = await self._request(
            "POST",
            self.endpoints.url("users_update", device_id),
            payload={"user": user_id, "name": name},
        )
        data = self._unwrap(body)
        cached = self._user_cache.get(device_id, {}).get(user_id)
        if cached:
            cached.name = name
        return ControlResult(success=True, message="user renamed", raw=data)

    async def enroll_fingerprint(self, device_id: str, name: str) -> ControlResult:
        """Start fingerprint enrollment; user touches sensor multiple times."""
        body = await self._request(
            "POST",
            self.endpoints.url("fingerprint_enroll", device_id),
            payload={"name": name, "type": 1},
        )
        data = self._unwrap(body)
        return ControlResult(
            success=True,
            message="fingerprint enrollment started",
            command_id=str(data.get("session") or data.get("enroll_id") or "") or None,
            raw=data,
        )

    # ---------- history ----------

    async def get_history(
        self, device_id: str, limit: int = 50, offset: int = 0
    ) -> list[LockEvent]:
        params: dict[str, Any] = {"count": min(limit, 100)}
        if offset:
            params["offset"] = offset
        body = await self._request(
            "GET", self.endpoints.url("logs", device_id), params=params
        )
        events = self._parse_events(device_id, body)
        self._last_events[device_id] = events
        return events

    def _parse_events(self, device_id: str, body: Any) -> list[LockEvent]:
        items = self._listify(body, "logs", "events", "records", "history", "list")
        events: list[LockEvent] = []
        for item in items:
            ev = self._parse_event(device_id, item)
            if ev:
                events.append(ev)
        epoch = parse_ts(1)
        events.sort(key=lambda e: e.timestamp or epoch, reverse=True)
        return events

    def _parse_event(self, device_id: str, item: dict) -> LockEvent | None:
        try:
            method_raw = item.get("type")
            if isinstance(method_raw, int):
                method = UnlockMethod.coerce(
                    UNLOCK_METHOD_LABELS.get(method_raw, "unknown")
                )
            else:
                method = UnlockMethod.coerce(method_raw)
            status_raw = item.get("devStatus")
            if status_raw is None:
                status_raw = item.get("dev_status")
            if status_raw is None:
                status_raw = item.get("status")
            method_is_known = method is not UnlockMethod.UNKNOWN
            if isinstance(status_raw, int):
                if status_raw & DEVICE_STATUS_MASKS["tamper"]:
                    etype = LockEventType.TAMPER
                elif status_raw & DEVICE_STATUS_MASKS["door_open_long"]:
                    etype = LockEventType.DOOR_LEFT_OPEN
                elif status_raw & DEVICE_STATUS_MASKS["door_open"]:
                    etype = LockEventType.DOOR_OPEN
                elif status_raw & DEVICE_STATUS_MASKS["locked"]:
                    etype = LockEventType.LOCKED
                elif method_is_known and status_raw == 0:
                    etype = LockEventType.UNLOCKED
                elif method_is_known:
                    etype = LockEventType.UNLOCKED
                else:
                    etype = LockEventType.UNKNOWN
            else:
                text = str(status_raw or "").lower()
                type_text = "" if isinstance(method_raw, int) else str(method_raw or "").lower()
                combined = " ".join(
                    part
                    for part in (text, type_text, str(item.get("description") or ""), str(item.get("msg") or ""))
                    if part
                )
                if not combined:
                    etype = (
                        LockEventType.UNLOCKED
                        if method_is_known
                        else LockEventType.UNKNOWN
                    )
                elif "bell" in combined or "ring" in combined:
                    etype = LockEventType.BELL
                elif "battery" in combined:
                    etype = LockEventType.LOW_BATTERY
                else:
                    etype = LockEventType.coerce(combined)
            user_raw = item.get("user") or item.get("userName") or item.get("user_name")
            if isinstance(user_raw, dict):
                user_name = user_raw.get("name")
                user_id = user_raw.get("id")
            else:
                user_name = user_raw
                user_id = item.get("user_id")
            remote_raw = item.get("isRemote")
            if remote_raw is None:
                remote_raw = item.get("remotely")
            if remote_raw is None:
                remote_raw = item.get("remote")
            is_remote = bool(remote_raw)
            return LockEvent(
                type=etype,
                device_id=device_id,
                timestamp=parse_ts(item.get("time") or item.get("timestamp")),
                method=method,
                user=str(user_name) if user_name else None,
                user_id=str(user_id) if user_id not in (None, "") else None,
                remote=is_remote,
                photo_url=item.get("facePhotoUrl"),
                description=str(item.get("description") or item.get("msg") or ""),
                raw=item,
            )
        except Exception:  # noqa: BLE001 - malformed entries must not kill sync
            return None

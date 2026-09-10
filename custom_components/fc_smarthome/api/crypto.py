"""FC SmartHome cloud crypto layer.

Verified protocol (live-tested 2026-09-09):

- ``POST /v2/secure/getSecurityKey`` with form body ``secureData=<b64 blob>``:
  the blob is a persistent, per-install RSA artifact tied to the app's RSA-1024
  keypair. The server replies ``data = base64(RSA(negotiated_key_hex, app_pub))``.
  The negotiated key is a 32-char lowercase hex string; the session AES key is
  its first 16 chars used as ASCII (AES-128-ECB/PKCS7, hex I/O).
- ``POST /v2/login/loginPassword``: body = AES-ECB(negotiated[:16]) of
  ``{"password": md5(password), "phone": ..., "countrycode": int, ...}``;
  response is a quoted hex string, same key.
- Every authenticated API call afterwards uses the SAME negotiated key for the
  ``ts`` header and the request/response bodies (AES-128-ECB/PKCS7, hex I/O).
- ``POST /v2/login/loginToken`` renews the token with the negotiated key
  (body includes the old token).
- Envelope: ``{"result": 1|<code>, "message": ..., "data": ...}`` (1 = success).
- HTTP 690 = token expired; 672 = rate limit (wait ~3 min); 400 = crypto/format error.

The AES helper degrades gracefully: if ``pycryptodome`` is missing, the client
reports a clear error instead of silently sending plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

from .errors import FcError

try:  # pragma: no cover - optional at import time, checked at login time
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

APP_AES_BLOCK = 16


def require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise FcError(
            "pycryptodome is required for the FC cloud protocol (AES-ECB + RSA). "
            "Install it in the Home Assistant environment."
        )


def pkcs7_pad(data: bytes) -> bytes:
    pad = APP_AES_BLOCK - (len(data) % APP_AES_BLOCK)
    return data + bytes([pad]) * pad


def pkcs7_unpad(raw: bytes) -> bytes:
    if not raw:
        return raw
    pad = raw[-1]
    if 1 <= pad <= APP_AES_BLOCK and raw[-pad:] == bytes([pad]) * pad:
        return raw[:-pad]
    return raw


def aes_encrypt_hex(key: bytes, plaintext: str) -> str:
    """AES-128-ECB/PKCS7, hex output (vendor wire format)."""
    require_crypto()
    return AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(plaintext.encode())).hex()


def aes_decrypt_hex(key: bytes, hex_payload: str) -> str:
    require_crypto()
    raw = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(hex_payload))
    return pkcs7_unpad(raw).decode("utf-8", errors="replace")


def md5_hex(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def rsa_private_decrypt(pubkey_obj: Any, ciphertext: bytes) -> bytes | None:
    """Textbook PKCS#1 v1.5 private decrypt, returns the payload bytes."""
    require_crypto()
    c = int.from_bytes(ciphertext, "big")
    m_int = pow(c, pubkey_obj.d, pubkey_obj.n)
    raw = m_int.to_bytes(pubkey_obj.size_in_bytes(), "big")
    if raw[:2] in (b"\x00\x01", b"\x00\x02"):
        sep = raw.find(b"\x00", 2)
        if sep > 0:
            return raw[sep + 1:]
    return None


def load_private_key(b64_key: str):
    require_crypto()
    return RSA.import_key(base64.b64decode(b64_key))


def now_ms() -> int:
    return int(time.time() * 1000)

"""FC SmartHome API library package.

Self-contained (no Home Assistant imports) so the same code powers the
`fcctl` CLI and the HA custom component.
"""

from .client import FcClient
from .endpoints import DEFAULT_REGIONS, EndpointRegistry
from .errors import (
    FcApiError,
    FcAuthError,
    FcConnectionError,
    FcError,
    FcLocalError,
    FcNotVerifiedError,
)
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
)

__all__ = [
    "FcClient",
    "EndpointRegistry",
    "DEFAULT_REGIONS",
    "FcError",
    "FcApiError",
    "FcAuthError",
    "FcConnectionError",
    "FcLocalError",
    "FcNotVerifiedError",
    "ControlResult",
    "Device",
    "LockEvent",
    "LockEventType",
    "LockStatus",
    "LockUser",
    "LockUserType",
    "TokenPair",
    "UnlockMethod",
]

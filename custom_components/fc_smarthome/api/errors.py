"""Errors for the FC SmartHome API layer."""


class FcError(Exception):
    """Base error for all FC SmartHome failures."""


class FcConnectionError(FcError):
    """Could not reach the FC cloud."""


class FcAuthError(FcError):
    """Authentication or token refresh failed."""


class FcApiError(FcError):
    """The cloud rejected a request."""

    def __init__(self, message: str, code: int | None = None, payload: dict | None = None):
        super().__init__(message)
        self.code = code
        self.payload = payload or {}


class FcLocalError(FcError):
    """Local BLE transport failure."""


class FcNotVerifiedError(FcError):
    """A feature depends on endpoints not yet verified against the real app."""

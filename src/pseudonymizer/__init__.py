"""Keyed pseudonymization with HMAC-SHA256 tokens.

This library produces deterministic, domain-separated, keyed tokens that carry
their key id, enabling key rotation without breaking existing tokens.
Re-identification is possible only through an explicit vault that maps tokens
back to values.

Threat model (see ``docs/SECURITY.md`` for details):

Defended:
- Dictionary attack without the key: tokens are HMAC-SHA256, not a plain hash.
- Linkage across domains: the domain is part of the HMAC message.
- Key rotation: tokens include the key id; old tokens remain re-identifiable
  through the vault.
- Secrets never appear in ``repr``, events, or error messages.

Not defended:
- Brute force of low-entropy values by someone holding the key.
- Compromise of the vault.
- Frequency analysis (tokens are deterministic per domain/key/value).
- Pseudonymised data remains personal data under GDPR Recital 26.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
from collections.abc import Callable, Mapping
from typing import Literal, Protocol, TypeAlias

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ErrorCode: TypeAlias = Literal[
    "weak_key",
    "unknown_key",
    "invalid_key_id",
    "invalid_domain",
    "invalid_value",
    "value_too_large",
    "invalid_token",
    "no_vault",
    "not_in_vault",
    "vault_full",
]

_MESSAGES: dict[ErrorCode, str] = {
    "weak_key": "key must be at least 32 bytes long",
    "unknown_key": "key id is not present in the key set",
    "invalid_key_id": "key id must match ^[a-z0-9]{1,8}$",
    "invalid_domain": "domain must match ^[a-z0-9_]{1,32}$",
    "invalid_value": "value must be a non-empty string of at most 4096 characters",
    "value_too_large": "value exceeds the 4096 character limit",
    "invalid_token": "token must match ^pz_([a-z0-9]{1,8})_([a-z2-7]{26})$",
    "no_vault": "reidentification requires a vault",
    "not_in_vault": "token is not present in the vault",
    "vault_full": "vault has reached its maximum capacity",
}

_KEY_ID_RE = re.compile(r"^[a-z0-9]{1,8}$")
_DOMAIN_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_TOKEN_RE = re.compile(r"^pz_([a-z0-9]{1,8})_([a-z2-7]{26})$")
_MIN_KEY_BYTES = 32
_MAX_VALUE_CHARS = 4096


class PseudoError(Exception):
    """Base error for the pseudonymizer package.

    The ``code`` attribute is a stable machine-readable identifier; messages
    are constant, never longer than 200 characters, and never contain values,
    tokens, or key material.
    """

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")


class Vault(Protocol):
    """Protocol for token-to-value storage used by :class:`Pseudonymizer`.

    Implementations may be in-memory, on disk, or remote. ``put`` must be
    idempotent for an existing token; ``get`` returns ``None`` when a token is
    unknown.
    """

    def put(self, token: str, value: str) -> None:
        """Store a token/value pair."""
        ...

    def get(self, token: str) -> str | None:
        """Return the value for ``token`` or ``None``."""
        ...


class InMemoryVault:
    """A bounded in-memory :class:`Vault`.

    New distinct entries beyond ``max_entries`` raise
    :class:`PseudoError` with code ``'vault_full'``. Re-putting an existing
    token is a no-op.
    """

    def __init__(self, max_entries: int = 1_000_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._store: dict[str, str] = {}
        self._lock = __import__("threading").Lock()

    def put(self, token: str, value: str) -> None:
        with self._lock:
            if token in self._store:
                return
            if len(self._store) >= self._max_entries:
                raise PseudoError("vault_full")
            self._store[token] = value

    def get(self, token: str) -> str | None:
        with self._lock:
            return self._store.get(token)


class Pseudonymizer:
    """Pseudonymizes strings into keyed, domain-separated HMAC-SHA256 tokens.

    Args:
        keys: Mapping of key id to secret key bytes. Every key must be at least
            32 bytes long; every key id must match ``^[a-z0-9]{1,8}$``.
        active_key_id: The key id used when ``key_id`` is not given to
            :meth:`pseudonymize`. Must be present in ``keys``.
        vault: Optional :class:`Vault` used to store mappings for
            :meth:`reidentify`. If present, every :meth:`pseudonymize` call
            writes the token/value pair.
        on_event: Optional callback invoked after a successful pseudonymization
            with a dictionary containing ``event``, ``domain``, and ``key_id``
            (never the value or token).
    """

    def __init__(
        self,
        keys: Mapping[str, bytes],
        active_key_id: str,
        *,
        vault: Vault | None = None,
        on_event: Callable[[dict[str, str]], None] | None = None,
    ) -> None:
        self._keys = dict(keys)
        self._active_key_id = active_key_id
        self._vault = vault
        self._on_event = on_event

        for kid in self._keys:
            if not _KEY_ID_RE.fullmatch(kid):
                raise PseudoError("invalid_key_id")
        if not _KEY_ID_RE.fullmatch(active_key_id):
            raise PseudoError("invalid_key_id")
        if active_key_id not in self._keys:
            raise PseudoError("unknown_key")
        for key in self._keys.values():
            if len(key) < _MIN_KEY_BYTES:
                raise PseudoError("weak_key")

    def pseudonymize(self, value: str, *, domain: str, key_id: str | None = None) -> str:
        """Return a deterministic token for ``value`` in ``domain``.

        If ``key_id`` is ``None`` the active key id is used; otherwise the
        specified key is used (allowing lookups with an older key). The value
        is used exactly as given; callers are responsible for normalisation.
        If a vault is configured, the token/value pair is written on every call.

        Raises:
            PseudoError: if the value, domain, or key id is invalid, or if the
                vault write fails.
        """
        if not isinstance(value, str):
            raise PseudoError("invalid_value")
        if len(value) < 1:
            raise PseudoError("invalid_value")
        if len(value) > _MAX_VALUE_CHARS:
            raise PseudoError("value_too_large")
        if not _DOMAIN_RE.fullmatch(domain):
            raise PseudoError("invalid_domain")

        selected_key_id = self._active_key_id if key_id is None else key_id
        if not _KEY_ID_RE.fullmatch(selected_key_id):
            raise PseudoError("invalid_key_id")
        if selected_key_id not in self._keys:
            raise PseudoError("unknown_key")
        key = self._keys[selected_key_id]

        message = domain.encode("ascii") + b"\x00" + value.encode("utf-8")
        digest = hmac.new(key, message, hashlib.sha256).digest()
        token_body = base64.b32encode(digest).decode("ascii").lower()[:26]
        token = f"pz_{selected_key_id}_{token_body}"

        if self._vault is not None:
            self._vault.put(token, value)
        if self._on_event is not None:
            self._on_event({"event": "pseudonymized", "domain": domain, "key_id": selected_key_id})
        return token

    def pseudonymize_record(
        self, record: Mapping[str, object], fields: Mapping[str, str]
    ) -> dict[str, object]:
        """Pseudonymize selected fields of a record.

        ``fields`` maps a record key to its domain. Keys present in ``fields``
        must have string values in ``record``; other keys are copied unchanged.
        If a key in ``fields`` is absent from ``record``, it is left absent in
        the result.
        """
        result: dict[str, object] = {}
        for key, value in record.items():
            if key in fields:
                if not isinstance(value, str):
                    raise PseudoError("invalid_value")
                result[key] = self.pseudonymize(value, domain=fields[key])
            else:
                result[key] = value
        return result

    def reidentify(self, token: str) -> str:
        """Return the original value for a token.

        Requires a vault; otherwise raises :class:`PseudoError` with
        ``'no_vault'``. Well-formed tokens not present in the vault raise
        ``'not_in_vault'``.
        """
        if self._vault is None:
            raise PseudoError("no_vault")
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise PseudoError("invalid_token")
        value = self._vault.get(token)
        if value is None:
            raise PseudoError("not_in_vault")
        return value

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(active_key_id={self._active_key_id!r}, "
            f"keys=<redacted>, vault={'set' if self._vault is not None else 'None'})"
        )


__all__ = [
    "InMemoryVault",
    "PseudoError",
    "Pseudonymizer",
    "Vault",
    "__version__",
]

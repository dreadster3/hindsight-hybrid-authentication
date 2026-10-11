"""Hybrid tenant extension for Hindsight: static API keys and OAuth2/OIDC bearer tokens.

One ``TenantExtension`` accepts every credential shape a deployment needs — the
env-declared static API keys used by headless clients, OAuth2/OIDC bearer
tokens (authentik) verified locally against a cached JWKS, and opaque bearer
tokens validated by RFC 7662 introspection — and resolves each to a **per-user
PostgreSQL schema** (``{prefix}_{user_id}``), provisioned lazily on first
access. Isolation therefore sits below the bank mechanism: a client cannot
reach another user's banks by guessing a bank id, because the schema is the
boundary.

Three lanes share one resolver. Lane A matches env-declared static API keys in
constant time; lane B verifies OAuth2/OIDC (authentik) JWT bearer tokens
locally against a cached JWKS; lane C validates any other (opaque) bearer token
against the configured introspection endpoint. Lane routing is by credential
shape: a static key never contains ".", a JWT always has exactly two, and
anything else is opaque. A credential that fails its lane is refused — there
is no fallback to another lane or to unauthenticated.

Configuration via environment variables, following the loader convention
(``HINDSIGHT_API_TENANT_<NAME>`` -> ``config["<name>"]``)::

    HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_hybrid_tenant:HybridTenantExtension
    HINDSIGHT_API_TENANT_USERS=user1:key1,user1:key2,user2:key3   # required, comma-separated user:key pairs
    HINDSIGHT_API_TENANT_SCHEMA_PREFIX=user                      # optional, default "user"
    HINDSIGHT_API_TENANT_OAUTH_ENABLED=false                     # optional, default false
    HINDSIGHT_API_TENANT_OAUTH_ISSUER=...                        # required when OAuth is enabled (https)
    HINDSIGHT_API_TENANT_OAUTH_AUDIENCE / _JWKS_URL / _GROUPS_ALLOWLIST  # optional
    HINDSIGHT_API_TENANT_OAUTH_CLIENT_URL / _CLIENT_ID / _CLIENT_SECRET  # all three, or none

The introspection lane activates only when all three ``..._OAUTH_CLIENT_*``
variables are set; a partial trio fails startup naming the missing field. There
is no separate enable flag.

Configuration is validated in ``__init__`` (the loader turns a failure into a
hard load failure); when OAuth is enabled, ``on_startup`` warms the JWKS cache
and fails startup if the issuer is unreachable — an unverifiable token is never
accepted, so a misconfigured lane fails loudly rather than degrading. The
introspection lane makes no startup call (there is no credential to probe with)
and resolves lazily on the first opaque token.

Provenance: the static-key lane is ported from
``hindsight-extensions/static-keys-tenant``; the JWKS fetch/cache/kid-refresh
pattern from ``hindsight-extensions/supabase-tenant`` (vectorize-io/hindsight @
a9eeed77f9bce99d8f97d39a30d3281747300824, MIT).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import jwt as pyjwt
from hindsight_api.extensions.tenant import (
    AuthenticationError,
    Tenant,
    TenantContext,
    TenantExtension,
)
from hindsight_api.models import RequestContext
from jwt import PyJWK

logger = logging.getLogger(__name__)

__all__ = ["HybridTenantExtension"]

# Schema prefix must be a valid Postgres identifier component (letters, digits, underscores).
# \Z rather than $: $ also matches just before a trailing "\n", so an
# operator-supplied "user\n" would pass validation and produce a schema name
# Postgres would treat as a different identifier.
_SCHEMA_PREFIX_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*\Z")

# User IDs appear in schema names, so they must be safe as a Postgres identifier
# component: start with a letter/underscore, then letters/digits/underscore/dash.
# Dashes are normalized to underscores and the whole id is lowercased before
# building the schema name (Postgres folds unquoted identifiers to lowercase).
# \Z, not $, so a signed claim ending in "\n" cannot slip through as "x\n".
_USER_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\Z")

# PostgreSQL truncates identifiers to NAMEDATALEN (63) bytes. An operator can
# configure two distinct user ids that differ only past that boundary; both
# would land on the same truncated schema and silently share memories. Reject
# at init rather than discovering the collision at runtime.
_MAX_SCHEMA_LENGTH = 63

# A short key is a guessable key. Reject at startup so an operator cannot ship a
# per-user isolation boundary whose front door is a five-character secret.
_MIN_KEY_LENGTH = 16

# Truthy/falsy spellings accepted for boolean config values. Anything else is a
# typo, and a typo in a security switch must fail startup, not silently disable
# the feature it names.
_TRUE_VALUES = ("true", "1", "yes", "on")
_FALSE_VALUES = ("", "false", "0", "no", "off")

# OAuth/JWKS lane. RS256 is the only asymmetric algorithm authentik is
# configured to sign with; restricting decode to it also blocks an "alg"
# downgrade to a symmetric key. The 10 s leeway absorbs normal clock skew
# between the issuer and this pod (PyJWT's default is zero).
JWT_ALGORITHM = "RS256"
JWT_LEEWAY_SECONDS = 10
JWKS_CACHE_TTL_SECONDS = 600
JWKS_TIMEOUT_SECONDS = 10.0
MAX_JWKS_BYTES = 64 * 1024

# Minimum age of the JWKS cache before a kid miss may force a refresh. A token
# flood carrying garbage kids would otherwise trigger one upstream fetch per
# request; a key rotated within this window is picked up by the TTL refresh.
JWKS_MIN_REFRESH_INTERVAL_SECONDS = 30

# Shortest credential accepted for the JWT lane (JWTs are typically 100+ chars).
MIN_TOKEN_LENGTH = 20

# A plaintext-HTTP issuer is only tolerated on loopback, where there is no
# network segment to intercept (dev sidecar / local tests).
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _derive_key_id(api_key: str) -> str:
    """Derive a stable, non-secret identifier for an API key.

    ``RequestContext.api_key_id`` is documented as identifying *the key* (and
    multiple keys per user is a selling point of this extension), but metering
    must never log or store the key itself. A truncated sha256 digest is
    deterministic, short, and safe to paste into an issue or a chat — it is
    also the name used to refer to a key in configuration error messages.
    """
    return hashlib.sha256(api_key.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def _encode_key(api_key: str) -> bytes:
    """Encode a configured key the same way bearer-token bytes are recovered.

    Header values arrive latin-1-decoded and are re-encoded with
    "surrogateescape" (see _resolve), so the same codec here makes the two
    sides byte-comparable.
    """
    return api_key.encode("utf-8", "surrogateescape")


def _is_jwt_shaped(token: str) -> bool:
    """A JWT is three base64url segments — exactly two ``.`` separators.

    Static keys are rejected at startup if they contain ``.``, so the two
    credential shapes cannot overlap and routing by shape is unambiguous.
    """
    return token.count(".") == 2


def _parse_csv(raw: str) -> list[str]:
    """Split a comma-separated config value, dropping blank entries."""
    return [part.strip() for part in raw.split(",") if part.strip()]


def _monotonic() -> float:
    """Monotonic clock, indirected so tests can drive JWKS cache expiry."""
    return time.monotonic()


def _require_secure_url(url: str, config_name: str) -> None:
    """Reject a non-HTTPS OAuth URL unless it points at loopback.

    A plaintext issuer cannot be trusted to sign the tokens this extension
    accepts; loopback is exempt because a sidecar/dev issuer has no network
    path to intercept.
    """
    parts = urlsplit(url)
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and (parts.hostname or "") in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        f"{config_name} must be an https URL (got scheme '{parts.scheme or '<none>'}'): "
        "a non-HTTPS issuer cannot be trusted to sign tokens."
    )


@dataclass(frozen=True)
class _KeyEntry:
    """A configured API key's mapping: the owning user and its isolated schema."""

    user_id: str
    schema_name: str
    key_id: str
    # The key pre-encoded for compare_digest (utf-8/surrogateescape): computed
    # once at init so authenticate() never re-encodes every configured key on
    # every request.
    key_bytes: bytes


class _JwksCache:
    """Cached JWKS public keys, keyed by ``kid``.

    ``warm`` replaces the cache wholesale. ``signing_key`` refetches when the
    cache is older than ``ttl`` — matching the 10-minute cache the issuer
    itself serves, so rotation is picked up — and refreshes once on a ``kid``
    miss (the key may have rotated since the last fetch) before giving up. A
    second miss is an authentication failure, not a reason to trust the token.
    """

    def __init__(
        self,
        fetch: Callable[[], Awaitable[dict[str, PyJWK]]],
        *,
        ttl: float = JWKS_CACHE_TTL_SECONDS,
    ) -> None:
        self._fetch = fetch
        self._ttl = ttl
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at = 0.0

    async def warm(self) -> dict[str, PyJWK]:
        """Fetch keys, replacing the cache. Propagates fetch failures."""
        keys = await self._fetch()
        self._keys = keys
        self._fetched_at = _monotonic()
        return keys

    async def signing_key(self, kid: str) -> PyJWK:
        """Return the key for ``kid``, refreshing as needed.

        A fetch failure here becomes ``AuthenticationError``: a 401 the client
        can retry, never a 500 leaking the upstream error.
        """
        try:
            # An empty key set also refetches here, bypassing the TTL: with no
            # keys nothing can authenticate, so trade a burst of fetches during
            # an issuer outage for fast recovery once keys reappear, rather than
            # serving the outage for a full TTL.
            if not self._keys or _monotonic() - self._fetched_at > self._ttl:
                await self.warm()
        except Exception as e:
            raise AuthenticationError("Unable to fetch identity provider signing keys") from e

        if kid in self._keys:
            return self._keys[kid]

        # kid miss — the issuer may have rotated keys since the last fetch, so
        # refresh once and retry. Only when the cache is not already fresh: a
        # token flood bearing garbage kids must not hammer the issuer's JWKS
        # endpoint, and a just-fetched JWKS cannot contain the key either.
        if _monotonic() - self._fetched_at < JWKS_MIN_REFRESH_INTERVAL_SECONDS:
            raise AuthenticationError("Unable to find signing key for token")
        logger.debug("Signing key %s not cached, refreshing JWKS for possible rotation", kid)
        try:
            await self.warm()
        except Exception as e:
            raise AuthenticationError("Unable to fetch identity provider signing keys") from e
        if kid in self._keys:
            return self._keys[kid]

        raise AuthenticationError("Unable to find signing key for token")


class HybridTenantExtension(TenantExtension):
    """TenantExtension mapping credentials to per-user PostgreSQL schemas.

    Static credentials are declared in ``HINDSIGHT_API_TENANT_USERS`` as
    ``user_id:api_key`` pairs; multiple keys may map to the same user. An
    authenticated request is mapped to schema ``{prefix}_{user_id}`` (user ids
    are lowercased, dashes normalized to underscores), provisioned lazily on
    first access.

    Example:
        HINDSIGHT_API_TENANT_USERS=pi:key-a,pi:key-b,openwebui:key-c
        HINDSIGHT_API_TENANT_SCHEMA_PREFIX=user

        User "pi" gets schema "user_pi" (either key); user "openwebui" gets
        schema "user_openwebui".
    """

    def __init__(self, config: dict[str, str]) -> None:
        """Parse and validate configuration. Raises ValueError on misconfiguration.

        Args:
            config: Configuration values from environment (keys lowercased,
                prefix stripped by the extension loader).

        Raises:
            ValueError: If required configuration is missing or invalid. Error
                messages never echo key material — they name a key by index and
                by its derived ``key_id``.
        """
        super().__init__(config)

        # PostgreSQL folds unquoted identifiers to lowercase at query time,
        # while the migration path creates the schema quoted. A mixed-case
        # prefix like "My_user" would therefore be created as "My_user" and
        # looked up as "my_user" — every query missing. Fold it once here, then
        # validate the normalized form that will actually be used.
        self.schema_prefix = config.get("schema_prefix", "user").lower()

        # OAuth lane config, parsed and validated here so a misconfigured lane
        # fails the load rather than the first request; on_startup then warms
        # the JWKS cache. See the oauth_enabled guard at the end of __init__.
        self.oauth_issuer = config.get("oauth_issuer", "")
        self.oauth_audience = config.get("oauth_audience", "")
        self.oauth_jwks_url = config.get("oauth_jwks_url", "")
        if not self.oauth_jwks_url and self.oauth_issuer:
            # authentik publishes per-application JWKS at {issuer}/jwks/.
            self.oauth_jwks_url = f"{self.oauth_issuer.rstrip('/')}/jwks/"
        self.oauth_groups_allowlist = _parse_csv(config.get("oauth_groups_allowlist", ""))

        # Token introspection lane (RFC 7662). All three values or none: there is
        # no separate enable flag, because a partial trio is always a
        # misconfiguration — a URL with no credentials, or credentials with no
        # endpoint. The error names the missing field and never echoes a value
        # (the client secret is one of the three).
        self.oauth_client_url = config.get("oauth_client_url", "").strip()
        self.oauth_client_id = config.get("oauth_client_id", "").strip()
        self.oauth_client_secret = config.get("oauth_client_secret", "").strip()
        introspection_fields = {
            "HINDSIGHT_API_TENANT_OAUTH_CLIENT_URL": self.oauth_client_url,
            "HINDSIGHT_API_TENANT_OAUTH_CLIENT_ID": self.oauth_client_id,
            "HINDSIGHT_API_TENANT_OAUTH_CLIENT_SECRET": self.oauth_client_secret,
        }
        introspection_missing = [name for name, value in introspection_fields.items() if not value]
        self.oauth_introspection_enabled = not introspection_missing
        if introspection_missing and len(introspection_missing) < len(introspection_fields):
            raise ValueError(
                "Token introspection is partially configured. All three of "
                + ", ".join(introspection_fields)
                + " are required together; missing "
                + ", ".join(introspection_missing)
                + "."
            )
        oauth_enabled_raw = config.get("oauth_enabled", "").strip().lower()
        if oauth_enabled_raw in _TRUE_VALUES:
            self.oauth_enabled = True
        elif oauth_enabled_raw in _FALSE_VALUES:
            self.oauth_enabled = False
        else:
            # The value is not echoed: an operator who pastes this error into a
            # chat should not have to notice that they pasted a secret into the
            # wrong variable.
            raise ValueError(
                "Invalid HINDSIGHT_API_TENANT_OAUTH_ENABLED value. Expected one of: "
                + ", ".join(repr(v) if v else "''" for v in (*_TRUE_VALUES, *_FALSE_VALUES))
                + "."
            )

        if not _SCHEMA_PREFIX_RE.match(self.schema_prefix):
            raise ValueError(
                f"Invalid schema_prefix '{self.schema_prefix}'. "
                "Must be a valid Postgres identifier (letters, digits, underscores, "
                "starting with a letter or underscore)."
            )

        # Parse users into an API-key -> _KeyEntry map. Multiple keys may map
        # to the same user. Also keep a per-user map so list_tenants() can
        # return every configured tenant, even before any authentication has
        # happened.
        self._key_to_user: dict[str, _KeyEntry] = {}
        self._users: dict[str, str] = {}  # user_id -> schema_name

        users_raw = config.get("users", "")
        if not users_raw.strip():
            raise ValueError(
                "HINDSIGHT_API_TENANT_USERS is required when using HybridTenantExtension. "
                'Format: "user1:key1,user2:key2"'
            )

        for index, entry in enumerate(users_raw.split(",")):
            entry = entry.strip()
            if not entry:
                continue
            # Error messages below must never quote `entry` or `api_key`: an
            # operator who misconfigures HINDSIGHT_API_TENANT_USERS pastes the
            # startup error into an issue or a chat, and would disclose the
            # key. Report the entry's index (and the user id, once it is known
            # and validated) instead — the key is named by its sha256-derived
            # key_id, see _derive_key_id.
            if ":" not in entry:
                raise ValueError(
                    f'Invalid HINDSIGHT_API_TENANT_USERS entry at index {index}. Expected format "user_id:api_key".'
                )
            user_id, api_key = entry.split(":", 1)
            user_id = user_id.strip()
            api_key = api_key.strip()
            if not user_id or not api_key:
                raise ValueError(
                    f"Invalid HINDSIGHT_API_TENANT_USERS entry at index {index}: "
                    + ("user_id" if not user_id else "api_key")
                    + " must be non-empty."
                )
            if not _USER_ID_RE.match(user_id):
                # Index only: an inverted pair ("SECRET:owner") puts key material
                # in the user_id slot, and the operator pasting this error would
                # be the one leaking it.
                raise ValueError(
                    f"Invalid user_id at index {index} in HINDSIGHT_API_TENANT_USERS. "
                    "Must start with a letter or underscore, then letters, digits, underscores or dashes."
                )

            key_id = _derive_key_id(api_key)
            # A key that is not ASCII cannot round-trip through the Authorization
            # header unchanged, and a key containing "." would be indistinguishable
            # from a JWT when routing by credential shape — reject both at startup
            # rather than letting them resolve to "Invalid API key" forever.
            if not api_key.isascii():
                raise ValueError(
                    f"Invalid API key (key_id '{key_id}') at index {index} in HINDSIGHT_API_TENANT_USERS: "
                    "keys must be ASCII."
                )
            if "." in api_key:
                raise ValueError(
                    f"Invalid API key (key_id '{key_id}') at index {index} in HINDSIGHT_API_TENANT_USERS: "
                    "'.' is not allowed, because keys containing '.' are routed as JWT-shaped tokens."
                )
            if len(api_key) < _MIN_KEY_LENGTH:
                raise ValueError(
                    f"Invalid API key (key_id '{key_id}') at index {index} in HINDSIGHT_API_TENANT_USERS: "
                    f"keys must be at least {_MIN_KEY_LENGTH} characters."
                )

            # Normalize the user id to lowercase. PostgreSQL folds unquoted
            # identifiers to lowercase at query time (the runtime's fq_table()
            # does not quote the schema, while the migration path creates it
            # quoted), so a mixed-case id like "Rafael" and its lowercase twin
            # "rafael" would collapse to the same schema at runtime — either
            # breaking every query or, worse, silently sharing one schema
            # between two users. Lowercasing makes case variants the same
            # canonical user (consistent with Postgres folding), so they merge
            # onto one schema rather than drifting apart.
            user_id = user_id.lower()
            schema_name = self._schema_name_for(user_id)

            # Each schema must be a unique isolation boundary. Two distinct
            # users whose ids differ in non-case ways yet normalize to the same
            # schema (e.g. "jane-doe" and "jane_doe"), or that collide past the
            # 63-byte identifier limit, would silently read and write each
            # other's memories — reject loudly instead of breaking the
            # extension's isolation guarantee.
            if len(schema_name) > _MAX_SCHEMA_LENGTH:
                raise ValueError(
                    f"Schema name '{schema_name}' for user_id '{user_id}' exceeds the PostgreSQL "
                    f"identifier limit of {_MAX_SCHEMA_LENGTH} characters."
                )
            claimed_by = next(
                (uid for uid, s in self._users.items() if uid != user_id and s == schema_name), None
            )
            if claimed_by is not None:
                raise ValueError(
                    f"Schema name '{schema_name}' for user_id '{user_id}' is already claimed by "
                    f"user_id '{claimed_by}'. Two distinct users cannot share one schema."
                )
            if api_key in self._key_to_user:
                raise ValueError(
                    f"Duplicate API key (key_id '{key_id}') in HINDSIGHT_API_TENANT_USERS "
                    f"is configured for both user_id '{self._key_to_user[api_key].user_id}' "
                    f"and user_id '{user_id}'. Each key must be unique."
                )

            self._key_to_user[api_key] = _KeyEntry(
                user_id=user_id,
                schema_name=schema_name,
                key_id=key_id,
                key_bytes=_encode_key(api_key),
            )
            self._users[user_id] = schema_name

        if not self._key_to_user:
            raise ValueError(
                "HINDSIGHT_API_TENANT_USERS contained no valid 'user_id:api_key' pairs. "
                'Format: "user1:key1,user2:key2"'
            )

        # Track initialized schemas to avoid redundant migrations. Two
        # concurrent first requests for the same user would both see the
        # schema missing and both run migrations without the per-schema lock
        # below serializing them.
        self._initialized_schemas: set[str] = set()
        self._schema_locks: dict[str, asyncio.Lock] = {}

        # Users that have authenticated at least once, user_id -> schema_name.
        # Static users are known at startup, but OAuth users are not (their
        # tokens are minted by the IdP, not by config); list_tenants() unions
        # this with the static set so the worker consolidates every schema that
        # has ever been used.
        self._seen_users: dict[str, str] = {}

        # OAuth lane startup validation. Configuration is checked here so a
        # misconfigured lane fails the load, not the first request; reachability
        # is checked in on_startup, where a network call is allowed.
        if self.oauth_enabled:
            if not self.oauth_issuer:
                raise ValueError(
                    "HINDSIGHT_API_TENANT_OAUTH_ISSUER is required when HINDSIGHT_API_TENANT_OAUTH_ENABLED=true. "
                    "Set it to your OIDC issuer URL (e.g. https://authentik.example/application/o/hindsight-mcp)."
                )
            _require_secure_url(self.oauth_issuer, "HINDSIGHT_API_TENANT_OAUTH_ISSUER")
            _require_secure_url(self.oauth_jwks_url, "HINDSIGHT_API_TENANT_OAUTH_JWKS_URL")

        # Introspection credentials travel over the network, so the endpoint
        # gets the same HTTPS-only rule as the issuer/JWKS above.
        if self.oauth_introspection_enabled:
            _require_secure_url(
                self.oauth_client_url,
                "HINDSIGHT_API_TENANT_OAUTH_CLIENT_URL",
            )

        # Lane B's cached JWKS keys, constructed unconditionally so authenticate()
        # has no lazy-init branch to race on. Lane A never touches it.
        self._jwks = _JwksCache(self._fetch_jwks)

        # Reusable HTTP client for JWKS fetches, created in on_startup. Startup,
        # shutdown and every authenticate() run on the server's event loop, which
        # the client binds to.
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self, context: RequestContext) -> TenantContext:
        """Authenticate an HTTP request and return its tenant context.

        Args:
            context: Request context whose ``api_key`` is the bearer token.

        Returns:
            TenantContext with schema_name set to ``{prefix}_{user_id}``.

        Raises:
            AuthenticationError: If the credential is missing or unknown.
        """
        return await self._resolve(context)

    async def authenticate_mcp(self, context: RequestContext) -> TenantContext:
        """Authenticate an MCP request — same isolation as HTTP, no bypass.

        Implemented explicitly (rather than inheriting the base class's
        delegate-to-authenticate) so both transports route through one
        ``_resolve`` helper and cannot drift apart.
        """
        return await self._resolve(context)

    async def _resolve(self, context: RequestContext) -> TenantContext:
        """Resolve a credential to a provisioned tenant schema. Shared by every lane.

        Lane routing is by credential shape: a static key is matched exactly
        (constant time) against the configured keys; a JWT-shaped token goes to
        the JWKS lane and is verified there — refused with "Unknown credential"
        when that lane is disabled — rather than being mistaken for a key; any
        other token goes to the introspection lane when configured. Every bearer
        lane resolves to a user id and then flows through one mapping/schema
        path, so the lanes cannot drift apart.
        """
        key = context.api_key
        if not key:
            raise AuthenticationError("Missing Authorization header. Expected: Bearer <api_key>")

        # Lane routing is by credential shape, not by config. Static keys are
        # rejected at startup if they contain ".", so a JWT-shaped token cannot
        # be a configured key. No lane falls back to another, nor to
        # unauthenticated: a credential that fails its lane is a 401.
        entry = self._match_static_key(key)
        if entry is not None:
            user_id, schema_name, key_id = entry.user_id, entry.schema_name, entry.key_id
        else:
            user_id = await self._resolve_bearer_user_id(key)
            schema_name = self._schema_name_for(user_id)
            # The claim is attacker-controlled until the token verifies, and
            # even then it must not name a schema outside the tenant namespace
            # (invalid identifier character) or one Postgres would truncate into
            # a neighbour's. Same rules lane A enforces at startup.
            if not _SCHEMA_PREFIX_RE.match(schema_name) or len(schema_name) > _MAX_SCHEMA_LENGTH:
                raise AuthenticationError("Token subject cannot be mapped to a valid tenant schema")
            key_id = None

        await self._ensure_schema(schema_name)

        # Usage metering: the HTTP/MCP layers read these fields back after auth
        # to attribute operations to a tenant / API key. api_key_id identifies
        # *the key* (see RequestContext), not the user — with multiple keys per
        # user it must distinguish which key authenticated. It is the derived,
        # non-secret key_id, never the key itself. Bearer-lane credentials (OAuth
        # JWT, introspection) are not static keys, so they leave api_key_id unset.
        context.tenant_id = user_id
        if key_id is not None:
            context.api_key_id = key_id
        self._seen_users.setdefault(user_id, schema_name)

        return TenantContext(schema_name=schema_name)

    async def _resolve_bearer_user_id(self, token: str) -> str:
        """Route a non-static bearer token to its lane and return the resolved user id.

        A JWT-shaped token (exactly two ``.``) always goes to the JWKS lane; any
        other non-empty token is opaque and goes to the introspection lane when
        it is configured. Unknown shapes/lanes are refused, never guessed.
        """
        if _is_jwt_shaped(token):
            if not self.oauth_enabled:
                raise AuthenticationError("Unknown credential")
            return await self._verify_oauth_token(token)
        if self.oauth_introspection_enabled:
            return await self._introspect_token(token)
        raise AuthenticationError("Invalid API key")

    def _match_static_key(self, key: str) -> _KeyEntry | None:
        """Return the entry whose configured key matches ``key``, or None.

        Compares with hmac.compare_digest over every configured key — never an
        exact-equality fast path, which would let unknown keys skip the
        constant-time loop entirely and leak key size/shape via timing. The
        number of comparisons still depends on the matching key's position (we
        stop at the first match); that reveals nothing to an attacker holding
        only invalid keys, and an attacker holding a valid key already knows
        where it sits in the list. Configured keys are pre-encoded to bytes at
        init (_KeyEntry.key_bytes), so each request only encodes the incoming
        key. Header values arrive latin-1-decoded, so encode with
        "surrogateescape" so any byte sequence round-trips losslessly instead of
        raising TypeError (a 500, not a 401) for non-ASCII bearer tokens.
        """
        key_bytes = _encode_key(key)
        for entry in self._key_to_user.values():
            if hmac.compare_digest(key_bytes, entry.key_bytes):
                return entry
        return None

    # ------------------------------------------------------------------
    # OAuth / JWKS lane
    # ------------------------------------------------------------------

    async def on_startup(self) -> None:
        """Warm the JWKS cache and fail startup if the OAuth lane is unusable.

        With no network-backed lane configured this is a no-op (static keys need
        no network). With the JWKS lane enabled the issuer must be reachable
        *now*: an extension that starts without keys would either accept tokens
        it cannot verify or reject every one — both are worse than failing the
        deploy. The introspection lane is deliberately not probed here: unlike
        JWKS there is no credential to probe with, so it resolves lazily on the
        first opaque token.
        """
        if not self.oauth_enabled and not self.oauth_introspection_enabled:
            return
        if self.oauth_enabled:
            logger.info("Initializing hybrid tenant extension (OAuth lane enabled)")
            logger.info("OAuth issuer: %s", self.oauth_issuer)
        if self.oauth_introspection_enabled:
            logger.info("Initializing hybrid tenant extension (token introspection lane enabled)")
            logger.info("Introspection endpoint: %s", self.oauth_client_url)
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(JWKS_TIMEOUT_SECONDS, connect=JWKS_TIMEOUT_SECONDS)
            )
        if not self.oauth_enabled:
            # Introspection-only: no reachability probe (see docstring above).
            return
        try:
            keys = await self._jwks.warm()
        except Exception as e:
            await self._http.aclose()
            self._http = None
            # The URL is config, not secret, and the transport error never
            # carries the JWKS body or any token.
            raise RuntimeError(
                f"OAuth is enabled but the JWKS endpoint {self.oauth_jwks_url} is unreachable: {e!s}"
            ) from e
        logger.info("JWKS loaded with %d key(s)", len(keys))

    async def on_shutdown(self) -> None:
        """Close the shared HTTP client, if one was created."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _fetch_jwks(self) -> dict[str, PyJWK]:
        """Fetch and parse the issuer's JWKS document into ``kid`` -> PyJWK.

        Streams the response so a broken or hostile endpoint cannot exhaust
        memory with an oversized body. Raises on transport/HTTP/JSON failure;
        callers decide whether that fails startup or a single authentication.
        """
        if self._http is None:
            raise RuntimeError("HTTP client not initialized")
        async with self._http.stream("GET", self.oauth_jwks_url) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_JWKS_BYTES:
                    raise ValueError(f"JWKS document exceeds {MAX_JWKS_BYTES} bytes")
        data = json.loads(bytes(body))
        if not isinstance(data, dict):
            raise ValueError("JWKS endpoint did not return a JSON object")
        keys: dict[str, PyJWK] = {}
        for key_data in data.get("keys", []):
            kid = key_data.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = PyJWK(key_data)
            except pyjwt.PyJWKError:
                logger.debug("Skipping unparsable JWKS key: kid=%s", kid)
        return keys

    async def _verify_oauth_token(self, token: str) -> str:
        """Verify an OAuth2/OIDC bearer token and return its user id.

        RS256 only — restricting ``algorithms`` at decode blocks an ``alg``
        downgrade to a symmetric key. ``iss`` must equal the configured issuer;
        ``aud`` is enforced only when configured. PyJWT's own exp/nbf/iat checks
        run with a small clock-skew leeway. Never logs or echoes the token.
        """
        if len(token) < MIN_TOKEN_LENGTH:
            raise AuthenticationError("Invalid token format")
        if self._http is None:
            raise AuthenticationError("OAuth lane is not initialized")

        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.InvalidTokenError as e:
            raise AuthenticationError("Invalid token") from e
        kid = header.get("kid")
        if not kid:
            raise AuthenticationError("Token missing key ID (kid) header")

        signing_key = await self._jwks.signing_key(kid)
        # PyJWT raises InvalidAudienceError for an aud-bearing token when no
        # audience was passed, so "aud not configured" must disable the check
        # explicitly rather than rely on audience=None.
        decode_kwargs: dict = {"issuer": self.oauth_issuer, "leeway": JWT_LEEWAY_SECONDS}
        if self.oauth_audience:
            decode_kwargs["audience"] = self.oauth_audience
        else:
            decode_kwargs["options"] = {"verify_aud": False}
        try:
            claims = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=[JWT_ALGORITHM],
                **decode_kwargs,
            )
        except pyjwt.ExpiredSignatureError as e:
            raise AuthenticationError("Token has expired") from e
        except pyjwt.ImmatureSignatureError as e:
            raise AuthenticationError("Token is not yet valid") from e
        except pyjwt.InvalidIssuerError as e:
            raise AuthenticationError("Invalid token issuer") from e
        except pyjwt.InvalidAudienceError as e:
            raise AuthenticationError("Invalid token audience") from e
        except pyjwt.InvalidAlgorithmError as e:
            raise AuthenticationError("Unsupported token signing algorithm") from e
        except pyjwt.InvalidSignatureError as e:
            raise AuthenticationError("Invalid token signature") from e
        except pyjwt.InvalidTokenError as e:
            raise AuthenticationError("Invalid token") from e

        # kid/iss/derived id only — never the token or its other claims.
        logger.debug("OAuth token verified: kid=%s iss=%s", kid, claims.get("iss"))

        if self.oauth_groups_allowlist:
            groups = claims.get("groups") or []
            if isinstance(groups, str):
                groups = [groups]
            if not set(groups) & set(self.oauth_groups_allowlist):
                raise AuthenticationError("Token is not a member of an allowed group")

        user_id = claims.get("preferred_username") or claims.get("sub")
        if not user_id:
            raise AuthenticationError(
                "Token valid but missing both 'preferred_username' and 'sub' claims"
            )
        user_id = str(user_id).lower()
        logger.debug("OAuth user resolved: iss=%s user_id=%s", claims.get("iss"), user_id)
        return user_id

    async def _introspect_token(self, token: str) -> str:
        """Validate an opaque bearer token via RFC 7662 introspection; return its user id.

        POSTs ``token=<token>`` form-encoded to the configured endpoint with HTTP
        Basic auth (client id/secret). A token is accepted only when the response
        says ``active`` is true; ``exp`` is enforced (with the same clock-skew
        leeway as the JWKS lane) when present, and the groups allowlist applies
        with the same semantics. A non-2xx response, transport failure or
        malformed JSON is an ``AuthenticationError`` (401), never a 500.

        Lazy by design: unlike the JWKS warm-up there is no credential to probe
        with at startup, so the first opaque token pays the first network hop.
        The token and the client secret are never logged or echoed.
        """
        if self._http is None:
            raise AuthenticationError("Introspection lane is not initialized")

        try:
            # Same timeout discipline as the JWKS fetch: a hung IdP fails the
            # request rather than pinning a worker on the first opaque token.
            response = await self._http.post(
                self.oauth_client_url,
                data={"token": token},
                auth=(self.oauth_client_id, self.oauth_client_secret),
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            # Message carries no token/secret; the chain is for local logs only.
            raise AuthenticationError("Token introspection request failed") from e

        try:
            claims = response.json()
        except ValueError as e:
            raise AuthenticationError("Token introspection returned malformed JSON") from e
        if not isinstance(claims, dict):
            raise AuthenticationError("Token introspection returned malformed JSON")

        active = claims.get("active") is True
        user_id = claims.get("preferred_username") or claims.get("sub")
        logger.debug("Introspection result: active=%s user_present=%s", active, bool(user_id))
        if not active:
            raise AuthenticationError("Token is not active")

        # Only exp is enforced: an opaque token has no nbf/iat the IdP promised,
        # and PyJWT is not involved here, so the boundary is replicated by hand
        # with the same leeway (expired once exp + leeway < now).
        exp = claims.get("exp")
        if exp is not None:
            try:
                expired = float(exp) + JWT_LEEWAY_SECONDS < time.time()
            except (TypeError, ValueError) as e:
                raise AuthenticationError(
                    "Token introspection returned an invalid expiration"
                ) from e
            if expired:
                raise AuthenticationError("Token has expired")

        if self.oauth_groups_allowlist:
            groups = claims.get("groups") or []
            if isinstance(groups, str):
                groups = [groups]
            if not set(groups) & set(self.oauth_groups_allowlist):
                raise AuthenticationError("Token is not a member of an allowed group")

        if not user_id:
            raise AuthenticationError(
                "Token valid but missing both 'preferred_username' and 'sub' claims"
            )
        return str(user_id).lower()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _schema_name_for(self, user_id: str) -> str:
        """Build the tenant schema name for a user id (lowercase, dashes -> underscores)."""
        return f"{self.schema_prefix}_{user_id.lower().replace('-', '_')}"

    def _schema_lock(self, schema_name: str) -> asyncio.Lock:
        """Return (creating if needed) the init lock for one tenant schema."""
        lock = self._schema_locks.get(schema_name)
        if lock is None:
            lock = asyncio.Lock()
            self._schema_locks[schema_name] = lock
        return lock

    async def _ensure_schema(self, schema_name: str) -> None:
        """Provision a tenant schema on first access.

        The per-schema lock serializes concurrent first requests (two requests
        racing here would otherwise both call run_migration for the same
        schema); inside the lock the check runs again so the loser of the lock
        skips a redundant migration.
        """
        if schema_name in self._initialized_schemas:
            return
        async with self._schema_lock(schema_name):
            if schema_name not in self._initialized_schemas:
                await self._initialize_schema(schema_name)

    async def _initialize_schema(self, schema_name: str) -> None:
        """Run migrations for a new tenant schema and cache the result."""
        logger.info("Initializing schema: %s", schema_name)
        try:
            await self.context.run_migration(schema_name)
            self._initialized_schemas.add(schema_name)
            logger.info("Schema ready: %s", schema_name)
        except Exception as e:
            logger.error("Schema initialization failed for %s: %s", schema_name, e)
            raise AuthenticationError(f"Failed to initialize tenant: {e!s}")

    # ------------------------------------------------------------------
    # Worker discovery
    # ------------------------------------------------------------------

    async def list_tenants(self) -> list[Tenant]:
        """Return every tenant the worker should process.

        Static users are known at startup; users seen through authentication are
        added as they appear (OAuth users are minted by the IdP, not by config).
        The union keeps background consolidation running over every schema that
        has ever been used.
        """
        tenants = dict(self._users)
        for user_id, schema_name in self._seen_users.items():
            tenants.setdefault(user_id, schema_name)
        return [
            Tenant(schema=schema_name, tenant_id=user_id)
            for user_id, schema_name in tenants.items()
        ]

"""Hybrid tenant extension for Hindsight: static API keys now, OAuth2/OIDC next.

One ``TenantExtension`` accepts both credential shapes a deployment needs — the
env-declared static API keys used by headless clients today, and OAuth2/OIDC
bearer tokens (authentik) once the JWKS lane lands — and resolves either to a
**per-user PostgreSQL schema** (``{prefix}_{user_id}``), provisioned lazily on
first access. Isolation therefore sits below the bank mechanism: a client
cannot reach another user's banks by guessing a bank id, because the schema is
the boundary.

This build implements the core, static-key lane only. It is deliberately
explicit about the parts that are not here yet:

    - ``HINDSIGHT_API_TENANT_USERS`` parsing with fail-fast startup validation
    - constant-time static key match (``hmac.compare_digest``, no early fast path)
    - JWT-shaped tokens are rejected with "Unknown credential" instead of being
      matched as keys (the JWKS lane is a stacked PR), and
      ``HINDSIGHT_API_TENANT_OAUTH_ENABLED=true`` is refused at startup so the
      gap can never be silently misread as "OAuth is on"

Configuration via environment variables, following the loader convention
(``HINDSIGHT_API_TENANT_<NAME>`` -> ``config["<name>"]``)::

    HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_hybrid_tenant:HybridTenantExtension
    HINDSIGHT_API_TENANT_USERS=user1:key1,user1:key2,user2:key3   # required, comma-separated user:key pairs
    HINDSIGHT_API_TENANT_SCHEMA_PREFIX=user                      # optional, default "user"
    HINDSIGHT_API_TENANT_OAUTH_ENABLED=false                     # optional, default false
    HINDSIGHT_API_TENANT_OAUTH_ISSUER / _AUDIENCE / _JWKS_URL / _GROUPS_ALLOWLIST

Planned but deliberately not implemented here: ``on_startup`` (plan §3) is not
overridden. Every configuration check lives in ``__init__``, which the loader
runs *before* startup and turns into a hard load failure — strictly earlier and
stricter than an ``on_startup`` check — and the only work ``on_startup`` would
do in this build (warming the JWKS cache) is moot while
``oauth_enabled=true`` is refused. An override arrives with the lane that
needs one.

Provenance: the static-key lane is ported from
``hindsight-extensions/static-keys-tenant`` (vectorize-io/hindsight @
a9eeed77f9bce99d8f97d39a30d3281747300824, MIT).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
from dataclasses import dataclass

from hindsight_api.extensions.tenant import AuthenticationError, Tenant, TenantContext, TenantExtension
from hindsight_api.models import RequestContext

logger = logging.getLogger(__name__)

__all__ = ["HybridTenantExtension"]

# Schema prefix must be a valid Postgres identifier component (letters, digits, underscores)
_SCHEMA_PREFIX_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# User IDs appear in schema names, so they must be safe as a Postgres identifier
# component: start with a letter/underscore, then letters/digits/underscore/dash.
# Dashes are normalized to underscores and the whole id is lowercased before
# building the schema name (Postgres folds unquoted identifiers to lowercase).
_USER_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

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

        # OAuth lane config. Parsed and held now so the config surface is
        # complete, but the lane itself is not implemented in this build: see
        # the oauth_enabled guard at the end of __init__.
        self.oauth_issuer = config.get("oauth_issuer", "")
        self.oauth_audience = config.get("oauth_audience", "")
        self.oauth_jwks_url = config.get("oauth_jwks_url", "")
        if not self.oauth_jwks_url and self.oauth_issuer:
            # authentik publishes per-application JWKS at {issuer}/jwks/.
            self.oauth_jwks_url = f"{self.oauth_issuer.rstrip('/')}/jwks/"
        self.oauth_groups_allowlist = _parse_csv(config.get("oauth_groups_allowlist", ""))
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
                user_id=user_id, schema_name=schema_name, key_id=key_id, key_bytes=_encode_key(api_key)
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

        # The OAuth lane is a stacked PR. Refuse to start with it enabled rather
        # than silently running static-only and leaving machine clients to fail
        # with a 401 they cannot diagnose from the deployment's config.
        if self.oauth_enabled:
            raise ValueError(
                "HINDSIGHT_API_TENANT_OAUTH_ENABLED=true is not supported by this build: the OAuth/JWT "
                "lane is not implemented yet. Unset it (or set it to false) to run the static-key lane."
            )

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
        (constant time) against the configured keys; a JWT-shaped token belongs
        to the JWKS lane, which this build does not implement, so it is refused
        with "Unknown credential" rather than being mistaken for a key.
        """
        key = context.api_key
        if not key:
            raise AuthenticationError("Missing Authorization header. Expected: Bearer <api_key>")

        entry = self._match_static_key(key)
        if entry is None:
            if _is_jwt_shaped(key):
                raise AuthenticationError("Unknown credential")
            raise AuthenticationError("Invalid API key")

        await self._ensure_schema(entry.schema_name)

        # Usage metering: the HTTP/MCP layers read these fields back after auth
        # to attribute operations to a tenant / API key. api_key_id identifies
        # *the key* (see RequestContext), not the user — with multiple keys per
        # user it must distinguish which key authenticated. It is the derived,
        # non-secret key_id, never the key itself.
        context.tenant_id = entry.user_id
        context.api_key_id = entry.key_id
        self._seen_users.setdefault(entry.user_id, entry.schema_name)

        return TenantContext(schema_name=entry.schema_name)

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
        return [Tenant(schema=schema_name, tenant_id=user_id) for user_id, schema_name in tenants.items()]

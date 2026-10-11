"""Unit tests for the hybrid tenant extension's config + static-key lane.

Run against the vendored pinned ``hindsight_api`` interface (see conftest.py).
"""

import asyncio
import hmac

import pytest
from hindsight_api.extensions.tenant import AuthenticationError, Tenant, TenantContext, TenantExtension
from hindsight_api.models import RequestContext

from hindsight_ext_hybrid_tenant import HybridTenantExtension

KEY_PI_A = "pi-key-0123456789abcdef"
KEY_PI_B = "pi-key-fedcba9876543210"
KEY_OW = "openwebui-key-0123456789"
USERS = f"pi:{KEY_PI_A},pi:{KEY_PI_B},openwebui:{KEY_OW}"


class FakeExtensionContext:
    """Records the schema migrations the extension asks the server to run."""

    def __init__(self) -> None:
        self.migrations: list[str] = []
        self.fail_for: set[str] = set()

    async def run_migration(self, schema_name: str) -> None:
        self.migrations.append(schema_name)
        if schema_name in self.fail_for:
            raise RuntimeError("migration unavailable")


def make_extension(config: dict[str, str] | None = None, ctx: FakeExtensionContext | None = None) -> HybridTenantExtension:
    cfg = {"users": USERS}
    if config:
        cfg.update(config)
    ext = HybridTenantExtension(cfg)
    ext.set_context(ctx or FakeExtensionContext())
    return ext


def config_error(users: str) -> str:
    """Return the startup ValueError message for a users config (fails the test if none)."""
    with pytest.raises(ValueError) as excinfo:
        HybridTenantExtension({"users": users})
    return str(excinfo.value)


# ---------------------------------------------------------------------------
# Config parsing + defaults
# ---------------------------------------------------------------------------


def test_satisfies_pinned_tenant_extension_interface():
    ext = make_extension()
    assert isinstance(ext, TenantExtension)
    assert asyncio.run(ext.list_tenants())


def test_users_env_is_required():
    with pytest.raises(ValueError, match="HINDSIGHT_API_TENANT_USERS is required"):
        HybridTenantExtension({})
    with pytest.raises(ValueError, match="HINDSIGHT_API_TENANT_USERS is required"):
        HybridTenantExtension({"users": "   "})


def test_users_without_a_valid_pair_is_rejected():
    assert "no valid" in config_error(",")
    assert "no valid" in config_error(" , , ")


def test_schema_prefix_defaults_to_user():
    assert make_extension().schema_prefix == "user"


def test_schema_prefix_must_be_a_postgres_identifier():
    for bad in ("1user", "has-dash", "has space", "", "drop;table"):
        with pytest.raises(ValueError, match="Invalid schema_prefix"):
            HybridTenantExtension({"users": USERS, "schema_prefix": bad})


def test_oauth_fields_parse_and_default_to_disabled():
    ext = make_extension()
    assert ext.oauth_enabled is False
    assert ext.oauth_issuer == ""
    assert ext.oauth_audience == ""
    assert ext.oauth_jwks_url == ""
    assert ext.oauth_groups_allowlist == []


def test_oauth_fields_parse_from_config():
    ext = make_extension(
        {
            "oauth_enabled": "false",
            "oauth_issuer": "https://authentik.example/application/o/hindsight-mcp",
            "oauth_audience": "hindsight-mcp",
            "oauth_groups_allowlist": "agents, admins ,",
        }
    )
    assert ext.oauth_enabled is False
    assert ext.oauth_issuer == "https://authentik.example/application/o/hindsight-mcp"
    assert ext.oauth_audience == "hindsight-mcp"
    # authentik publishes per-application JWKS at {issuer}/jwks/ (trailing slash trimmed).
    assert ext.oauth_jwks_url == "https://authentik.example/application/o/hindsight-mcp/jwks/"
    assert ext.oauth_groups_allowlist == ["agents", "admins"]


def test_explicit_oauth_jwks_url_wins():
    url = "https://authentik.example/custom/jwks/"
    ext = make_extension({"oauth_issuer": "https://authentik.example/o/x", "oauth_jwks_url": url})
    assert ext.oauth_jwks_url == url


def test_enabling_the_unimplemented_oauth_lane_fails_startup():
    for flag in ("true", "TRUE", "1", "yes", "on"):
        with pytest.raises(ValueError, match="HINDSIGHT_API_TENANT_OAUTH_ENABLED"):
            HybridTenantExtension({"users": USERS, "oauth_enabled": flag})


# ---------------------------------------------------------------------------
# Startup validation of the users list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "users",
    [
        "pi",  # no ":" separator
        ":key-0123456789abc",  # empty user id
        "pi:",  # empty key
        "1pi:key-0123456789",  # user id must start with a letter/underscore
        "p i:key-0123456789",  # space is not a valid identifier character
        "pi:short",  # key below the minimum length
        "pi:key.with.dots.12345",  # "." collides with JWT shape routing
        "pi:cl\u00e9-tr\u00e8s-longue-1234",  # non-ASCII key
    ],
)
def test_invalid_user_key_pairs_are_rejected(users):
    with pytest.raises(ValueError):
        HybridTenantExtension({"users": users})


def test_short_key_error_names_the_key_without_echoing_it():
    weak = "shortkey"
    message = config_error(f"pi:{weak}")
    assert "key_id" in message and "at least 16" in message
    assert weak not in message


def test_duplicate_key_across_users_is_rejected_without_echoing_it():
    message = config_error(f"pi:{KEY_PI_A},other:{KEY_PI_A}")
    assert "Duplicate API key" in message and "key_id" in message
    assert KEY_PI_A not in message


def test_duplicate_key_for_the_same_user_is_rejected():
    message = config_error(f"pi:{KEY_PI_A},pi:{KEY_PI_A}")
    assert "Duplicate API key" in message
    assert KEY_PI_A not in message


def test_schema_collision_after_normalization_is_rejected():
    message = config_error(f"jane-doe:{KEY_PI_A},jane_doe:{KEY_PI_B}")
    assert "already claimed" in message


def test_schema_name_longer_than_postgres_identifier_limit_is_rejected():
    long_user = "a" * 60  # "user_" + 60 chars = 65 > 63
    with pytest.raises(ValueError, match="identifier limit of 63"):
        HybridTenantExtension({"users": f"{long_user}:{KEY_PI_A}"})


def test_user_ids_are_normalized_to_lowercase_and_underscores():
    ext = make_extension({"users": f"Pi-Agent:{KEY_PI_A}"})
    assert asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A))).schema_name == "user_pi_agent"
    tenants = asyncio.run(ext.list_tenants())
    # tenant_id keeps the (lowercased) declared id; only the schema replaces dashes.
    assert [(t.schema, t.tenant_id) for t in tenants] == [("user_pi_agent", "pi-agent")]


def test_case_variants_merge_onto_one_user_and_schema():
    ext = make_extension({"users": f"Pi:{KEY_PI_A},pi:{KEY_PI_B}"})
    assert len(asyncio.run(ext.list_tenants())) == 1
    assert asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_B))).schema_name == "user_pi"


def test_custom_schema_prefix_applies():
    ext = make_extension({"schema_prefix": "tenant"})
    assert asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A))).schema_name == "tenant_pi"


# ---------------------------------------------------------------------------
# Lane routing + static-key lane
# ---------------------------------------------------------------------------


def test_static_key_authenticates_and_reports_identity():
    rc = RequestContext(api_key=KEY_PI_A)
    tc = asyncio.run(make_extension().authenticate(rc))
    assert isinstance(tc, TenantContext)
    assert tc.schema_name == "user_pi"
    assert rc.tenant_id == "pi"
    # api_key_id identifies the key, not the user, and is never the key itself.
    assert rc.api_key_id and rc.api_key_id != KEY_PI_A


def test_second_key_for_same_user_reaches_the_same_schema():
    ext = make_extension()
    assert asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_B))).schema_name == "user_pi"


def test_missing_credential_is_rejected():
    ext = make_extension()
    for context in (RequestContext(), RequestContext(api_key="")):
        with pytest.raises(AuthenticationError):
            asyncio.run(ext.authenticate(context))


def test_unknown_static_key_is_rejected():
    ext = make_extension()
    with pytest.raises(AuthenticationError):
        asyncio.run(ext.authenticate(RequestContext(api_key="nope-key-0123456789")))


def test_jwt_shaped_token_is_rejected_as_unknown_credential_without_fallback():
    ctx = FakeExtensionContext()
    ext = make_extension(ctx=ctx)
    with pytest.raises(AuthenticationError) as excinfo:
        asyncio.run(ext.authenticate(RequestContext(api_key="aaa.bbb.ccc")))
    assert "Unknown credential" in str(excinfo.value)
    assert ctx.migrations == []  # no lane ran, no schema was provisioned


def test_keys_are_compared_with_compare_digest(monkeypatch):
    calls = 0
    real = hmac.compare_digest

    def spy(a, b):
        nonlocal calls
        calls += 1
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)

    ext = make_extension()
    asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A)))
    assert calls >= 1

    calls = 0
    with pytest.raises(AuthenticationError):
        asyncio.run(ext.authenticate(RequestContext(api_key="nope-key-0123456789")))
    # Unknown keys still walk the constant-time loop over every configured key:
    # there is no equality fast path that would leak key shape via timing.
    assert calls == len(ext._key_to_user)


def test_http_and_mcp_lanes_return_the_same_tenant_context():
    ext = make_extension()
    http = asyncio.run(ext.authenticate(RequestContext(api_key=KEY_OW)))
    mcp = asyncio.run(ext.authenticate_mcp(RequestContext(api_key=KEY_OW)))
    assert http == mcp
    assert http.schema_name == "user_openwebui"


def test_both_lanes_route_through_one_resolver(monkeypatch):
    ext = make_extension()
    seen: list[RequestContext] = []
    resolve = ext._resolve

    async def spy(context: RequestContext) -> TenantContext:
        seen.append(context)
        return await resolve(context)

    monkeypatch.setattr(ext, "_resolve", spy)
    asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A)))
    asyncio.run(ext.authenticate_mcp(RequestContext(api_key=KEY_PI_A)))
    assert len(seen) == 2


# ---------------------------------------------------------------------------
# Lazy schema provisioning
# ---------------------------------------------------------------------------


def test_schema_is_provisioned_on_first_access_only():
    ctx = FakeExtensionContext()
    ext = make_extension(ctx=ctx)
    for _ in range(3):
        asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A)))
    assert ctx.migrations == ["user_pi"]


def test_distinct_users_get_distinct_schemas():
    ctx = FakeExtensionContext()
    ext = make_extension(ctx=ctx)
    asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A)))
    asyncio.run(ext.authenticate(RequestContext(api_key=KEY_OW)))
    assert sorted(ctx.migrations) == ["user_openwebui", "user_pi"]


def test_concurrent_first_requests_provision_the_schema_once():
    ctx = FakeExtensionContext()
    ext = make_extension(ctx=ctx)

    async def auth_twice():
        return await asyncio.gather(
            ext.authenticate(RequestContext(api_key=KEY_PI_A)),
            ext.authenticate(RequestContext(api_key=KEY_PI_A)),
        )

    results = asyncio.run(auth_twice())
    assert [tc.schema_name for tc in results] == ["user_pi", "user_pi"]
    assert ctx.migrations == ["user_pi"]


def test_migration_failure_surfaces_as_authentication_error():
    ctx = FakeExtensionContext()
    ctx.fail_for.add("user_pi")
    ext = make_extension(ctx=ctx)
    with pytest.raises(AuthenticationError, match="Failed to initialize tenant"):
        asyncio.run(ext.authenticate(RequestContext(api_key=KEY_PI_A)))


# ---------------------------------------------------------------------------
# Worker discovery
# ---------------------------------------------------------------------------


def test_list_tenants_covers_every_configured_user():
    tenants = asyncio.run(make_extension().list_tenants())
    assert isinstance(tenants[0], Tenant)
    assert {(t.schema, t.tenant_id) for t in tenants} == {("user_pi", "pi"), ("user_openwebui", "openwebui")}


def test_list_tenants_is_a_union_of_static_and_seen_users():
    ext = make_extension()
    # An IdP-authenticated user (the stacked OAuth lane) is never in config; the
    # worker must still discover its schema or its consolidation stalls.
    ext._seen_users["oidc-user"] = "user_oidc_user"
    assert ("user_oidc_user", "oidc-user") in {(t.schema, t.tenant_id) for t in asyncio.run(ext.list_tenants())}


def test_authentication_marks_the_user_as_seen():
    ext = make_extension()
    assert ext._seen_users == {}
    asyncio.run(ext.authenticate(RequestContext(api_key=KEY_OW)))
    assert ext._seen_users == {"openwebui": "user_openwebui"}

"""Unit tests for the RFC 7662 token introspection lane (opaque bearer tokens).

No network: the introspection endpoint (and the JWKS endpoint, for the
coexistence cases) is served by one ``httpx.MockTransport`` handler that records
the request. Opaque tokens are never signed, so the assertions are about the
request the extension makes and the claims it acts on. Run against the vendored
pinned ``hindsight_api`` interface (see conftest.py).
"""

import asyncio
import base64
import contextlib
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext
from jwt.algorithms import RSAAlgorithm

from hindsight_ext_hybrid_tenant import HybridTenantExtension

ISSUER = "https://authentik.test/application/o/hindsight-mcp"
JWKS_URL = f"{ISSUER}/jwks/"
INTROSPECT_URL = "https://authentik.test/application/o/introspect/"
CLIENT_ID = "hindsight-introspection-client"
CLIENT_SECRET = "client-secret-that-must-never-be-logged"
AUDIENCE = "hindsight-mcp"
KEY_PI = "pi-key-0123456789abcdef"
USERS = f"pi:{KEY_PI}"
# Opaque on purpose: no ".", so _is_jwt_shaped() routes it to introspection.
OPAQUE = "opaque-bearer-token-with-no-dots"

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "introspection-test-key"


def _jwk() -> dict:
    jwk = RSAAlgorithm.to_jwk(_RSA_KEY.public_key(), as_dict=True)
    jwk.update({"kid": _KID, "alg": "RS256", "use": "sig"})
    return jwk


def sign(**claims) -> str:
    """Sign a currently-valid JWT with the test key, overriding any claims."""
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": AUDIENCE, "exp": now + 300, "sub": "1234567890", **claims}
    return jwt.encode(payload, _RSA_KEY, algorithm="RS256", headers={"kid": _KID})


@dataclass
class FakeAuthentik:
    """Serves both the JWKS and the introspection endpoint, recording introspection calls."""

    jwks_keys: list[dict] = field(default_factory=lambda: [_jwk()])
    jwks_status: int = 200
    introspection_status: int = 200
    introspection_body: bytes | None = None
    introspection_claims: dict = field(default_factory=lambda: {"active": True, "sub": "pat"})
    introspection_requests: list[httpx.Request] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jwks/"):
            if self.jwks_status != 200:
                return httpx.Response(self.jwks_status, text="jwks unavailable")
            return httpx.Response(200, json={"keys": self.jwks_keys})
        self.introspection_requests.append(request)
        if self.introspection_status != 200:
            return httpx.Response(self.introspection_status, text="introspection failed")
        if self.introspection_body is not None:
            return httpx.Response(200, content=self.introspection_body)
        return httpx.Response(200, json=self.introspection_claims)


class FakeExtensionContext:
    """Records the schema migrations the extension asks the server to run."""

    def __init__(self) -> None:
        self.migrations: list[str] = []

    async def run_migration(self, schema_name: str) -> None:
        self.migrations.append(schema_name)


CONFIG = {
    "users": USERS,
    "oauth_enabled": "true",
    "oauth_issuer": ISSUER,
    "oauth_jwks_url": JWKS_URL,
    "oauth_audience": AUDIENCE,
    "oauth_introspection_url": INTROSPECT_URL,
    "oauth_introspection_client_id": CLIENT_ID,
    "oauth_introspection_client_secret": CLIENT_SECRET,
}


def make_extension(authentik: FakeAuthentik, **overrides) -> HybridTenantExtension:
    config = dict(CONFIG)
    config.update(overrides)
    ext = HybridTenantExtension(config)
    ext.set_context(FakeExtensionContext())
    # Pre-set the client: on_startup reuses an existing one, so tests drive the
    # mock transport without touching the production construction path.
    ext._http = httpx.AsyncClient(transport=httpx.MockTransport(authentik.handler))
    return ext


@contextlib.asynccontextmanager
async def running(authentik: FakeAuthentik, **overrides):
    ext = make_extension(authentik, **overrides)
    try:
        yield ext
    finally:
        await ext.on_shutdown()


def run(coro_fn) -> None:
    """Run an async test body on a fresh event loop (matches the repo's style)."""
    asyncio.run(coro_fn())


# ---------------------------------------------------------------------------
# Config: trio validation
# ---------------------------------------------------------------------------


def test_absent_trio_leaves_introspection_disabled():
    ext = HybridTenantExtension({"users": USERS})
    assert ext.oauth_introspection_enabled is False


def test_complete_trio_enables_introspection():
    ext = HybridTenantExtension(dict(CONFIG))
    assert ext.oauth_introspection_enabled is True


@pytest.mark.parametrize("dropped", list(CONFIG)[-3:])
def test_partial_trio_fails_startup_naming_the_missing_field(dropped):
    config = {k: v for k, v in CONFIG.items() if k != dropped}
    with pytest.raises(ValueError) as excinfo:
        HybridTenantExtension(config)
    message = str(excinfo.value)
    assert dropped.upper() in message  # names the missing variable ...
    assert CLIENT_SECRET not in message  # ... without echoing a value


def test_partial_trio_never_echoes_the_supplied_secret():
    # URL and secret supplied, client id missing: the error must name the field,
    # never quote the secret that was supplied.
    config = {k: v for k, v in CONFIG.items() if k != "oauth_introspection_client_id"}
    with pytest.raises(ValueError) as excinfo:
        HybridTenantExtension(config)
    assert "OAUTH_INTROSPECTION_CLIENT_ID" in str(excinfo.value)
    assert CLIENT_SECRET not in str(excinfo.value)


def test_introspection_endpoint_must_be_https():
    config = dict(CONFIG, oauth_introspection_url="http://authentik.test/introspect/")
    with pytest.raises(ValueError, match="INTROSPECTION_URL"):
        HybridTenantExtension(config)


# ---------------------------------------------------------------------------
# Active tokens -> tenant schema
# ---------------------------------------------------------------------------


def test_active_token_with_preferred_username_maps_to_normalized_schema():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "J-Doe"}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            # Lazy: startup makes no introspection call.
            assert authentik.introspection_requests == []
            rc = RequestContext(api_key=OPAQUE)
            tc = await ext.authenticate(rc)
            assert tc.schema_name == "user_j_doe"
            assert rc.tenant_id == "j-doe"
            assert rc.api_key_id is None  # not a static key
            assert len(authentik.introspection_requests) == 1

    run(_run)


def test_active_token_falls_back_to_sub():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": True, "sub": "Abc-123"})
        async with running(authentik) as ext:
            await ext.on_startup()
            tc = await ext.authenticate(RequestContext(api_key=OPAQUE))
            assert tc.schema_name == "user_abc_123"

    run(_run)


def test_introspection_user_is_recorded_for_worker_discovery():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "Pat"}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            await ext.authenticate(RequestContext(api_key=OPAQUE))
            assert ("user_pat", "pat") in {
                (t.schema, t.tenant_id) for t in await ext.list_tenants()
            }

    run(_run)


def test_introspection_subject_with_invalid_schema_chars_is_rejected():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "X\n"}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="valid tenant schema"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


# ---------------------------------------------------------------------------
# Rejections: inactive, missing user, exp, groups
# ---------------------------------------------------------------------------


def test_inactive_token_is_rejected():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": False, "sub": "pat"})
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="not active"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_token_without_username_or_sub_is_rejected():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": True})
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="preferred_username"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_expired_token_beyond_leeway_is_rejected():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "sub": "pat", "exp": int(time.time()) - 60}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="expired"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_exp_within_leeway_is_accepted():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "sub": "pat", "exp": int(time.time()) - 5}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            assert (
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            ).schema_name == "user_pat"

    run(_run)


def test_token_without_exp_is_accepted():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": True, "sub": "pat"})
        async with running(authentik) as ext:
            await ext.on_startup()
            assert (
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            ).schema_name == "user_pat"

    run(_run)


def test_groups_allowlist_accepts_a_member():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "sub": "pat", "groups": ["other", "agents"]}
        )
        async with running(authentik, oauth_groups_allowlist="agents, admins") as ext:
            await ext.on_startup()
            assert (
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            ).schema_name == "user_pat"

    run(_run)


def test_groups_allowlist_rejects_a_non_member():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "sub": "pat", "groups": ["viewers"]}
        )
        async with running(authentik, oauth_groups_allowlist="agents") as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="allowed group"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_groups_allowlist_rejects_a_token_with_no_groups_claim():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": True, "sub": "pat"})
        async with running(authentik, oauth_groups_allowlist="agents") as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="allowed group"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


# ---------------------------------------------------------------------------
# Transport failures become 401, never 500
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [400, 401, 403, 500, 503])
def test_http_error_status_is_an_authentication_error(status):
    async def _run():
        authentik = FakeAuthentik(introspection_status=status)
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="introspection request failed"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_transport_error_is_an_authentication_error():
    async def _run():
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        ext = HybridTenantExtension(dict(CONFIG, oauth_enabled="false"))
        ext.set_context(FakeExtensionContext())
        ext._http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
        await ext.on_startup()
        with pytest.raises(AuthenticationError, match="introspection request failed"):
            await ext.authenticate(RequestContext(api_key=OPAQUE))
        await ext.on_shutdown()

    run(_run)


def test_malformed_json_is_an_authentication_error():
    async def _run():
        authentik = FakeAuthentik(introspection_body=b"not json")
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="malformed JSON"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


def test_json_array_response_is_an_authentication_error():
    async def _run():
        authentik = FakeAuthentik(introspection_body=b'["not", "an", "object"]')
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="malformed JSON"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))

    run(_run)


# ---------------------------------------------------------------------------
# Request shape + secret hygiene
# ---------------------------------------------------------------------------


def test_request_is_form_encoded_with_basic_auth():
    async def _run():
        authentik = FakeAuthentik(introspection_claims={"active": True, "sub": "pat"})
        async with running(authentik) as ext:
            await ext.on_startup()
            await ext.authenticate(RequestContext(api_key=OPAQUE))

            assert len(authentik.introspection_requests) == 1
            request = authentik.introspection_requests[0]
            assert request.method == "POST"
            assert request.headers["content-type"] == "application/x-www-form-urlencoded"
            # RFC 7662: the token travels form-encoded in the body, not a header.
            assert parse_qs(request.content.decode()) == {"token": [OPAQUE]}

            expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            assert request.headers["authorization"] == f"Basic {expected}"

    run(_run)


def test_neither_token_nor_secret_is_echoed_in_errors_or_logs(caplog):
    async def _run():
        caplog.set_level(logging.DEBUG)
        authentik = FakeAuthentik(introspection_claims={"active": False, "sub": "pat"})
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError) as excinfo:
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            assert OPAQUE not in str(excinfo.value)
            assert CLIENT_SECRET not in str(excinfo.value)
        for record in caplog.records:
            assert OPAQUE not in record.getMessage()
            assert CLIENT_SECRET not in record.getMessage()

    run(_run)


def test_transport_error_message_does_not_leak_the_secret():
    async def _run():
        authentik = FakeAuthentik(introspection_status=500)
        async with running(authentik) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError) as excinfo:
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            assert CLIENT_SECRET not in str(excinfo.value)
            assert OPAQUE not in str(excinfo.value)

    run(_run)


# ---------------------------------------------------------------------------
# Lane routing + coexistence
# ---------------------------------------------------------------------------


def test_static_jwt_and_opaque_tokens_all_route_in_one_instance():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "Ophelia"}
        )
        async with running(authentik) as ext:
            await ext.on_startup()

            static_rc = RequestContext(api_key=KEY_PI)
            assert (await ext.authenticate(static_rc)).schema_name == "user_pi"
            assert static_rc.api_key_id  # static lane still reports the key id

            jwt_rc = RequestContext(api_key=sign(preferred_username="Jwta"))
            assert (await ext.authenticate(jwt_rc)).schema_name == "user_jwta"

            opaque_rc = RequestContext(api_key=OPAQUE)
            assert (await ext.authenticate(opaque_rc)).schema_name == "user_ophelia"

            # Only the opaque token reached introspection; the JWT used JWKS.
            assert len(authentik.introspection_requests) == 1

    run(_run)


def test_jwt_shaped_token_never_goes_to_introspection():
    async def _run():
        authentik = FakeAuthentik()
        async with running(authentik) as ext:
            await ext.on_startup()
            # Even with introspection configured, JWTs stay on the JWKS lane.
            await ext.authenticate(RequestContext(api_key=sign()))
            assert authentik.introspection_requests == []

    run(_run)


def test_opaque_token_without_introspection_configured_is_refused():
    async def _run():
        authentik = FakeAuthentik()
        async with running(
            authentik,
            oauth_introspection_url="",
            oauth_introspection_client_id="",
            oauth_introspection_client_secret="",
        ) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="Invalid API key"):
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            assert authentik.introspection_requests == []

    run(_run)


def test_introspection_only_lane_works_with_jwks_disabled():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "Pat"}
        )
        async with running(authentik, oauth_enabled="false") as ext:
            await ext.on_startup()
            assert (
                await ext.authenticate(RequestContext(api_key=OPAQUE))
            ).schema_name == "user_pat"
            # JWTs still refused: the JWKS lane is off, and opaque != JWT.
            with pytest.raises(AuthenticationError, match="Unknown credential"):
                await ext.authenticate(RequestContext(api_key=sign()))

    run(_run)


def test_mcp_lane_returns_the_same_tenant_context_for_an_opaque_token():
    async def _run():
        authentik = FakeAuthentik(
            introspection_claims={"active": True, "preferred_username": "Pat"}
        )
        async with running(authentik) as ext:
            await ext.on_startup()
            http = await ext.authenticate(RequestContext(api_key=OPAQUE))
            mcp = await ext.authenticate_mcp(RequestContext(api_key=OPAQUE))
            assert http == mcp
            assert http.schema_name == "user_pat"

    run(_run)

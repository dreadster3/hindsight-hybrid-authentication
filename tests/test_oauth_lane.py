"""Unit tests for the OAuth2/OIDC lane (JWKS + JWT verification).

No network: JWKS is served by an `` httpx.MockTransport`` handler and tokens are
signed with a locally generated RSA keypair. Run against the vendored pinned
``hindsight_api`` interface (see conftest.py).
"""

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from hindsight_api.extensions.tenant import AuthenticationError
from hindsight_api.models import RequestContext
from jwt.algorithms import RSAAlgorithm

import hindsight_ext_hybrid_tenant.extension as ext_module
from hindsight_ext_hybrid_tenant import HybridTenantExtension

ISSUER = "https://authentik.test/application/o/hindsight-mcp"
JWKS_URL = f"{ISSUER}/jwks/"
AUDIENCE = "hindsight-mcp"
KEY_PI = "pi-key-0123456789abcdef"
USERS = f"pi:{KEY_PI}"


# ---------------------------------------------------------------------------
# Test RSA keypair + JWKS fixtures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestKey:
    """An RSA signing key with the ``kid`` it publishes under."""

    kid: str
    private: object

    @property
    def jwk(self) -> dict:
        jwk = RSAAlgorithm.to_jwk(self.private.public_key(), as_dict=True)
        jwk["kid"] = self.kid
        jwk["alg"] = "RS256"
        jwk["use"] = "sig"
        return jwk


def _generate_key(kid: str) -> TestKey:
    return TestKey(kid=kid, private=rsa.generate_private_key(public_exponent=65537, key_size=2048))


KEY_A = _generate_key("k1")
KEY_B = _generate_key("k2")  # simulates a rotated key arriving in a later JWKS
FOREIGN = _generate_key("foreign")  # never published in the JWKS


def sign(key: TestKey, *, iss: str = ISSUER, aud: str | None = AUDIENCE, **claims) -> str:
    """Sign a JWT with the given test key, defaulting to a currently-valid token."""
    now = int(time.time())
    payload = {
        "iss": iss,
        "exp": now + 300,
        "nbf": now - 5,
        "iat": now - 5,
        "sub": "1234567890",
        **claims,
    }
    if aud is None:
        payload.pop("aud", None)
    else:
        payload.setdefault("aud", aud)
    if payload.get("sub") is None:
        payload.pop("sub", None)
    return jwt.encode(payload, key.private, algorithm="RS256", headers={"kid": key.kid})


@dataclass
class JwksServer:
    """A mutable JWKS endpoint served to httpx's MockTransport, counting fetches."""

    keys: list[TestKey] = field(default_factory=lambda: [KEY_A])
    fetches: int = 0
    status: int = 200
    body: bytes | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        if self.status != 200:
            return httpx.Response(self.status, text="jwks unavailable")
        if self.body is not None:
            return httpx.Response(200, content=self.body, headers={"content-type": "application/json"})
        return httpx.Response(200, json={"keys": [k.jwk for k in self.keys]})


class FakeExtensionContext:
    """Records the schema migrations the extension asks the server to run."""

    def __init__(self) -> None:
        self.migrations: list[str] = []

    async def run_migration(self, schema_name: str) -> None:
        self.migrations.append(schema_name)


def make_extension(server: JwksServer, ctx: FakeExtensionContext | None = None, **overrides) -> HybridTenantExtension:
    """Build an OAuth-enabled extension wired to ``server`` via a mock transport."""
    config = {
        "users": USERS,
        "oauth_enabled": "true",
        "oauth_issuer": ISSUER,
        "oauth_jwks_url": JWKS_URL,
        "oauth_audience": AUDIENCE,
    }
    config.update({k: v for k, v in overrides.items() if v is not None})
    ext = HybridTenantExtension(config)
    ext.set_context(ctx or FakeExtensionContext())
    # Pre-set the client: on_startup reuses an existing one, so tests drive the
    # mock transport without touching the production construction path.
    ext._http = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    return ext


@contextlib.asynccontextmanager
async def running(server: JwksServer, **overrides):
    """Yield an OAuth-enabled extension with its mock HTTP client closed after."""
    ext = make_extension(server, **overrides)
    try:
        yield ext
    finally:
        await ext.on_shutdown()


def run(coro_fn) -> None:
    """Run an async test body on a fresh event loop (matches the repo's style)."""
    asyncio.run(coro_fn())


# ---------------------------------------------------------------------------
# Valid tokens -> tenant schema
# ---------------------------------------------------------------------------


def test_valid_token_maps_to_normalized_user_schema():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            rc = RequestContext(api_key=sign(KEY_A, preferred_username="J-Doe"))
            tc = await ext.authenticate(rc)
            assert tc.schema_name == "user_j_doe"
            assert rc.tenant_id == "j-doe"
            assert rc.api_key_id is None  # not a static key
            assert server.fetches == 1  # warmed once, no per-request fetch

    run(_run)


def test_user_id_falls_back_to_sub_when_preferred_username_absent():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            tc = await ext.authenticate(RequestContext(api_key=sign(KEY_A, sub="Abc-123")))
            assert tc.schema_name == "user_abc_123"

    run(_run)


def test_token_without_username_or_sub_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            token = sign(KEY_A, sub=None)
            with pytest.raises(AuthenticationError, match="preferred_username"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_user_id_with_trailing_newline_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            # "$" would match before the trailing newline and mint schema
            # "user_x\n"; the \Z anchor rejects the claim instead.
            token = sign(KEY_A, preferred_username="X\n")
            with pytest.raises(AuthenticationError, match="valid tenant schema"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_issuer_mismatch_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            token = sign(KEY_A, iss="https://evil.test/application/o/hindsight-mcp")
            with pytest.raises(AuthenticationError, match="issuer"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_audience_mismatch_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="audience"):
                await ext.authenticate(RequestContext(api_key=sign(KEY_A, aud="some-other-app")))

    run(_run)


def test_unset_audience_skips_the_audience_check():
    async def _run():
        server = JwksServer()
        # No oauth_audience configured -> any aud (or none) is accepted.
        async with running(server, oauth_audience="") as ext:
            await ext.on_startup()
            for token in (sign(KEY_A, aud="anything"), sign(KEY_A, aud=None)):
                tc = await ext.authenticate(RequestContext(api_key=token))
                assert tc.schema_name == "user_1234567890"

    run(_run)


def test_expired_token_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            token = sign(KEY_A, exp=int(time.time()) - 3600)
            with pytest.raises(AuthenticationError, match="expired"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_not_yet_valid_token_beyond_leeway_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            now = int(time.time())
            token = sign(KEY_A, nbf=now + 120, iat=now + 120)
            with pytest.raises(AuthenticationError, match="not yet valid"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_small_clock_skew_within_leeway_is_accepted():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            now = int(time.time())
            token = sign(KEY_A, nbf=now + 5, iat=now + 5)
            assert (await ext.authenticate(RequestContext(api_key=token))).schema_name == "user_1234567890"

    run(_run)


def test_signature_from_unpublished_key_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            # kid of a published key, but signed by a foreign private key.
            token = sign(TestKey(kid=KEY_A.kid, private=FOREIGN.private))
            with pytest.raises(AuthenticationError, match="signature"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_algorithm_downgrade_is_rejected():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            # HS256 with the RSA public key material as the HMAC secret: the
            # classic alg-confusion attempt. A real kid keeps the token out of the
            # "missing kid" path so decode is what rejects it, on algorithm alone.
            token = jwt.encode(
                {"iss": ISSUER, "sub": "x", "exp": int(time.time()) + 300},
                "secret",
                algorithm="HS256",
                headers={"kid": KEY_A.kid},
            )
            with pytest.raises(AuthenticationError, match="algorithm"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


# ---------------------------------------------------------------------------
# groups allowlist
# ---------------------------------------------------------------------------


def test_groups_allowlist_accepts_a_member():
    async def _run():
        server = JwksServer()
        async with running(server, oauth_groups_allowlist="agents, admins") as ext:
            await ext.on_startup()
            token = sign(KEY_A, groups=["other", "agents"])
            assert (await ext.authenticate(RequestContext(api_key=token))).schema_name == "user_1234567890"

    run(_run)


def test_groups_allowlist_rejects_a_non_member():
    async def _run():
        server = JwksServer()
        async with running(server, oauth_groups_allowlist="agents") as ext:
            await ext.on_startup()
            token = sign(KEY_A, groups=["viewers"])
            with pytest.raises(AuthenticationError, match="allowed group"):
                await ext.authenticate(RequestContext(api_key=token))

    run(_run)


def test_groups_allowlist_rejects_a_token_with_no_groups_claim():
    async def _run():
        server = JwksServer()
        async with running(server, oauth_groups_allowlist="agents") as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="allowed group"):
                await ext.authenticate(RequestContext(api_key=sign(KEY_A)))

    run(_run)


def test_no_groups_allowlist_skips_the_groups_check():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            assert (await ext.authenticate(RequestContext(api_key=sign(KEY_A, groups=[])))).schema_name

    run(_run)


# ---------------------------------------------------------------------------
# JWKS fetch / cache / kid rotation
# ---------------------------------------------------------------------------


def test_kid_miss_triggers_one_refresh_and_retry(monkeypatch):
    async def _run():
        clock = {"t": 1000.0}
        monkeypatch.setattr(ext_module, "_monotonic", lambda: clock["t"])
        server = JwksServer(keys=[KEY_A])
        async with running(server) as ext:
            await ext.on_startup()
            assert server.fetches == 1
            # Issuer rotates, and enough time passes that a refresh is allowed.
            clock["t"] += ext_module.JWKS_MIN_REFRESH_INTERVAL_SECONDS + 1
            server.keys = [KEY_B]
            token = sign(KEY_B)
            tc = await ext.authenticate(RequestContext(api_key=token))
            assert tc.schema_name == "user_1234567890"
            assert server.fetches == 2  # exactly one refresh

    run(_run)


def test_kid_miss_within_refresh_window_skips_refetch(monkeypatch):
    async def _run():
        clock = {"t": 1000.0}
        monkeypatch.setattr(ext_module, "_monotonic", lambda: clock["t"])
        server = JwksServer(keys=[KEY_A])
        async with running(server) as ext:
            await ext.on_startup()
            assert server.fetches == 1
            # A garbage-kid token right after the warm must not trigger a fetch:
            # otherwise a token flood hammers the issuer's JWKS endpoint.
            token = sign(TestKey(kid="garbage", private=KEY_A.private))
            with pytest.raises(AuthenticationError, match="signing key"):
                await ext.authenticate(RequestContext(api_key=token))
            assert server.fetches == 1

    run(_run)


def test_kid_miss_twice_raises_authentication_error(monkeypatch):
    async def _run():
        clock = {"t": 1000.0}
        monkeypatch.setattr(ext_module, "_monotonic", lambda: clock["t"])
        server = JwksServer(keys=[KEY_A])
        async with running(server) as ext:
            await ext.on_startup()
            clock["t"] += ext_module.JWKS_MIN_REFRESH_INTERVAL_SECONDS + 1
            token = sign(TestKey(kid="rotated-away", private=KEY_A.private))
            with pytest.raises(AuthenticationError, match="signing key"):
                await ext.authenticate(RequestContext(api_key=token))
            assert server.fetches == 2  # one warm + one refresh, then give up

    run(_run)


def test_jwks_cache_expires_after_ttl_and_refetches(monkeypatch):
    async def _run():
        clock = {"t": 1000.0}
        monkeypatch.setattr(ext_module, "_monotonic", lambda: clock["t"])
        server = JwksServer(keys=[KEY_A])
        async with running(server) as ext:
            await ext.on_startup()
            assert server.fetches == 1

            token = sign(KEY_A)
            await ext.authenticate(RequestContext(api_key=token))
            assert server.fetches == 1  # within TTL: served from cache

            clock["t"] += 601
            await ext.authenticate(RequestContext(api_key=token))
            assert server.fetches == 2  # TTL elapsed: refetched

    run(_run)


def test_jwks_fetch_failure_during_auth_is_an_authentication_error():
    async def _run():
        server = JwksServer(keys=[KEY_A])
        async with running(server) as ext:
            await ext.on_startup()
            server.status = 500  # issuer now unavailable
            # Expire the cache so the next authenticate must refetch.
            ext._jwks._fetched_at -= ext_module.JWKS_CACHE_TTL_SECONDS + 1
            with pytest.raises(AuthenticationError, match="signing keys"):
                await ext.authenticate(RequestContext(api_key=sign(KEY_A)))

    run(_run)


def test_startup_fails_fast_when_jwks_is_unreachable():
    async def _run():
        server = JwksServer(status=503)
        ext = make_extension(server)
        with pytest.raises(RuntimeError, match="unreachable"):
            await ext.on_startup()
        assert ext._http is None  # client torn down, lane cannot silently half-run

    run(_run)


def test_malformed_jwks_document_fails_startup():
    async def _run():
        server = JwksServer(body=b"not json")
        ext = make_extension(server)
        with pytest.raises(RuntimeError, match="unreachable"):
            await ext.on_startup()

    run(_run)


def test_oversized_jwks_document_fails_startup():
    async def _run():
        # A body past the streaming size cap is rejected before it is parsed, so
        # a broken or hostile endpoint cannot exhaust memory.
        server = JwksServer(body=b"x" * (ext_module.MAX_JWKS_BYTES + 1))
        ext = make_extension(server)
        with pytest.raises(RuntimeError, match="unreachable"):
            await ext.on_startup()

    run(_run)


# ---------------------------------------------------------------------------
# Lane routing, static-key coexistence, error hygiene
# ---------------------------------------------------------------------------


def test_static_key_lane_still_works_with_oauth_enabled():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            rc = RequestContext(api_key=KEY_PI)
            assert (await ext.authenticate(rc)).schema_name == "user_pi"
            assert rc.api_key_id  # static lane still reports the key id

    run(_run)


def test_unknown_credential_still_gets_401():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            with pytest.raises(AuthenticationError, match="Invalid API key"):
                await ext.authenticate(RequestContext(api_key="not-a-key-and-not-a-jwt"))
            # A JWT-shaped token that fails verification is a 401, never a fallback.
            with pytest.raises(AuthenticationError, match="signature"):
                await ext.authenticate(RequestContext(api_key=sign(TestKey(kid=KEY_A.kid, private=FOREIGN.private))))

    run(_run)


def test_jwt_lane_is_off_when_oauth_disabled():
    async def _run():
        ext = HybridTenantExtension({"users": USERS})
        ext.set_context(FakeExtensionContext())
        with pytest.raises(AuthenticationError, match="Unknown credential"):
            await ext.authenticate(RequestContext(api_key=sign(KEY_A)))

    run(_run)


def test_mcp_lane_returns_the_same_tenant_context_for_a_jwt():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            http = await ext.authenticate(RequestContext(api_key=sign(KEY_A, preferred_username="Pat")))
            mcp = await ext.authenticate_mcp(RequestContext(api_key=sign(KEY_A, preferred_username="Pat")))
            assert http == mcp
            assert http.schema_name == "user_pat"

    run(_run)


def test_oauth_user_is_recorded_for_worker_discovery():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            await ext.authenticate(RequestContext(api_key=sign(KEY_A, preferred_username="Pat")))
            assert ("user_pat", "pat") in {(t.schema, t.tenant_id) for t in await ext.list_tenants()}

    run(_run)


def test_error_messages_never_echo_token_material():
    async def _run():
        server = JwksServer()
        async with running(server) as ext:
            await ext.on_startup()
            token = sign(KEY_A, iss="https://evil.test/o/hindsight")
            with pytest.raises(AuthenticationError) as excinfo:
                await ext.authenticate(RequestContext(api_key=token))
            assert token not in str(excinfo.value)
            # Nor does a bad kid leak the token into the error.
            bad_kid_token = sign(TestKey(kid="gone", private=KEY_A.private))
            with pytest.raises(AuthenticationError) as excinfo:
                await ext.authenticate(RequestContext(api_key=bad_kid_token))
            assert bad_kid_token not in str(excinfo.value)

    run(_run)

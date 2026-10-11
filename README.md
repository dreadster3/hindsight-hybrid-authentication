# hindsight-ext-hybrid-tenant

Custom Hindsight `TenantExtension` giving every user their own PostgreSQL
schema. Hindsight resolves **identity → tenant** before **tenant → bank**:
this extension turns a credential (static API key or OAuth2/OIDC bearer token)
into a schema name (`{prefix}_{user_id}`), and every query then runs against
`<schema>.*` only. Isolation sits *below* the bank mechanism, so guessing
another user's bank id — `/mcp/<their-bank>/` or `X-Bank-Id` — simply 404s: the
bank does not exist in the caller's schema. A user owns any number of banks
inside their own schema (`coding-agent::<repo>`, personal, per-agent), which is
the natural model once the schema *is* the boundary.

One extension, three lanes, one resolver. Lane routing is by credential shape:
configured static keys never contain `.`; a JWT always has exactly two; anything
else is an opaque bearer token. A credential that fails its lane is refused —
no fallback to another lane, no unauthenticated path.

## Auth matrix

| Lane / consumer | Credential | Validation | Resolved user | Banks |
|---|---|---|---|---|
| pi extension (`~/.pi/agent/settings.json`) | static `apiToken` | exact match against env-declared keys (constant time) | env-paired `user_id` | per-repo banks inside `user_<id>` |
| OpenWebUI tool server | static bearer (one key) | static key | dedicated `openwebui` service user | per-OpenWebUI-user banks inside `user_openwebui` via `X-Bank-Id: {{USER_ID}}` *(shared-schema caveat)* |
| OAuth-capable MCP clients (Claude Code, IDEs, …) | authentik access token | local JWKS validation (PyJWT, cached keys from the issuer's `jwks` endpoint), RS256 only | `preferred_username` / `sub` claim | own banks inside `user_<id>` |
| Opaque-token clients | authentik opaque token | RFC 7662 introspection (`POST` form-encoded, HTTP Basic auth) | `preferred_username` / `sub` from the introspection response | own banks inside `user_<id>` |
| Machine clients (n8n, scripts) | authentik client-credentials token | same JWKS validation | the client's bound `user` | app-owned banks inside `user_<id>` |

Missing/unknown credential → `AuthenticationError` → 401. No fallback to
unauthenticated.

## Configuration

All variables use the loader convention `HINDSIGHT_API_TENANT_<NAME>` →
`config["<name_lowercased>"]`.

| Variable | Required | Default | Format / semantics |
|---|---|---|---|
| `HINDSIGHT_API_TENANT_EXTENSION` | yes | — | `hindsight_ext_hybrid_tenant:HybridTenantExtension` |
| `HINDSIGHT_API_TENANT_USERS` | yes | — | comma-separated `user_id:api_key` pairs. Multiple keys may map to one user (`pi:K1,pi:K2,openwebui:K3`). |
| `HINDSIGHT_API_TENANT_SCHEMA_PREFIX` | no | `user` | Postgres identifier component (`^[A-Za-z_][A-Za-z0-9_]*\Z`). Lowercased at load to match Postgres identifier folding. Schema = `{prefix}_{user_id}`. |
| `HINDSIGHT_API_TENANT_OAUTH_ENABLED` | no | `false` | `true`/`1`/`yes`/`on` or `false`/`0`/`no`/`off`, matched case-insensitively (value stripped + lowercased). Anything else fails startup. When false the extension behaves exactly like the static-keys lane. |
| `HINDSIGHT_API_TENANT_OAUTH_ISSUER` | yes when OAuth enabled | — | OIDC issuer URL, e.g. `https://authentik.example/application/o/hindsight-mcp`. Must be `https` (`http` allowed only on loopback). |
| `HINDSIGHT_API_TENANT_OAUTH_AUDIENCE` | no | — | Expected `aud` claim. Enforced only when set; unset disables the audience check. |
| `HINDSIGHT_API_TENANT_OAUTH_JWKS_URL` | no | `{issuer}/jwks/` | JWKS endpoint. Must be `https` (`http` allowed only on loopback). |
| `HINDSIGHT_API_TENANT_OAUTH_GROUPS_ALLOWLIST` | no | — | comma-separated authentik group names. When set, a token must carry at least one; otherwise rejected. |
| `HINDSIGHT_API_TENANT_OAUTH_BASE_URL` | no | — | RFC 7662 introspection endpoint, e.g. `https://authentik.example/application/o/introspect/`. Must be `https` (`http` allowed only on loopback). |
| `HINDSIGHT_API_TENANT_OAUTH_CLIENT_ID` | no | — | Introspection client id (HTTP Basic auth user). |
| `HINDSIGHT_API_TENANT_OAUTH_CLIENT_SECRET` | no | — | Introspection client secret (HTTP Basic auth password). Inject from an Infisical-style env secret, never into the image. |

The three introspection variables are all-or-nothing: **all three set** →
opaque-token introspection is active; **a partial trio** fails startup, naming
the missing field (values are never echoed). There is no separate enable flag.

### Startup validation (fail fast)

Misconfiguration raises during load, not on the first request.

- `USERS` entries must be `user_id:api_key`; both sides non-empty.
- `user_id`: `^[A-Za-z_][A-Za-z0-9_-]*\Z`, then lowercased, dashes → underscores.
- `api_key`: ASCII, no `.` (would be routed as JWT-shaped), ≥ 16 chars.
- Keys unique across users; schema names unique after normalization; schema
  names ≤ 63 bytes (Postgres `NAMEDATALEN`).
- Error messages never echo key material — a key is named by its derived,
  non-secret `key_id` (sha256 prefix) in error text and in metering.
- OAuth enabled → issuer present; issuer and JWKS URL `https` (loopback exempt).
- Introspection trio all-or-nothing; a partial trio fails startup naming the
  missing field; the introspection URL is `https` (loopback exempt). The client
  secret is never echoed in error text.

### OAuth / JWKS behavior

- `algorithms=["RS256"]` only — blocks an `alg` downgrade to a symmetric key.
- `iss` must equal the configured issuer; `aud` enforced only when configured;
  `exp`/`nbf`/`iat` checked by PyJWT with a 10 s clock-skew leeway.
- JWKS cached 600 s; on a `kid` miss the cache is refreshed once and retried.
  A miss while the cache is < 30 s old fails without an upstream fetch, so a
  flood of garbage-`kid` tokens cannot hammer the issuer (an *empty* key set
  refetches on every request by design — nothing can authenticate anyway).
- JWKS body capped at 64 KiB; fetch timeout 10 s.
- User id = `preferred_username` or `sub` (lowercased); must map to a valid,
  non-truncating schema or the request is refused.
- `on_startup` warms the JWKS cache and **fails startup** if the issuer is
  unreachable. An unverifiable token is never accepted, so a broken lane fails
  the deploy rather than degrading.
- Never logs or stores tokens; debug logs carry `kid`, `iss`, derived user id.

### Token introspection mode

Set all three `..._OAUTH_CLIENT_*` variables to hand hindsight a single
authentik client id/secret and have it validate opaque bearer tokens itself via
RFC 7662. For any token that is neither a configured static key nor JWT-shaped,
the extension POSTs `token=<token>` form-encoded to the introspection endpoint
with HTTP Basic auth (client id/secret) and accepts only a response whose
`active` is `true`. The user id comes from `preferred_username` or `sub`, `exp`
is enforced when present (same 10 s leeway), and the groups allowlist applies —
identical semantics to the JWKS lane.

Prefer this over local JWKS when clients hold **opaque** tokens (nothing local
to verify) or when you need **authentik-side session revocation** to take effect
immediately: introspection asks the IdP on every request, so a revoked or
deactivated token stops working at once. The cost is a **network hop to
authentik per opaque-token request** (with a strict 10 s timeout). **JWT-shaped
tokens keep using the JWKS lane even when introspection is configured** — the
local path is faster and never regresses to a remote call.

The lane is lazy: startup makes no call to authentik (unlike the JWKS warm-up,
there is no credential to probe with), so the first opaque token pays the first
hop. The token and the client secret are never logged or echoed. Supply the
client secret through Infisical-style env injection (a Kubernetes Secret / env
var), not baked into the image.

### Metering fields set after auth

`RequestContext.tenant_id` = resolved user id. `RequestContext.api_key_id` =
the derived `key_id` for static keys (distinguishes which key authenticated);
left unset for OAuth credentials.

## Wiring recipes

### pi extension

`~/.pi/agent/settings.json`:

```json
{
  "apiUrl": "http://hindsight.internal.example",
  "apiToken": "REPLACE_WITH_THE_PI_USERS_STATIC_KEY"
}
```

The `apiToken` is that user's static key from `HINDSIGHT_API_TENANT_USERS`; pi
defaults to a `coding-agent::<repo>` bank inside the user's schema. `apiUrl` is
the HTTPRoute URL (or the internal service URL).

### OpenWebUI tool server

- Tool server URL: unchanged, e.g.
  `http://hindsight.hindsight.svc.cluster.local:8888/mcp/`.
- Authorization: bearer = the `openwebui` user's key (the one configured as
  `openwebui:<key>`).
- Keep the per-user bank header the tool server templates server-side:
  `{"X-Bank-Id": "{{USER_ID}}"}`.

All OpenWebUI users land in the single `user_openwebui` schema; separation
*inside* it is bank-id-by-convention. See caveats.

### OAuth-capable MCP clients

1. In authentik create an OAuth2 provider + application (e.g. `hindsight-mcp`),
   signing **RS256**, scopes `profile email groups`.
2. Point the client's MCP server URL at the hindsight HTTPRoute URL
   (`http://hindsight.internal.example`).
3. Grant per client: **device-code** for interactive clients,
   **client-credentials** for non-interactive ones.
4. Set `HINDSIGHT_API_TENANT_OAUTH_ISSUER`, `..._AUDIENCE` (if the client sends
   an `aud`), and `..._JWKS_URL` (defaults to `{issuer}/jwks/`).

The extension validates the token locally and binds it to the claim-derived
user; it never calls the IdP per request.

### Machine clients (client-credentials)

- Create an authentik OAuth2 app per machine, **client-credentials** grant.
- The client fetches a token from authentik and sends it as
  `Authorization: Bearer <token>`.
- The extension only inspects the JWT signature/claims, not the grant type, so
  a client-credentials token authenticates the same as a device-code one.

## Workers

`list_tenants()` returns the **union** of static users (known at startup) and
users seen through authentication (OAuth users are minted by the IdP, not by
config; seen re-enter the union on their next authentication after a restart —
the set is in-memory). The worker's background consolidation therefore keeps
running over every schema that has ever been used — static and OAuth alike. A worker without
this extension would stop every tenant's processing; `list_tenants` is the
seam that keeps it working.

## Caveats

- **Shared OpenWebUI schema.** Every OpenWebUI user shares `user_openwebui`;
  per-user separation inside it is bank-id-by-convention. OpenWebUI templates
  `X-Bank-Id` server-side, so hindsight trusts it *within that one schema* —
  which is exactly the header-trust posture the schema boundary removes
  everywhere else. True per-OpenWebUI-user schemas need a per-user tool-server
  token, which OpenWebUI cannot currently inject. Accept or revisit when it can.
- **Cross-lane bank convergence.** "Same user, same bank from pi and chat" is
  still a *rename*: point the pi `banks.<id>.bank` mapping at the chat bank id.
  One hop, reversible, no new mechanism.
- **Token lifetime for machine clients.** authentik access tokens are
  short-lived; non-interactive clients should use client-credentials (per-app
  app passwords) and refresh on their own. The extension cares about the JWT
  signature, not the grant type.
- **Header hygiene.** Keep hindsight's auth as the only gate. If a reverse
  proxy is added later, it must not become trusted input: never trust
  gateway-injected `X-authentik-*` (or any identity) headers. The extension
  validates the credential itself.

## Data migration

Switching from `ApiKeyTenantExtension` does **not** move data. Memories created
under the old single-tenant model live in the **`public`** schema; new tenants
create `user_*` schemas. Before rollout either:

- (a) do a one-time re-import — `hindsight-admin` export/transfer of the
  `public` schema's banks into each user's schema, or
- (b) start fresh (early/ephemeral data).

Decide explicitly; do not leave data stranded silently.

## Provenance

- Vendored pattern sources: the static-key lane is ported from
  `hindsight-extensions/static-keys-tenant`; the JWKS fetch/cache/kid-refresh
  pattern from `hindsight-extensions/supabase-tenant`.
- Upstream: `vectorize-io/hindsight` (MIT). The interface used here is pinned
  to commit `a9eeed77f9bce99d8f97d39a30d3281747300824`.
- `hindsight_api` is **not** a dependency of this repo. A verbatim copy of the
  pinned interface lives under `tests/_stub/` for the test run only; at runtime
  the image supplies the real `hindsight_api`.

## Development

```sh
uv sync
uv run pytest
```

## Building the image

The extension is not on PyPI: the image is the deployment artifact, built on top
of Hindsight and carrying `src/hindsight_ext_hybrid_tenant` inside it.

```sh
docker build -f deploy/Dockerfile -t hindsight-hybrid-auth:dev .
```

```sh
docker run -p 8888:8888 \
  -e HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_hybrid_tenant:HybridTenantExtension \
  -e HINDSIGHT_API_TENANT_USERS='pi:REPLACE_WITH_A_32_CHAR_KEY' \
  -e HINDSIGHT_API_DATABASE_URL=postgresql://hindsight:REPLACE_WITH_A_PASSWORD@db:5432/hindsight \
  hindsight-hybrid-auth:dev
```

For the OAuth lane add `-e HINDSIGHT_API_TENANT_OAUTH_ENABLED=true -e
HINDSIGHT_API_TENANT_OAUTH_ISSUER=https://authentik.example/application/o/hindsight-mcp`.
The slim base ships no local embedding/reranking models, so point the server at
a remote provider: `-e HINDSIGHT_API_EMBEDDINGS_PROVIDER=tei` (or `openai`/
`google`) and `-e HINDSIGHT_API_RERANKER_PROVIDER=rrf` (model-free — keeps the
fused RRF order; or `tei`).
The build imports the extension in the server's own interpreter, so a packaging
mistake fails the build instead of the first authenticated request. A worker
deployment needs the same `HINDSIGHT_API_TENANT_*` variables as the API, or
background consolidation stops for every tenant (see Workers).

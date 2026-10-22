# A Hindsight image with the hybrid-authentication tenant extension in it.
#
# The base image *is* the runtime: it already carries the server and its
# virtualenv, so this file only adds the extension. No builder stage — the
# upstream extension recipe (hindsight-extensions/README.md, "Docker packaging")
# is the pattern, and a second Python stage here would resolve a second,
# drifting copy of the server this extension must run inside.
#
# Build from the repository root so src/ is in the build context:
#   docker build -f deploy/Dockerfile -t hindsight-hybrid-auth:dev .
#
# Run:
#   docker run -p 8888:8888 \
#     -e HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_hybrid_tenant:HybridTenantExtension \
#     -e HINDSIGHT_API_TENANT_USERS='pi:REPLACE_WITH_A_32_CHAR_KEY' \
#     hindsight-hybrid-auth:dev
#
# Pinned by digest, not by tag: the digest is the index of the published
# `:latest-slim` (linux/amd64 + linux/arm64), so two builds of this commit
# produce the same image. Moving to a newer Hindsight is an explicit digest
# bump, never a tag that silently moved underneath the deployment.
FROM ghcr.io/vectorize-io/hindsight:1.1.0-slim@sha256:fbc37d194bce007b6cce2fd9f66cd7f8c050bd18b80e662090a92835d9cb191d

# Install into the server's virtualenv explicitly. It was created by `uv sync`
# and ships no `pip` of its own, so a bare `pip install` would land in user
# site-packages and be invisible to the running server. `uv` is the base
# image's (installed at its own build time), and the floors here mirror the
# runtime dependencies in pyproject.toml.
RUN uv pip install --python /app/api/.venv/bin/python --no-cache \
      'PyJWT[crypto]>=2.13.0' \
      'httpx>=0.28.1'

# /app/extensions is ours — the base image does not use it — so nothing the
# server ships can be shadowed by what lands here. The base sets no PYTHONPATH
# of its own, so this assignment replaces nothing.
COPY src/hindsight_ext_hybrid_tenant /app/extensions/hindsight_ext_hybrid_tenant
ENV PYTHONPATH=/app/extensions

# Fail the build, rather than the first authenticated request. This is the
# interpreter the server itself runs, and the import pulls in the PyJWT/httpx
# deps installed above, so a packaging mistake cannot ship.
RUN /app/api/.venv/bin/python -c "import hindsight_ext_hybrid_tenant"

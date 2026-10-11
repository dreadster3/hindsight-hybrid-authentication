"""Minimal stand-in for ``hindsight_api.models``.

Adapted from the pinned upstream
``hindsight-api-slim/hindsight_api/models.py`` (vectorize-io/hindsight @
a9eeed77f9bce99d8f97d39a30d3281747300824): the ``RequestContext`` dataclass is
verbatim, while the SQLAlchemy ORM models below it are dropped — the tenant
extension only ever touches ``RequestContext``.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .cancellation import CancellationToken


@dataclass
class RequestContext:
    """
    Context for request authentication and authorization.

    This dataclass carries authentication data from HTTP requests to the
    memory engine operations. Beyond the Authorization header, a deployment can
    surface additional request headers to its extensions via ``extra_headers``
    (see HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS).
    """

    api_key: str | None = None
    api_key_id: str | None = None  # UUID of the API key used for authentication
    tenant_id: str | None = None  # Tenant identifier (set by extension after auth)
    internal: bool = False  # True for background/internal operations (skips extension auth)
    mcp_authenticated: bool = False  # True when MCP transport auth already validated (skips tenant re-auth)
    user_initiated: bool = False  # True for async operations that originated from a user request
    allowed_bank_ids: list[str] | None = None  # None = unrestricted (all banks)
    retry_count: int = 0
    cancellation: "CancellationToken | None" = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    authenticated_schema: str | None = None

    def raise_if_cancelled(self) -> None:
        """Abort the current operation if its cancellation token has fired.

        A no-op when no token is attached, so engine code can call it at every
        stage boundary without caring whether the caller opted into cancellation.
        """
        if self.cancellation is not None:
            self.cancellation.raise_if_cancelled()

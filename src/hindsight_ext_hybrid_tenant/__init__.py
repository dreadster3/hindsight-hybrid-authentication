"""Hybrid tenant extension for the Hindsight API server.

Configure the server to load it with::

    HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_hybrid_tenant:HybridTenantExtension
"""

from hindsight_ext_hybrid_tenant.extension import HybridTenantExtension

__all__ = ["HybridTenantExtension"]

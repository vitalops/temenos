"""Filtered egress — the allowlist proxy a `network='filtered'` box is pointed at.

`plan.md` §13 specifies this as *pasta + in-namespace nft TPROXY → SNI/Host
allowlist proxy + stub DNS*. What is here is the proxy and the allowlist: the
half that is pure Python, testable anywhere, and useful on its own.

What is **not** here is the namespace plumbing that makes the proxy the only
way out. Until that exists, a filtered box is *pointed* at the proxy
(``HTTPS_PROXY``) rather than confined to it — see
:attr:`~temenos.net.proxy.EgressProxy.enforced`, which says ``False`` and says
why. Read that before trusting this against hostile code; the answer for that
case is still ``network='none'``.
"""
from .allowlist import HostAllowlist, Verdict
from .proxy import EgressProxy, Meter

__all__ = ["EgressProxy", "HostAllowlist", "Meter", "Verdict"]

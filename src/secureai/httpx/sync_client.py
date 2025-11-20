"""
httpx.Client with RATLS verification.
"""

import httpx

from ..ssl_context import create_ssl_context_with_ratls
from ..utils import _get_default_logger

logger = _get_default_logger()


class Client(httpx.Client):
    """httpx.Client with RATLS verification.

    You should never set the `verify` keyword argument as it's what sets a custom SSL Context.
    """

    def __init__(self, *args, ratls_server_hostnames=[], **kwargs):
        if kwargs.get("verify") is not None:
            raise ValueError(
                "setting verify argument isn't possible. RATLS uses its own SSLContext"
            )
        kwargs["verify"] = create_ssl_context_with_ratls(ratls_server_hostnames)
        super().__init__(*args, **kwargs)

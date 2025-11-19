"""
This is a draft module that attempts to implement RATLS verification in httpx AsyncClient.
It's currently not functional.
"""

import ssl
from typing import Iterable, List

import httpcore
import httpx
from httpcore._backends.sync import SyncStream
from httpx._config import DEFAULT_LIMITS, Limits, create_ssl_context
from httpx._transports.default import SOCKET_OPTION
from httpx._types import CertTypes, ProxyTypes

from ..ratls import ratls_verify

raise NotImplementedError(
    "Async RATLSClient is not implemented yet. Don't import this module."
)


class RATLSSyncStream(SyncStream):
    def __init__(self, *args, ratls_server_hostnames: List[str] = [], **kwargs):
        self.ratls_server_hostnames = ratls_server_hostnames
        super().__init__(*args, **kwargs)

    def start_tls(self, *args, **kwargs):
        ssl_stream = super().start_tls(*args, **kwargs)

        socket: ssl.SSLSocket = ssl_stream.get_extra_info("socket")
        assert isinstance(socket, ssl.SSLSocket)

        if not ratls_verify(socket, self.ratls_server_hostnames):
            raise ssl.SSLError("RATLS verification failed")

        return RATLSSyncStream(
            sock=socket,
            ratls_server_hostnames=self.ratls_server_hostnames,
        )


class RATLSSyncBackend(httpcore.SyncBackend):
    """httpx NetworkBackend with RATLS verification."""

    def __init__(self, *args, ratls_server_hostnames: List[str] = [], **kwargs):
        self.ratls_server_hostnames = ratls_server_hostnames
        super().__init__(*args, **kwargs)

    def connect_tcp(self, *args, **kwargs):
        stream = super().connect_tcp(*args, **kwargs)
        return RATLSSyncStream(
            sock=stream.get_extra_info("socket"),
            ratls_server_hostnames=self.ratls_server_hostnames,
        )


class RATLSHTTPTransport(httpx.HTTPTransport):
    """httpx HTTPTransport with RATLS verification.

    You should never set the `verify` keyword argument as it's what sets a custom SSL Context.
    """

    def __init__(
        self,
        ratls_server_hostnames: List[str] = [],
        verify: ssl.SSLContext | str | bool = True,
        cert: CertTypes | None = None,
        trust_env: bool = True,
        http1: bool = True,
        http2: bool = False,
        limits: Limits = DEFAULT_LIMITS,
        proxy: ProxyTypes | None = None,
        uds: str | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ):
        self.ratls_server_hostnames = ratls_server_hostnames

        import httpcore

        ssl_context = create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)

        if proxy is None:
            self._pool = httpcore.ConnectionPool(
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                uds=uds,
                local_address=local_address,
                retries=retries,
                socket_options=socket_options,
                # This is the most important part that enables RATLS verification
                network_backend=RATLSSyncBackend(
                    ratls_server_hostnames=ratls_server_hostnames
                ),
            )
        else:
            raise ValueError("RATLSHTTPTransport does not support proxies.")


# This is an alternative Client that uses the custom Transport instead of SSLContext
# This is a tentative implementation and might be changed in the future
# It might be helpful in case of async as wrap_socket is not used there
class ClientV2(httpx.Client):
    """httpx.Client with RATLS verification.
    You should never set the `transport` keyword argument as it's what sets a custom SSL Context.
    """

    def __init__(self, *args, ratls_server_hostnames: List[str] = [], **kwargs):
        if kwargs.get("transport") is not None:
            raise ValueError(
                "setting transport argument isn't possible. RATLS uses its own HTTPTransport"
            )
        kwargs["transport"] = RATLSHTTPTransport(
            ratls_server_hostnames=ratls_server_hostnames
        )
        super().__init__(*args, **kwargs)


# TODO: Async backend in httpx isn't similar to the sync backend.
# Async doesn't use ssl.wrap_socket which means our current approach won't work.
# We need to find a way to hook into the async SSL handshake to perform RATLS verification
# Solutions:
# Async backends uses https://docs.python.org/3/library/ssl.html#ssl.SSLObject, we might find a way to hook into it.
# Another approach is to create a custom Transport that uses a custom NetworkBackend similar to the what we have in custom_transport.py
class AsyncRATLSClient(httpx.AsyncClient):
    """httpx.AsyncClient with RATLS verification.

    You should never set the `verify` keyword argument as it's what sets a custom SSL Context.
    """

    def __init__(self, *args, ratls_server_hostnames=[], **kwargs):
        raise NotImplementedError("Async RATLSClient is not implemented yet.")

        # if kwargs.get("verify") is not None:
        #     raise ValueError("setting verify argument isn't possible. RATLS uses its own SSLContext")
        # kwargs["verify"] = _create_verifying_ssl_context(ratls_server_hostnames)
        # super().__init__(*args, **kwargs)

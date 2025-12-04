"""
SSL Context with RATLS verification.
"""

import ssl

from .ratls import ratls_verify
from .utils import _get_default_logger
from .verifiers import RATLSVerifier
from .verifiers.errors import RATLSVerificationError

logger = _get_default_logger()


# We create a custom SSLContext that replaces the wrap_socket method.
# Our custom wrap_socket method performs RATLS verification after the handshake.
# The handshake is either done automatically by wrap_socket or we do it manually.
#
# See https://docs.python.org/3/library/ssl.html#ssl.SSLContext.wrap_socket
# And https://docs.python.org/3/library/ssl.html#ssl-sockets
def create_ssl_context_with_ratls(
    ratls_verifier_per_hostname: dict[str, RATLSVerifier] = None,
) -> ssl.SSLContext:
    """
    Create an SSL context that do ratls verification as part of the wrap_socket method.

    Args:
        ratls_verifier_per_hostname: Optional dictionary of RATLS verifiers per hostname.
            Hostnames not in this dict are ignored.
    Returns:
        ssl.SSLContext: SSL context with RATLS verification.
    """
    context = ssl.create_default_context()

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname

    # Store the original wrap_socket method
    original_wrap_socket = context.wrap_socket

    def wrap_socket_with_ratls(sock, *args, **kwargs):
        ssl_sock = original_wrap_socket(sock, *args, **kwargs)

        # Perform the handshake if not already done
        if not kwargs.get("do_handshake_on_connect", True):
            logger.debug("Performing TLS handshake for RATLS verification")
            ssl_sock.do_handshake()

        if not ratls_verify(ssl_sock, ratls_verifier_per_hostname):
            raise RATLSVerificationError("Verification failed")

        return ssl_sock

    # Replace wrap_socket with our version
    context.wrap_socket = wrap_socket_with_ratls

    return context

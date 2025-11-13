"""
RATLS Implementation.
"""

import logging
import ssl
from http.client import HTTPSConnection
from typing import List

logger = logging.getLogger("ratls")


# TODO: replace with RATLS standard endpoint for remote attestation
DEFAULT_QUOTE_ENDPOINT = "/"


def _get_quote_from_tls_conn(
    ssl_sock: ssl.SSLSocket, host, port=443, quote_endpoint=DEFAULT_QUOTE_ENDPOINT
) -> bytes:
    """Get a quote from the server using an existing TLS connection.

    Args:
        ssl_sock: An established SSL socket connected to the server.
        quote_endpoint: The HTTP endpoint to request the quote from.
        host: The server hostname.
        port: The server port (default is 443).
    """

    # Create an HTTPSConnection that uses our existing SSL socket
    logger.debug(f"Creating HTTPS client with existing socket for {host}:{port}")

    # Create a connection object and attach our socket to it
    conn = HTTPSConnection(host)
    conn.sock = ssl_sock  # Use our existing SSL socket

    # Make an HTTP request
    conn.request("GET", quote_endpoint)
    logger.debug(f"Sent GET request to {host}:{port}{quote_endpoint}")

    # Get the response
    response = conn.getresponse()
    response_data = response.read()

    logger.debug(f"Received HTTP response: {response.status} {response.reason}")
    logger.debug(f"Response body: {len(response_data)} bytes")
    return response_data

    # Don't close the connection - leave the socket open for future use
    # Note: conn.close() would close the socket, so we avoid calling it


# TODO: use a RATLS config which should be a dict of host_config per hostname
# so every hostname has its own config.
# The config should allow to set what is acceptable for a TEE environment.
# The config can be in yaml.
# We can have verifiers (subclass of Verifier) per configs so that different logics can be applied
# depending on different hardwares, RATLS versions, etc
def ratls_verify(
    ssl_sock: ssl.SSLSocket, hostname_verification_list: List[str]
) -> bool:
    """Verify RATLS on an ssl_sock.

    The verification should only run if the server hostname is in the list of hostnames to verify.
    """
    hostname = ssl_sock.server_hostname
    assert hostname is not None
    logger.debug(f"Socket server hostname: {hostname}")

    # We only verify servers on the list
    if hostname not in hostname_verification_list:
        logger.debug(f"Hostname {hostname} ignored")
        return True  # No verification

    logger.debug(f"Starting RATLS verification for {hostname}")

    cert_der = ssl_sock.getpeercert(binary_form=True)
    if cert_der is None:
        logger.error(f"No certificate received from {hostname}")
        return False
    logger.debug(f"Certificate received for {hostname} ({len(cert_der)} bytes)")

    result = _get_quote_from_tls_conn(ssl_sock, hostname)
    logger.debug(f"Quote received for {hostname} ({len(result)} bytes)")

    return True  # Success

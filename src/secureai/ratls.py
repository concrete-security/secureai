"""
RATLS Implementation.
"""

import binascii
import json
import secrets
import ssl
from hashlib import sha256
from http.client import HTTPSConnection
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .utils import _get_default_logger
from .verifiers.tdx import TDXVerifier, cert_hash_from_eventlog

logger = _get_default_logger()


DEFAULT_QUOTE_ENDPOINT = "/tdx_quote"


class RATLSVerificationError(Exception):
    """Exception raised when RATLS verification fails."""

    pass


def _get_quote_from_tls_conn(
    report_data: bytes,
    ssl_sock: ssl.SSLSocket,
    host,
    port=443,
    quote_endpoint=DEFAULT_QUOTE_ENDPOINT,
) -> dict:
    """Get a quote from the server using an existing TLS connection.

    Args:
        report_data: The report data to send to the server (not hex-encoded). Max 64 bytes.
        ssl_sock: An established SSL socket connected to the server.
        quote_endpoint: The HTTP endpoint to request the quote from.
        host: The server hostname.
        port: The server port (default is 443).

    Returns:
        dict with quote metadata and quote bytes (hex encoded)
    """

    if len(report_data) > 64:
        raise ValueError("report_data must be at most 64 bytes")

    # Create an HTTPSConnection that uses our existing SSL socket
    logger.debug(f"Creating HTTPS client with existing socket for {host}:{port}")

    # Create a connection object and attach our socket to it
    conn = HTTPSConnection(host)
    conn.sock = ssl_sock  # Use our existing SSL socket

    body_json = {"report_data_hex": report_data.hex()}
    conn.request(
        "POST",
        quote_endpoint,
        body=json.dumps(body_json),
        headers={"Content-Type": "application/json"},
    )
    logger.debug(f"Sent POST request to {host}:{port}{quote_endpoint}")

    # Get the response
    response = conn.getresponse()
    response_data = response.read()

    logger.debug(f"Received HTTP response: {response.status} {response.reason}")
    logger.debug(f"Response body: {len(response_data)} bytes")

    quote_data = json.loads(response_data)
    if not quote_data["success"]:
        logger.debug(f"Quote retrieval failed. Server returned: {quote_data}")
        raise RATLSVerificationError(
            "Quote retrieval failed. Use debug mode for more logs"
        )

    # Never close the socket, as it's externally managed
    # the socket should still be usable after this function returns
    return quote_data


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
    We assume the socket is connected to an HTTP server with an attestation endpoint.

    Args:
        ssl_sock: An established SSL socket connected to the server.
        hostname_verification_list: List of hostnames to verify using RATLS.

    Returns:
        True if verification passes, False otherwise
    """
    hostname = ssl_sock.server_hostname
    assert hostname is not None
    logger.debug(f"Socket server hostname: {hostname}")

    # We only verify servers on the list
    if hostname not in hostname_verification_list:
        logger.debug(f"Hostname {hostname} ignored")
        return True  # No verification

    logger.debug(f"Starting RATLS verification for {hostname}")

    # Get quote from server
    # TODO: Can we also add something about the TLS connection state?
    # The goal would be to bind the quote to the TLS session (avoid replay attacks)
    report_data = secrets.token_bytes(64)
    try:
        quote_response = _get_quote_from_tls_conn(report_data, ssl_sock, hostname)
    except Exception as e:
        logger.debug(f"Failed to get quote from {hostname}: {e}")
        return False
    logger.debug(f"Quote received for {hostname}")

    # This report_data is just metadata, so we make sure the server didn't get it wrong
    # The verifier should check this value too in the quote itself
    assert report_data.hex() == quote_response["quote"]["report_data"], (
        f"Report data mismatch {report_data.hex()} != {quote_response['quote']['report_data']}"
    )

    # Get server certificate
    cert_der = ssl_sock.getpeercert(binary_form=True)
    if cert_der is None:
        logger.debug(f"No certificate received from {hostname}")
        return False
    logger.debug(f"Certificate received for {hostname} ({len(cert_der)} bytes)")
    # Compute cert hash
    cert = x509.load_der_x509_certificate(cert_der)
    cert_data = cert.public_bytes(Encoding.PEM)
    cert_hash = sha256(cert_data).hexdigest()
    logger.debug(f"Certificate hash: {cert_hash}")

    # Get event log. It's metadata to replay the RTMRs
    event_log = json.loads(quote_response["quote"]["event_log"])

    # Verify that the received cert hash matches the one in the event log.
    # This makes sure the TEE is the one that generated the TLS cert.
    # This verification itself is not sufficient. We also need to verify the event log matches
    # the expected RTMRs
    computed_cert_hash = cert_hash_from_eventlog(event_log)
    logger.debug(f"Computed Cert Hash from Event Log: {computed_cert_hash}")

    if computed_cert_hash == cert_hash:
        logger.debug("Certificate hash matches the event log.")
    else:
        logger.debug("Certificate hash does NOT match the event log.")
        return False

    # Verify the quote using TDX verifier
    quote_bytes = binascii.unhexlify(quote_response["quote"]["quote"])
    verifier = TDXVerifier()
    verifier.set_report_data(report_data.hex())
    verifier.set_collaterals()
    verifier.set_rtmrs_from_eventlog(event_log)
    verifier.set_check_up_to_date()
    if not verifier.verify(quote_bytes):
        logger.debug(f"Quote verification failed for {hostname}")
        return False

    logger.debug(f"Quote verification succeeded for {hostname}")
    return True

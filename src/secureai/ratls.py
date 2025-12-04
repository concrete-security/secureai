"""
RATLS Implementation.
"""

import ssl

from .utils import _get_default_logger
from .verifiers import RATLSVerifier

logger = _get_default_logger()


def ratls_verify(
    ssl_sock: ssl.SSLSocket,
    ratls_verifier_per_hostname: dict[str, RATLSVerifier] = None,
) -> bool:
    """Verify RATLS on an ssl_sock.

    The verification should only run if the server hostname was configured with a verifier.
    We assume the socket is connected to an HTTP server with an attestation endpoint.

    Args:
        ssl_sock: An established SSL socket connected to the server.
        ratls_verifier_per_hostname: Optional dictionary of RATLS verifiers per hostname.
            Hostnames not in this dict are ignored.
    Returns:
        True if verification passes, False otherwise
    """
    hostname = ssl_sock.server_hostname
    assert hostname is not None
    logger.debug(f"Socket server hostname: {hostname}")

    if ratls_verifier_per_hostname is None:
        ratls_verifier_per_hostname = {}

    # We only verify servers on the list
    if hostname not in ratls_verifier_per_hostname.keys():
        logger.debug(f"Hostname {hostname} ignored")
        return True  # No verification

    # Get config for this hostname
    verifier = ratls_verifier_per_hostname.get(hostname)
    assert verifier is not None  # We checked the key exists above

    logger.debug(
        f"Starting RATLS verification for {hostname} using {verifier.__class__.__name__}"
    )

    try:
        if not verifier.verify(ssl_sock):
            logger.debug(f"RATLS Verification failed for {hostname}")
            return False
        logger.debug(f"RATLS Verification succeeded for {hostname}")
        return True
    except Exception as e:
        logger.debug(f"RATLS Verification failed for {hostname}: {e}")
        return False

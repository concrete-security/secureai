"""Provenance verification module.

This module provides functionality to verify SLSA provenance for container
images, particularly those referenced in docker-compose files.

Example:
    >>> from secureai.provenance import (
    ...     DockerComposeProvenanceVerifier,
    ...     build_default_policy,
    ... )
    >>>
    >>> verifier = DockerComposeProvenanceVerifier(
    ...     docker_compose=docker_compose_content,
    ...     service_policies={
    ...         "web": build_default_policy("org/repo"),
    ...     },
    ... )
    >>> result = verifier.verify()

For more advanced policies, use sigstore's policy classes directly:

    >>> from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository
    >>>
    >>> service_policies = {
    ...     "web": AllOf([
    ...         OIDCIssuer("https://token.actions.githubusercontent.com"),
    ...         GitHubWorkflowRepository("org/repo"),
    ...     ]),
    ... }
"""

import logging
import os

from .errors import ProvenanceVerificationError
from .slsa import (
    ContainerSLSAVerifier,
    VerificationResult,
    build_default_policy,
)
from .utils import _get_provenance_logger
from .verifier import (
    DockerComposeProvenanceVerifier,
    ProvenanceVerificationResult,
    ServiceVerificationResult,
    verify_docker_compose_provenance,
)

logger = _get_provenance_logger()

if os.getenv("DEBUG_PROVENANCE", "").lower() in ("1", "true"):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.ERROR)

__all__ = [
    # Main classes
    "DockerComposeProvenanceVerifier",
    "ContainerSLSAVerifier",
    # Results
    "ProvenanceVerificationResult",
    "ServiceVerificationResult",
    "VerificationResult",
    # Errors
    "ProvenanceVerificationError",
    # Convenience functions
    "verify_docker_compose_provenance",
    "build_default_policy",
]

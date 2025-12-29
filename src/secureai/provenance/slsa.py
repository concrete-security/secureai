"""SLSA Provenance Verification for Container Images.

This module provides functionality to verify SLSA provenance attestations
for container images using the sigstore library.
"""

import base64
import json
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate
from oras.container import Container
from oras.provider import Registry
from sigstore._internal.rekor.client import RekorClient
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TransparencyLogEntry
from sigstore.verify import Verifier
from sigstore.verify.policy import (
    AllOf,
    AnyOf,
    GitHubWorkflowName,
    GitHubWorkflowRepository,
    GitHubWorkflowSHA,
    Identity,
    OIDCIssuer,
    OIDCSourceRepositoryDigest,
    OIDCSourceRepositoryURI,
    VerificationPolicy,
)

from .utils import _get_provenance_logger

logger = _get_provenance_logger()


# Constants for SLSA GitHub generator
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_GENERATOR_IDENTITY_PATTERN = (
    "https://github.com/slsa-framework/slsa-github-generator/"
    ".github/workflows/generator_container_slsa3.yml"
)


@dataclass
class VerificationResult:
    """Result of SLSA verification for a single container image.

    Attributes:
        verified: Whether the verification succeeded
        image: The image name (without digest)
        digest: The image digest
        provenance: The provenance data if verification succeeded
        error: Error message if verification failed
    """

    verified: bool
    image: str
    digest: str
    provenance: Optional[dict] = None
    error: Optional[str] = None


def build_default_policy(
    expected_repo: str,
    expected_commit: str | None = None,
    expected_workflow_name: str | None = None,
) -> VerificationPolicy:
    """Build a common verification policy for GitHub Actions.

    This is a convenience function that builds a policy matching
    the SLSA GitHub generator workflow. For more advanced policies,
    use sigstore's policy classes directly.

    Args:
        expected_repo: Expected GitHub repository (e.g., "org/repo")
        expected_commit: Optional commit SHA to verify against
        expected_workflow_name: Optional GitHub Actions workflow name to verify

    Returns:
        A sigstore VerificationPolicy configured for SLSA verification

    Example:
        >>> policy = build_default_policy(
        ...     expected_repo="org/repo",
        ...     expected_commit="abc123def456"
        ... )
    """
    policies: list[VerificationPolicy] = [
        # Only accept certificates from GitHub Actions OIDC
        OIDCIssuer(GITHUB_OIDC_ISSUER),
        # Verify repository (workflow ran in this repo)
        GitHubWorkflowRepository(expected_repo),
        # Verify source repository (code came from this repo)
        OIDCSourceRepositoryURI(f"https://github.com/{expected_repo}"),
        # Accept SLSA generator workflow v2.0.0 or v2.1.0
        AnyOf(
            [
                Identity(
                    identity=f"{SLSA_GENERATOR_IDENTITY_PATTERN}@refs/tags/v2.0.0",
                    issuer=GITHUB_OIDC_ISSUER,
                ),
                Identity(
                    identity=f"{SLSA_GENERATOR_IDENTITY_PATTERN}@refs/tags/v2.1.0",
                    issuer=GITHUB_OIDC_ISSUER,
                ),
            ]
        ),
    ]

    if expected_commit:
        # Workflow ran at this commit
        policies.append(GitHubWorkflowSHA(expected_commit))
        # Source code came from this commit
        policies.append(OIDCSourceRepositoryDigest(expected_commit))

    if expected_workflow_name:
        policies.append(GitHubWorkflowName(expected_workflow_name))

    return AllOf(policies)


class ContainerSLSAVerifier:
    """Verify SLSA provenance for container images using sigstore.

    This verifies:
    1. The attestation signature is valid (via Sigstore)
    2. The certificate meets the provided policy requirements

    Example:
        >>> from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository
        >>>
        >>> verifier = ContainerSLSAVerifier()
        >>> policy = AllOf([
        ...     OIDCIssuer("https://token.actions.githubusercontent.com"),
        ...     GitHubWorkflowRepository("org/repo"),
        ... ])
        >>> result = verifier.verify(
        ...     image_ref="ghcr.io/org/repo/image@sha256:...",
        ...     policy=policy,
        ... )
    """

    def __init__(self):
        """Initialize verifier with sigstore production settings."""
        self._verifier = Verifier.production()
        logger.debug("ContainerSLSAVerifier initialized")

    def verify(
        self,
        image_ref: str,
        policy: VerificationPolicy,
    ) -> VerificationResult:
        """Verify SLSA provenance for a container image.

        Args:
            image_ref: Full image reference with digest (e.g., "ghcr.io/org/repo@sha256:...")
            policy: Sigstore verification policy to apply

        Returns:
            VerificationResult with verification status and extracted metadata
        """
        logger.debug(f"Starting SLSA verification for image: {image_ref}")

        try:
            logger.debug("Parsing image reference...")
            image, digest = self._parse_image_ref(image_ref)
            logger.debug(f"Parsed image: {image}, digest: {digest}")

            logger.debug("Fetching attestation from OCI registry...")
            bundle, provenance = self._fetch_attestation(image, digest)
            if not bundle:
                logger.debug("No SLSA attestation found for image")
                return VerificationResult(
                    verified=False,
                    image=image,
                    digest=digest,
                    error="No SLSA attestation found for image",
                )
            logger.debug("Attestation bundle fetched successfully")

            logger.debug("Verifying DSSE bundle with sigstore...")
            try:
                self._verifier.verify_dsse(
                    bundle=bundle,
                    policy=policy,
                )
            except VerificationError as e:
                logger.debug(f"Signature verification failed: {e}")
                return VerificationResult(
                    verified=False,
                    image=image,
                    digest=digest,
                    error=f"Signature verification failed: {str(e)}",
                )

            logger.debug("SLSA verification successful")
            return VerificationResult(
                verified=True,
                image=image,
                digest=digest,
                provenance=provenance,
            )

        except Exception as e:
            logger.debug(f"Verification error: {e}")
            return VerificationResult(
                verified=False,
                image=image_ref,
                digest="unknown",
                error=f"Verification error: {str(e)}",
            )

    def _parse_image_ref(self, image_ref: str) -> tuple[str, str]:
        """Resolve image reference to (image_name, digest).

        Args:
            image_ref: Full image reference with digest

        Returns:
            Tuple of (image_name, digest)

        Raises:
            ValueError: If image reference is missing required components
        """
        container = Container(image_ref)

        if not container.digest:
            raise ValueError(f"Image reference must include a digest: {image_ref}")

        if not container.repository:
            raise ValueError(f"Image reference must include a repository: {image_ref}")

        if not container.registry:
            raise ValueError(f"Image reference must include a registry: {image_ref}")

        namespace = (container.namespace + "/") if container.namespace else ""
        image = f"{container.registry}/{namespace}{container.repository}"

        return image, container.digest

    def _fetch_attestation(
        self, image: str, digest: str
    ) -> tuple[Optional[Bundle], Optional[dict]]:
        """Fetch the Sigstore bundle and provenance from the OCI registry.

        Args:
            image: Image name without digest
            digest: Image digest

        Returns:
            Tuple of (Bundle, provenance_dict) or (None, None) if not found
        """
        # Cosign stores attestations at: <image>:sha256-<hash>.att
        digest_hash = digest.replace("sha256:", "")
        att_ref = f"{image}:sha256-{digest_hash}.att"

        logger.debug(f"Fetching attestation from: {att_ref}")

        container = Container(att_ref)
        registry = Registry()
        manifest = registry.get_manifest(container)

        # Find the SLSA provenance layer
        layer: dict
        for layer in manifest.get("layers", []):
            annotations: dict = layer.get("annotations", {})
            predicate_type: str = annotations.get("predicateType", "")

            # Look for SLSA provenance attestation
            if "slsa.dev/provenance" in predicate_type.lower():
                logger.debug(f"Found SLSA provenance layer: {layer.get('digest')}")
                blob_digest = layer["digest"]

                # Fetch the DSSE envelope
                blob_resp = registry.get_blob(container, blob_digest)
                envelope: dict = json.loads(blob_resp.content)

                # Convert to sigstore Bundle format
                bundle = self._envelope_to_bundle(envelope, annotations)

                # Extract provenance from payload
                payload_b64 = envelope.get("payload", "")
                if payload_b64:
                    provenance = json.loads(base64.b64decode(payload_b64))
                else:
                    provenance = envelope

                return bundle, provenance

        return None, None

    def _envelope_to_bundle(self, envelope: dict, annotations: dict) -> Bundle:
        """Convert a DSSE envelope + cosign annotations to a sigstore Bundle.

        Args:
            envelope: DSSE envelope from attestation
            annotations: Layer annotations containing certificate and bundle info

        Returns:
            Sigstore Bundle object

        Raises:
            ValueError: If attestation cannot be parsed into bundle format
        """
        bundle_json = annotations.get("dev.sigstore.cosign/bundle")
        cert_pem: str = annotations.get("dev.sigstore.cosign/certificate", "")

        if bundle_json:
            cosign_bundle: dict = json.loads(bundle_json)
            payload: dict = cosign_bundle.get("Payload", {})
            log_index = payload.get("logIndex")

            logger.debug(f"Fetching Rekor entry at log index: {log_index}")

            # Fetch the full entry from Rekor using the sigstore client
            rekor_entry = self._fetch_rekor_entry(log_index)
            if not rekor_entry:
                raise ValueError(
                    f"Could not fetch Rekor entry for log index {log_index}"
                )

            cert = load_pem_x509_certificate(cert_pem.encode())
            cert_der_b64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode()

            # Build sigstore bundle using the TransparencyLogEntry's inner model
            bundle_dict = {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {"rawBytes": cert_der_b64},
                    "tlogEntries": [rekor_entry._inner.to_dict()],
                },
                "dsseEnvelope": envelope,
            }

            return Bundle.from_json(json.dumps(bundle_dict).encode())

        raise ValueError("Could not parse attestation into sigstore bundle format")

    def _fetch_rekor_entry(self, log_index: int) -> Optional[TransparencyLogEntry]:
        """Fetch the full Rekor entry including inclusion proof.

        Args:
            log_index: Rekor transparency log index

        Returns:
            TransparencyLogEntry or None if fetch failed
        """
        client = RekorClient.production()
        try:
            return client.log.entries.get(log_index=log_index)
        except Exception as e:
            logger.debug(f"Failed to fetch Rekor entry: {e}")
            return None

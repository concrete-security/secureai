"""Docker Compose Provenance Verification.

This module provides functionality to verify SLSA provenance for all container
images referenced in a docker-compose file.
"""

from dataclasses import dataclass, field

import yaml
from sigstore.verify.policy import VerificationPolicy

from .errors import ProvenanceVerificationError
from .slsa import ContainerSLSAVerifier, VerificationResult, _get_provenance_logger

logger = _get_provenance_logger()


@dataclass
class ServiceVerificationResult:
    """Result of SLSA verification for a single service.

    Attributes:
        service_name: Name of the service in docker-compose
        image_ref: The image reference from docker-compose
        result: The underlying VerificationResult from ContainerSLSAVerifier
    """

    service_name: str
    image_ref: str
    result: VerificationResult


@dataclass
class ProvenanceVerificationResult:
    """Aggregate result of provenance verification for all services.

    Attributes:
        verified: Whether all service verifications succeeded
        service_results: Dict mapping service name to its verification result
        failed_services: List of service names that failed verification
    """

    verified: bool
    service_results: dict[str, ServiceVerificationResult] = field(default_factory=dict)
    failed_services: list[str] = field(default_factory=list)


class DockerComposeProvenanceVerifier:
    """Verify SLSA provenance for all container images in a docker-compose file.

    This verifier parses a docker-compose file, extracts image references for
    each service, and verifies their SLSA provenance according to provided policies.

    Attributes:
        docker_compose: The docker-compose file content (YAML string)
        service_policies: Dict mapping service names to their sigstore policies
        ignore: List of service names to skip (no policy required)

    Example:
        >>> from sigstore.verify.policy import AllOf, OIDCIssuer, GitHubWorkflowRepository
        >>>
        >>> verifier = DockerComposeProvenanceVerifier(
        ...     docker_compose=docker_compose_content,
        ...     service_policies={
        ...         "web": AllOf([
        ...             OIDCIssuer("https://token.actions.githubusercontent.com"),
        ...             GitHubWorkflowRepository("org/web-app"),
        ...         ]),
        ...         "api": AllOf([
        ...             OIDCIssuer("https://token.actions.githubusercontent.com"),
        ...             GitHubWorkflowRepository("org/api-server"),
        ...         ]),
        ...     },
        ...     ignore=["redis", "postgres"],
        ... )
        >>> result = verifier.verify()
    """

    def __init__(
        self,
        docker_compose: str,
        service_policies: dict[str, VerificationPolicy],
        ignore: list[str] | None = None,
    ):
        """Initialize the verifier.

        Parses the docker-compose file and validates that all services have
        policies during initialization, so errors are caught early.

        Args:
            docker_compose: Docker-compose file content as a YAML string
            service_policies: Dict mapping service names to sigstore VerificationPolicy objects
            ignore: List of service names to skip (no policy required for these).
                   Defaults to empty list.

        Raises:
            ValueError: If docker_compose is empty, invalid YAML, has no services,
                or services are missing policies
        """
        if not docker_compose or not docker_compose.strip():
            raise ValueError("docker_compose cannot be empty")

        self.docker_compose = docker_compose
        self.service_policies = service_policies
        self.ignore = ignore or []

        logger.debug("DockerComposeProvenanceVerifier initializing...")
        logger.debug(
            f"  Policies provided for services: {list(service_policies.keys())}"
        )
        logger.debug(f"  Services to ignore: {self.ignore}")

        # Parse docker-compose and validate policies early
        self._service_images = self._parse_docker_compose()
        self._validate_policies(self._service_images)

        logger.debug("DockerComposeProvenanceVerifier initialized successfully")

    def _parse_docker_compose(self) -> dict[str, str]:
        """Parse docker-compose and extract service name to image ref mapping.

        Returns:
            Dict mapping service name to image reference

        Raises:
            ValueError: If parsing fails or no services found
        """
        logger.debug("Parsing docker-compose file...")

        try:
            compose_data = yaml.safe_load(self.docker_compose)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse docker-compose YAML: {e}")

        if not compose_data:
            raise ValueError("Docker-compose file is empty or invalid")

        services = compose_data.get("services", {})
        if not services:
            raise ValueError("No services found in docker-compose file")

        service_images: dict[str, str] = {}
        for service_name, service_config in services.items():
            if service_config is None:
                logger.debug(f"  Service '{service_name}' has no configuration")
                continue

            image_ref = service_config.get("image")
            if image_ref:
                service_images[service_name] = image_ref
                logger.debug(f"  Found service '{service_name}': {image_ref}")
            else:
                logger.debug(
                    f"  Service '{service_name}' has no image (uses build context?)"
                )

        logger.debug(f"Parsed {len(service_images)} services with images")
        return service_images

    def _validate_policies(self, service_images: dict[str, str]) -> None:
        """Validate that all required services have policies.

        Services in the ignore list are excluded from this check.

        Args:
            service_images: Dict mapping service names to image refs

        Raises:
            ValueError: If services lack policies and aren't ignored
        """
        # Services that need policies = all services with images - ignored services
        services_needing_policies = set(service_images.keys()) - set(self.ignore)
        services_with_policies = set(self.service_policies.keys())

        services_without_policies = services_needing_policies - services_with_policies

        if services_without_policies:
            missing = ", ".join(sorted(services_without_policies))
            raise ValueError(
                f"No policies provided for services: {missing}. "
                "Either provide policies for these services or add them to the ignore list."
            )

    def verify(self) -> ProvenanceVerificationResult:
        """Verify SLSA provenance for all services in the docker-compose file.

        Returns:
            ProvenanceVerificationResult with verification status for all services

        Raises:
            ProvenanceVerificationError: If any service verification fails
        """
        logger.debug("Starting provenance verification...")

        # Use the pre-parsed and validated service images from __init__
        service_images = self._service_images

        # Verify each service
        service_results: dict[str, ServiceVerificationResult] = {}
        failed_services: list[str] = []

        # Create a single verifier instance for all services
        slsa_verifier = ContainerSLSAVerifier()

        verified_count = 0
        for service_name, image_ref in service_images.items():
            # Skip ignored services
            if service_name in self.ignore:
                logger.debug(f"Skipping ignored service '{service_name}'")
                continue

            policy = self.service_policies.get(service_name)

            if policy is None:
                # This shouldn't happen after validation, but handle it gracefully
                logger.debug(f"Skipping service '{service_name}' (no policy)")
                continue

            logger.debug(f"Verifying service '{service_name}'...")
            logger.debug(f"  Image: {image_ref}")
            verified_count += 1

            # Verify the image
            result = slsa_verifier.verify(
                image_ref=image_ref,
                policy=policy,
            )

            service_result = ServiceVerificationResult(
                service_name=service_name,
                image_ref=image_ref,
                result=result,
            )
            service_results[service_name] = service_result

            if result.verified:
                logger.debug(f"  Service '{service_name}' verification: PASSED")
            else:
                logger.debug(
                    f"  Service '{service_name}' verification: FAILED - {result.error}"
                )
                failed_services.append(service_name)

        # Determine overall result
        all_verified = (
            len(failed_services) == 0 and len(service_results) == verified_count
        )

        if all_verified:
            logger.debug("All services verified successfully")
            return ProvenanceVerificationResult(
                verified=True,
                service_results=service_results,
            )
        else:
            error_msg = self._build_error_message(failed_services, service_results)
            logger.debug(f"Verification failed: {error_msg}")
            raise ProvenanceVerificationError(
                message=error_msg,
                reason="One or more services failed provenance verification",
            )

    def _build_error_message(
        self,
        failed_services: list[str],
        service_results: dict[str, ServiceVerificationResult],
    ) -> str:
        """Build a detailed error message for failed verifications.

        Args:
            failed_services: List of service names that failed
            service_results: Dict of all service results

        Returns:
            Formatted error message string
        """
        if not failed_services:
            return "No services were verified (no policies matched any services)"

        lines = [
            f"Provenance verification failed for {len(failed_services)} service(s):"
        ]
        for service_name in failed_services:
            result = service_results[service_name]
            lines.append(
                f"  - {service_name} ({result.image_ref}): {result.result.error}"
            )

        return "\n".join(lines)


def verify_docker_compose_provenance(
    docker_compose: str,
    service_policies: dict[str, VerificationPolicy],
    ignore: list[str] | None = None,
) -> ProvenanceVerificationResult:
    """Convenience function to verify SLSA provenance for a docker-compose file.

    Args:
        docker_compose: Docker-compose file content as a YAML string
        service_policies: Dict mapping service names to sigstore VerificationPolicy objects
        ignore: List of service names to skip (no policy required)

    Returns:
        ProvenanceVerificationResult with verification status

    Raises:
        ProvenanceVerificationError: If verification fails

    Example:
        >>> from secureai.provenance import verify_docker_compose_provenance, build_default_policy
        >>>
        >>> result = verify_docker_compose_provenance(
        ...     docker_compose=docker_compose_content,
        ...     service_policies={
        ...         "web": build_default_policy("org/repo"),
        ...     },
        ...     ignore=["redis"],
        ... )
    """
    verifier = DockerComposeProvenanceVerifier(
        docker_compose=docker_compose,
        service_policies=service_policies,
        ignore=ignore,
    )
    return verifier.verify()

"""Tests for DockerComposeProvenanceVerifier."""

from unittest.mock import Mock, patch

import pytest

from secureai.provenance import (
    DockerComposeProvenanceVerifier,
    ProvenanceVerificationError,
    ProvenanceVerificationResult,
    ServiceVerificationResult,
    VerificationResult,
    build_default_policy,
    verify_docker_compose_provenance,
)

SAMPLE_DOCKER_COMPOSE = """
services:
  web:
    image: ghcr.io/org/web-app@sha256:abc123
  api:
    image: ghcr.io/org/api-server@sha256:def456
  db:
    build: ./db
"""

SAMPLE_DOCKER_COMPOSE_SINGLE_SERVICE = """
services:
  web:
    image: ghcr.io/org/web-app@sha256:abc123
"""


class TestDockerComposeProvenanceVerifierInit:
    """Tests for DockerComposeProvenanceVerifier initialization."""

    def test_init_with_valid_inputs(self):
        """Test initialization with valid inputs."""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE,
            service_policies={
                "web": build_default_policy("org/web-app"),
                "api": build_default_policy("org/api-server"),
            },
        )
        assert verifier.ignore == []
        # Verify that service images were parsed
        assert "web" in verifier._service_images
        assert "api" in verifier._service_images

    def test_init_with_empty_docker_compose_raises_error(self):
        """Test that empty docker_compose raises ValueError."""
        with pytest.raises(ValueError, match="docker_compose cannot be empty"):
            DockerComposeProvenanceVerifier(
                docker_compose="",
                service_policies={},
            )

    def test_init_with_whitespace_only_raises_error(self):
        """Test that whitespace-only docker_compose raises ValueError."""
        with pytest.raises(ValueError, match="docker_compose cannot be empty"):
            DockerComposeProvenanceVerifier(
                docker_compose="   \n\t  ",
                service_policies={},
            )

    def test_init_with_ignore_list(self):
        """Test initialization with ignore list."""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE,
            service_policies={
                "web": build_default_policy("org/web-app"),
            },
            ignore=["api"],
        )
        assert verifier.ignore == ["api"]

    def test_init_with_none_ignore_defaults_to_empty_list(self):
        """Test initialization with None ignore defaults to empty list."""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE,
            service_policies={
                "web": build_default_policy("org/web-app"),
                "api": build_default_policy("org/api-server"),
            },
            ignore=None,
        )
        assert verifier.ignore == []

    def test_init_with_invalid_yaml_raises_error(self):
        """Test that invalid YAML raises ValueError during init."""
        with pytest.raises(ValueError, match="Failed to parse"):
            DockerComposeProvenanceVerifier(
                docker_compose="invalid: yaml: content: [",
                service_policies={},
            )

    def test_init_with_empty_compose_raises_error(self):
        """Test that empty compose data raises ValueError during init."""
        with pytest.raises(ValueError, match="empty or invalid"):
            DockerComposeProvenanceVerifier(
                docker_compose="# Just a comment",
                service_policies={},
            )

    def test_init_with_no_services_raises_error(self):
        """Test that compose without services raises ValueError during init."""
        with pytest.raises(ValueError, match="No services found"):
            DockerComposeProvenanceVerifier(
                docker_compose="version: '3'\nnetworks:\n  default:",
                service_policies={},
            )

    def test_init_with_missing_policies_raises_error(self):
        """Test that missing policies raises ValueError during init."""
        with pytest.raises(ValueError, match="No policies provided for services: api"):
            DockerComposeProvenanceVerifier(
                docker_compose=SAMPLE_DOCKER_COMPOSE,
                service_policies={
                    "web": build_default_policy("org/web-app"),
                    # Missing policy for "api"
                },
            )

    def test_init_allows_ignored_services_without_policies(self):
        """Test that ignored services don't need policies during init."""
        # Should not raise - api is ignored
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE,
            service_policies={
                "web": build_default_policy("org/web-app"),
            },
            ignore=["api"],
        )
        assert "web" in verifier._service_images
        assert "api" in verifier._service_images  # Still parsed, just ignored

    def test_extra_policies_for_nonexistent_services_allowed(self):
        """Test that extra policies for non-existent services don't cause errors."""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE_SINGLE_SERVICE,
            service_policies={
                "web": build_default_policy("org/web-app"),
                "nonexistent": build_default_policy("org/nonexistent"),
            },
        )

        # Should succeed - extra policies are just ignored
        assert "web" in verifier._service_images
        assert "nonexistent" not in verifier._service_images

    def test_complex_docker_compose_with_mixed_services(self):
        """Test complex compose with mix of images, builds, and empty services."""
        docker_compose = """
version: "3.8"
services:
  web:
    image: ghcr.io/org/web@sha256:abc
    ports:
      - "8080:80"
  api:
    image: ghcr.io/org/api@sha256:def
    environment:
      - DEBUG=true
  worker:
    build:
      context: ./worker
      args:
        - VERSION=1.0
  db:
    image: postgres:15
  cache:
networks:
  default:
volumes:
  data:
"""
        # web and api need policies (have images with digests)
        # db has image but no digest - it's included in service_images
        # worker uses build context - excluded
        # cache is empty - excluded
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "web": build_default_policy("org/web"),
                "api": build_default_policy("org/api"),
                "db": build_default_policy("postgres"),
            },
        )

        assert "web" in verifier._service_images
        assert "api" in verifier._service_images
        assert "db" in verifier._service_images  # Has image (even without digest)
        assert "worker" not in verifier._service_images
        assert "cache" not in verifier._service_images


class TestDockerComposeProvenanceVerifierParsing:
    """Tests for docker-compose parsing."""

    def test_parse_extracts_service_images(self):
        """Test that parsing extracts service images correctly."""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=SAMPLE_DOCKER_COMPOSE,
            service_policies={
                "web": build_default_policy("org/web-app"),
                "api": build_default_policy("org/api-server"),
            },
        )

        assert "web" in verifier._service_images
        assert "api" in verifier._service_images
        assert verifier._service_images["web"] == "ghcr.io/org/web-app@sha256:abc123"
        assert verifier._service_images["api"] == "ghcr.io/org/api-server@sha256:def456"
        # db service uses build context, so no image
        assert "db" not in verifier._service_images

    def test_service_with_null_config_is_skipped(self):
        """Test that service with null config is skipped during parsing."""
        docker_compose = """
services:
  web:
    image: ghcr.io/org/web@sha256:abc123
  empty_service:
"""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "web": build_default_policy("org/web"),
            },
        )

        # empty_service should not be in service_images
        assert "web" in verifier._service_images
        assert "empty_service" not in verifier._service_images

    def test_service_with_build_context_only_is_skipped(self):
        """Test that service using build context (no image) is skipped."""
        docker_compose = """
services:
  web:
    image: ghcr.io/org/web@sha256:abc123
  builder:
    build:
      context: ./app
      dockerfile: Dockerfile
"""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "web": build_default_policy("org/web"),
            },
        )

        assert "web" in verifier._service_images
        assert "builder" not in verifier._service_images

    def test_all_services_use_build_context_no_images_to_verify(self):
        """Test compose where all services use build context (no images)."""
        docker_compose = """
services:
  app:
    build: ./app
  worker:
    build: ./worker
"""
        # Should not raise - no services with images means nothing to verify
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={},
        )

        assert len(verifier._service_images) == 0


class TestDockerComposeProvenanceVerifierVerify:
    """Tests for verify method."""

    def test_verify_returns_success_when_all_pass(self):
        """Test verify returns success when all verifications pass."""
        mock_result = VerificationResult(
            verified=True,
            image="test",
            digest="sha256:abc",
            provenance={"test": "data"},
        )

        with patch(
            "secureai.provenance.verifier.ContainerSLSAVerifier"
        ) as mock_verifier_class:
            mock_verifier = Mock()
            mock_verifier.verify.return_value = mock_result
            mock_verifier_class.return_value = mock_verifier

            verifier = DockerComposeProvenanceVerifier(
                docker_compose=SAMPLE_DOCKER_COMPOSE,
                service_policies={
                    "web": build_default_policy("org/web-app"),
                    "api": build_default_policy("org/api-server"),
                },
            )

            result = verifier.verify()
            assert result.verified is True
            assert "web" in result.service_results
            assert "api" in result.service_results

    def test_verify_raises_error_when_any_fail(self):
        """Test verify raises error when any verification fails."""

        def mock_verify(image_ref, policy):  # noqa: ARG001
            if "web" in image_ref:
                return VerificationResult(
                    verified=True,
                    image=image_ref,
                    digest="sha256:abc",
                )
            else:
                return VerificationResult(
                    verified=False,
                    image=image_ref,
                    digest="sha256:def",
                    error="No attestation found",
                )

        with patch(
            "secureai.provenance.verifier.ContainerSLSAVerifier"
        ) as mock_verifier_class:
            mock_verifier = Mock()
            mock_verifier.verify.side_effect = mock_verify
            mock_verifier_class.return_value = mock_verifier

            verifier = DockerComposeProvenanceVerifier(
                docker_compose=SAMPLE_DOCKER_COMPOSE,
                service_policies={
                    "web": build_default_policy("org/web-app"),
                    "api": build_default_policy("org/api-server"),
                },
            )

            with pytest.raises(ProvenanceVerificationError) as exc_info:
                verifier.verify()

            assert "api" in str(exc_info.value)
            assert "No attestation found" in str(exc_info.value)

    def test_verify_skips_ignored_services(self):
        """Test verify skips services in ignore list."""
        mock_result = VerificationResult(
            verified=True,
            image="test",
            digest="sha256:abc",
        )

        with patch(
            "secureai.provenance.verifier.ContainerSLSAVerifier"
        ) as mock_verifier_class:
            mock_verifier = Mock()
            mock_verifier.verify.return_value = mock_result
            mock_verifier_class.return_value = mock_verifier

            verifier = DockerComposeProvenanceVerifier(
                docker_compose=SAMPLE_DOCKER_COMPOSE,
                service_policies={
                    "web": build_default_policy("org/web-app"),
                },
                ignore=["api"],
            )

            result = verifier.verify()
            assert result.verified is True
            assert "web" in result.service_results
            assert "api" not in result.service_results

            # Verify only web service was verified (api was ignored)
            assert mock_verifier.verify.call_count == 1
            # Check that the call was for web, not api
            call_args = mock_verifier.verify.call_args
            image_ref = call_args.kwargs.get(
                "image_ref", call_args.args[0] if call_args.args else ""
            )
            assert "web" in image_ref


class TestVerifyDockerComposeProvenanceFunction:
    """Tests for verify_docker_compose_provenance convenience function."""

    def test_function_creates_verifier_and_calls_verify(self):
        """Test convenience function works correctly."""
        mock_result = VerificationResult(
            verified=True,
            image="test",
            digest="sha256:abc",
        )

        with patch(
            "secureai.provenance.verifier.ContainerSLSAVerifier"
        ) as mock_verifier_class:
            mock_verifier = Mock()
            mock_verifier.verify.return_value = mock_result
            mock_verifier_class.return_value = mock_verifier

            result = verify_docker_compose_provenance(
                docker_compose=SAMPLE_DOCKER_COMPOSE_SINGLE_SERVICE,
                service_policies={
                    "web": build_default_policy("org/web-app"),
                },
            )

            assert result.verified is True


class TestProvenanceVerificationResult:
    """Tests for ProvenanceVerificationResult dataclass."""

    def test_create_successful_result(self):
        """Test creating a successful result."""
        result = ProvenanceVerificationResult(
            verified=True,
            service_results={
                "web": ServiceVerificationResult(
                    service_name="web",
                    image_ref="ghcr.io/org/web@sha256:abc",
                    result=VerificationResult(
                        verified=True,
                        image="ghcr.io/org/web",
                        digest="sha256:abc",
                    ),
                )
            },
        )

        assert result.verified is True
        assert "web" in result.service_results
        assert result.failed_services == []

    def test_create_failed_result(self):
        """Test creating a failed result."""
        result = ProvenanceVerificationResult(
            verified=False,
            failed_services=["api"],
        )

        assert result.verified is False
        assert "api" in result.failed_services


class TestServiceVerificationResult:
    """Tests for ServiceVerificationResult dataclass."""

    def test_create_result(self):
        """Test creating a service verification result."""
        inner_result = VerificationResult(
            verified=True,
            image="ghcr.io/org/web",
            digest="sha256:abc",
        )

        result = ServiceVerificationResult(
            service_name="web",
            image_ref="ghcr.io/org/web@sha256:abc",
            result=inner_result,
        )

        assert result.service_name == "web"
        assert result.image_ref == "ghcr.io/org/web@sha256:abc"
        assert result.result.verified is True

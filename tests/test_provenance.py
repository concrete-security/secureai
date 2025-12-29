"""Provenance verification tests with real images.

These tests verify SLSA provenance against real container images in registries.
They require network access.
"""

import pytest

from secureai.provenance import (
    ContainerSLSAVerifier,
    DockerComposeProvenanceVerifier,
    ProvenanceVerificationError,
    build_default_policy,
)

# Test images with valid SLSA provenance
AUTH_SERVICE_IMAGE = "ghcr.io/concrete-security/auth-service@sha256:f819c57d1648a4b4340fc296ef9872e43b70c7190d67a93820cf4f7b657d5310"
CERT_MANAGER_IMAGE = "ghcr.io/concrete-security/cert-manager@sha256:92655a24060497516ea0cfd79b7fbfb599f13d303eb0c3e9c79cf8c5ee9cc1d1"

# Test image without SLSA provenance
HELLO_WORLD_IMAGE = "docker.io/library/hello-world@sha256:5b3cc85e16e3058003c13b7821318369dad01dac3dbb877aac3c28182255c724"

# Expected repository for concrete-security images
EXPECTED_REPO = "concrete-security/umbra"
EXPECTED_COMMIT_SHA = "289024336e699c1936d36516936841532db75c11"


class TestContainerSLSAVerifier:
    """Tests for ContainerSLSAVerifier with real images."""

    def test_verify_auth_service_with_valid_policy(self):
        """Test verifying auth-service image with correct policy."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy(
            expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
        )

        result = verifier.verify(
            image_ref=AUTH_SERVICE_IMAGE,
            policy=policy,
        )

        assert result.verified is True
        assert result.image is not None
        assert (
            result.digest
            == "sha256:f819c57d1648a4b4340fc296ef9872e43b70c7190d67a93820cf4f7b657d5310"
        )
        assert result.provenance is not None
        assert result.error is None

    def test_verify_cert_manager_with_valid_policy(self):
        """Test verifying cert-manager image with correct policy."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy(
            expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
        )

        result = verifier.verify(
            image_ref=CERT_MANAGER_IMAGE,
            policy=policy,
        )

        assert result.verified is True
        assert result.image is not None
        assert (
            result.digest
            == "sha256:92655a24060497516ea0cfd79b7fbfb599f13d303eb0c3e9c79cf8c5ee9cc1d1"
        )
        assert result.provenance is not None
        assert result.error is None

    def test_verify_hello_world_fails_no_attestation(self):
        """Test that hello-world image fails (no SLSA attestation)."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy(expected_repo="library/hello-world")

        result = verifier.verify(
            image_ref=HELLO_WORLD_IMAGE,
            policy=policy,
        )

        assert result.verified is False
        assert result.error is not None

    def test_verify_with_wrong_repo_fails(self):
        """Test that verification fails when expected repo doesn't match."""
        verifier = ContainerSLSAVerifier()
        # Use wrong repository
        policy = build_default_policy(expected_repo="wrong-org/wrong-repo")

        result = verifier.verify(
            image_ref=AUTH_SERVICE_IMAGE,
            policy=policy,
        )

        assert result.verified is False
        assert result.error is not None


class TestDockerComposeProvenanceVerifier:
    """Tests for DockerComposeProvenanceVerifier with real images."""

    def test_verify_docker_compose_with_valid_images(self):
        """Test verifying a docker-compose with valid SLSA images."""
        docker_compose = f"""
services:
  auth:
    image: {AUTH_SERVICE_IMAGE}
  cert-manager:
    image: {CERT_MANAGER_IMAGE}
"""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "auth": build_default_policy(
                    expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
                ),
                "cert-manager": build_default_policy(
                    expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
                ),
            },
        )

        result = verifier.verify()

        assert result.verified is True
        assert "auth" in result.service_results
        assert "cert-manager" in result.service_results
        assert result.service_results["auth"].result.verified is True
        assert result.service_results["cert-manager"].result.verified is True

    def test_verify_docker_compose_with_invalid_image_fails(self):
        """Test that docker-compose verification fails when one image has no attestation."""
        docker_compose = f"""
services:
  auth:
    image: {AUTH_SERVICE_IMAGE}
  hello:
    image: {HELLO_WORLD_IMAGE}
"""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "auth": build_default_policy(
                    expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
                ),
                "hello": build_default_policy(expected_repo="library/hello-world"),
            },
        )

        with pytest.raises(ProvenanceVerificationError) as exc_info:
            verifier.verify()

        assert "hello" in str(exc_info.value)

    def test_verify_docker_compose_with_ignored_service(self):
        """Test that ignored services are skipped."""
        docker_compose = f"""
services:
  auth:
    image: {AUTH_SERVICE_IMAGE}
  hello:
    image: {HELLO_WORLD_IMAGE}
"""
        verifier = DockerComposeProvenanceVerifier(
            docker_compose=docker_compose,
            service_policies={
                "auth": build_default_policy(
                    expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
                ),
            },
            ignore=["hello"],  # Ignore the hello-world service
        )

        result = verifier.verify()

        assert result.verified is True
        assert "auth" in result.service_results
        assert "hello" not in result.service_results

    def test_verify_docker_compose_missing_policy_raises_error(self):
        """Test that missing policy for a service raises error during init."""
        docker_compose = f"""
services:
  auth:
    image: {AUTH_SERVICE_IMAGE}
  hello:
    image: {HELLO_WORLD_IMAGE}
"""
        with pytest.raises(ValueError) as exc_info:
            DockerComposeProvenanceVerifier(
                docker_compose=docker_compose,
                service_policies={
                    "auth": build_default_policy(
                        expected_repo=EXPECTED_REPO, expected_commit=EXPECTED_COMMIT_SHA
                    ),
                    # Missing policy for "hello"
                },
            )

        assert "hello" in str(exc_info.value)
        assert "No policies provided" in str(exc_info.value)

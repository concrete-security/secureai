"""Tests for ContainerSLSAVerifier and build_default_policy."""

from unittest.mock import Mock, patch

import pytest
from sigstore.verify.policy import AllOf

from secureai.provenance import (
    ContainerSLSAVerifier,
    VerificationResult,
    build_default_policy,
)
from secureai.provenance.slsa import (
    GITHUB_OIDC_ISSUER,
    SLSA_GENERATOR_IDENTITY_PATTERN,
)


class TestBuildDefaultPolicy:
    """Tests for build_default_policy helper function."""

    def test_build_policy_with_repo_only(self):
        """Test building policy with only required repo parameter."""
        policy = build_default_policy(expected_repo="org/repo")

        # Should return an AllOf policy
        assert isinstance(policy, AllOf)

    def test_build_policy_with_commit(self):
        """Test building policy with commit SHA."""
        policy = build_default_policy(
            expected_repo="org/repo",
            expected_commit="abc123def456",
        )

        assert isinstance(policy, AllOf)

    def test_build_policy_with_workflow_name(self):
        """Test building policy with workflow name."""
        policy = build_default_policy(
            expected_repo="org/repo",
            expected_workflow_name="build.yml",
        )

        assert isinstance(policy, AllOf)

    def test_build_policy_with_all_options(self):
        """Test building policy with all optional parameters."""
        policy = build_default_policy(
            expected_repo="org/repo",
            expected_commit="abc123",
            expected_workflow_name="release.yml",
        )

        assert isinstance(policy, AllOf)

    def test_build_policy_with_empty_repo(self):
        """Test build_default_policy with empty repo string."""
        # Empty repo is allowed - it's up to sigstore to validate
        policy = build_default_policy(expected_repo="")
        assert isinstance(policy, AllOf)


class TestContainerSLSAVerifierInit:
    """Tests for ContainerSLSAVerifier initialization."""

    def test_init_creates_verifier(self):
        """Test that init creates a verifier."""
        verifier = ContainerSLSAVerifier()
        assert verifier._verifier is not None


class TestContainerSLSAVerifierParseImageRef:
    """Tests for image reference parsing."""

    def test_parse_valid_image_ref_with_digest(self):
        """Test parsing a valid image reference with digest."""
        verifier = ContainerSLSAVerifier()
        image, digest = verifier._parse_image_ref(
            "ghcr.io/org/namespace/repo@sha256:abc123def456"
        )
        assert image == "ghcr.io/org/namespace/repo"
        assert digest == "sha256:abc123def456"

    def test_parse_image_ref_without_digest_raises_error(self):
        """Test that image ref without digest raises error."""
        verifier = ContainerSLSAVerifier()
        with pytest.raises(ValueError, match="must include a digest"):
            verifier._parse_image_ref("ghcr.io/org/repo:latest")

    def test_parse_image_ref_without_namespace_works(self):
        """Test that image ref without namespace works."""
        verifier = ContainerSLSAVerifier()
        image, digest = verifier._parse_image_ref("ghcr.io/repo@sha256:abc123")
        assert image == "ghcr.io/repo"
        assert digest == "sha256:abc123"

    def test_parse_image_ref_without_registry_uses_dockerio(self):
        """Test that image ref without registry uses docker.io."""
        verifier = ContainerSLSAVerifier()
        # oras.Container uses docker.io as default registry
        image, digest = verifier._parse_image_ref("repo@sha256:abc123")
        assert image == "docker.io/repo"
        assert digest == "sha256:abc123"

    def test_parse_image_ref_with_tag_and_digest(self):
        """Test image ref with both tag and digest uses digest."""
        verifier = ContainerSLSAVerifier()
        # When both tag and digest present, digest should be used
        image, digest = verifier._parse_image_ref(
            "ghcr.io/org/repo:v1.0.0@sha256:abc123"
        )
        assert digest == "sha256:abc123"
        assert image == "ghcr.io/org/repo"

    def test_parse_image_ref_with_port_in_registry(self):
        """Test image ref with port number in registry."""
        verifier = ContainerSLSAVerifier()
        image, digest = verifier._parse_image_ref(
            "localhost:5000/myimage@sha256:abc123"
        )
        assert image == "localhost:5000/myimage"
        assert digest == "sha256:abc123"

    def test_parse_image_ref_with_deeply_nested_namespace(self):
        """Test image ref with deeply nested namespace."""
        verifier = ContainerSLSAVerifier()
        image, digest = verifier._parse_image_ref(
            "ghcr.io/org/team/project/service@sha256:abc123"
        )
        assert image == "ghcr.io/org/team/project/service"
        assert digest == "sha256:abc123"


class TestContainerSLSAVerifierVerify:
    """Tests for verify method."""

    def test_verify_returns_false_when_no_attestation(self):
        """Test verify returns false when no attestation found."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy("org/repo")

        with patch.object(verifier, "_fetch_attestation", return_value=(None, None)):
            result = verifier.verify(
                "ghcr.io/org/namespace/repo@sha256:abc",
                policy=policy,
            )

            assert result.verified is False
            assert "No SLSA attestation found" in result.error

    def test_verify_returns_result_on_exception(self):
        """Test verify returns error result on exception."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy("org/repo")

        with patch.object(
            verifier, "_parse_image_ref", side_effect=ValueError("Parse error")
        ):
            result = verifier.verify(
                "invalid-ref",
                policy=policy,
            )

            assert result.verified is False
            assert "Verification error" in result.error
            assert "Parse error" in result.error

    def test_verify_returns_success_when_all_checks_pass(self):
        """Test verify returns success when verification passes."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy("org/repo")

        mock_bundle = Mock()
        mock_provenance = {"builder": {"id": "test"}}

        with patch.object(
            verifier, "_parse_image_ref", return_value=("image", "sha256:abc")
        ):
            with patch.object(
                verifier,
                "_fetch_attestation",
                return_value=(mock_bundle, mock_provenance),
            ):
                with patch.object(verifier._verifier, "verify_dsse"):
                    result = verifier.verify(
                        "ghcr.io/org/namespace/repo@sha256:abc",
                        policy=policy,
                    )

                    assert result.verified is True
                    assert result.provenance == mock_provenance


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_create_successful_result(self):
        """Test creating a successful verification result."""
        result = VerificationResult(
            verified=True,
            image="ghcr.io/org/repo",
            digest="sha256:abc123",
            provenance={"test": "data"},
        )

        assert result.verified is True
        assert result.image == "ghcr.io/org/repo"
        assert result.digest == "sha256:abc123"
        assert result.provenance == {"test": "data"}
        assert result.error is None

    def test_create_failed_result(self):
        """Test creating a failed verification result."""
        result = VerificationResult(
            verified=False,
            image="ghcr.io/org/repo",
            digest="sha256:abc123",
            error="Verification failed",
        )

        assert result.verified is False
        assert result.error == "Verification failed"
        assert result.provenance is None


class TestConstants:
    """Tests for module constants."""

    def test_github_oidc_issuer_is_correct(self):
        """Test GitHub OIDC issuer constant."""
        assert GITHUB_OIDC_ISSUER == "https://token.actions.githubusercontent.com"

    def test_slsa_generator_pattern_is_correct(self):
        """Test SLSA generator identity pattern constant."""
        assert "slsa-framework/slsa-github-generator" in SLSA_GENERATOR_IDENTITY_PATTERN
        assert "generator_container_slsa3.yml" in SLSA_GENERATOR_IDENTITY_PATTERN


class TestContainerSLSAVerifierMisc:
    """Tests for other cases in ContainerSLSAVerifier."""

    def test_fetch_attestation_no_layers_returns_none(self):
        """Test _fetch_attestation returns None when manifest has no layers."""
        verifier = ContainerSLSAVerifier()

        with patch("secureai.provenance.slsa.Registry") as mock_registry_class:
            mock_registry = Mock()
            mock_registry.get_manifest.return_value = {"layers": []}
            mock_registry_class.return_value = mock_registry

            result = verifier._fetch_attestation("ghcr.io/org/repo", "sha256:abc")
            assert result == (None, None)

    def test_fetch_attestation_no_slsa_layer_returns_none(self):
        """Test _fetch_attestation returns None when no SLSA provenance layer."""
        verifier = ContainerSLSAVerifier()

        with patch("secureai.provenance.slsa.Registry") as mock_registry_class:
            mock_registry = Mock()
            mock_registry.get_manifest.return_value = {
                "layers": [
                    {
                        "digest": "sha256:layer1",
                        "annotations": {"predicateType": "some/other/type"},
                    },
                    {
                        "digest": "sha256:layer2",
                        "annotations": {},
                    },
                ]
            }
            mock_registry_class.return_value = mock_registry

            result = verifier._fetch_attestation("ghcr.io/org/repo", "sha256:abc")
            assert result == (None, None)

    def test_envelope_to_bundle_without_bundle_json_raises_error(self):
        """Test _envelope_to_bundle raises when no bundle_json annotation."""
        verifier = ContainerSLSAVerifier()
        envelope = {"payload": "test", "signatures": []}
        annotations = {"dev.sigstore.cosign/certificate": "cert-data"}

        with pytest.raises(ValueError, match="Could not parse attestation"):
            verifier._envelope_to_bundle(envelope, annotations)

    def test_fetch_rekor_entry_returns_none_on_exception(self):
        """Test _fetch_rekor_entry returns None when fetch fails."""
        verifier = ContainerSLSAVerifier()

        with patch("secureai.provenance.slsa.RekorClient") as mock_rekor_class:
            mock_client = Mock()
            mock_client.log.entries.get.side_effect = Exception("Network error")
            mock_rekor_class.production.return_value = mock_client

            result = verifier._fetch_rekor_entry(12345)
            assert result is None

    def test_verify_signature_verification_failure(self):
        """Test verify handles sigstore VerificationError gracefully."""
        from sigstore.errors import VerificationError as SigstoreVerificationError

        verifier = ContainerSLSAVerifier()
        policy = build_default_policy("org/repo")

        mock_bundle = Mock()
        mock_provenance = {"test": "data"}

        with patch.object(
            verifier, "_parse_image_ref", return_value=("image", "sha256:abc")
        ):
            with patch.object(
                verifier,
                "_fetch_attestation",
                return_value=(mock_bundle, mock_provenance),
            ):
                with patch.object(
                    verifier._verifier,
                    "verify_dsse",
                    side_effect=SigstoreVerificationError("Certificate mismatch"),
                ):
                    result = verifier.verify(
                        "ghcr.io/org/repo@sha256:abc",
                        policy=policy,
                    )

                    assert result.verified is False
                    assert "Signature verification failed" in result.error
                    assert "Certificate mismatch" in result.error

    def test_verify_general_exception_returns_error_result(self):
        """Test verify catches general exceptions and returns error result."""
        verifier = ContainerSLSAVerifier()
        policy = build_default_policy("org/repo")

        with patch.object(
            verifier, "_parse_image_ref", side_effect=RuntimeError("Unexpected error")
        ):
            result = verifier.verify(
                "ghcr.io/org/repo@sha256:abc",
                policy=policy,
            )

            assert result.verified is False
            assert "Verification error" in result.error
            assert "Unexpected error" in result.error
            # When exception occurs early, image is set to the original ref
            assert result.image == "ghcr.io/org/repo@sha256:abc"
            assert result.digest == "unknown"

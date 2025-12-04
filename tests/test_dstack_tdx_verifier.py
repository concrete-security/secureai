"""Tests for DstackTDXVerifier initialization and configuration."""

import warnings
from unittest.mock import patch

import pytest

from secureai.verifiers.tdx import (
    DstackTDXVerifier,
    default_app_compose_from_docker_compose,
)


class TestDstackTDXVerifierInit:
    """Tests for DstackTDXVerifier initialization."""

    def test_init_default(self):
        """Test default initialization without any parameters."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            verifier = DstackTDXVerifier()

            # Should warn about no app_compose
            assert len(w) == 1
            assert "RATLS won't verify remote TEE runs a specific application" in str(
                w[0].message
            )
            assert issubclass(w[0].category, UserWarning)

        assert verifier.app_compose is None
        assert verifier.allowed_tcb_status == ["UpToDate"]
        assert verifier.collateral is not None

    def test_init_with_app_compose(self):
        """Test initialization with app_compose."""
        app_compose = {
            "docker_compose_file": "version: '3'\nservices:\n  app:\n    image: test",
            "features": ["kms"],
        }

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            verifier = DstackTDXVerifier(app_compose=app_compose)

            # Should not warn when app_compose is provided
            assert len(w) == 0

        assert verifier.app_compose == app_compose

    def test_init_with_docker_compose_file(self):
        """Test initialization with docker_compose_file."""
        docker_compose = "version: '3'\nservices:\n  web:\n    image: nginx"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            verifier = DstackTDXVerifier(docker_compose_file=docker_compose)

            # Should not warn when docker_compose_file is provided
            assert len(w) == 0

        assert verifier.app_compose is not None
        assert verifier.app_compose["docker_compose_file"] == docker_compose

    def test_init_with_both_app_compose_and_docker_compose_raises_error(self):
        """Test that providing both app_compose and docker_compose_file raises ValueError."""
        app_compose = {"docker_compose_file": "test"}
        docker_compose = "version: '3'"

        with pytest.raises(
            ValueError,
            match="You can only provide one of docker_compose_file or app_compose",
        ):
            DstackTDXVerifier(
                app_compose=app_compose,
                docker_compose_file=docker_compose,
            )

    def test_init_with_valid_tcb_status(self):
        """Test initialization with valid allowed_tcb_status."""
        verifier = DstackTDXVerifier(allowed_tcb_status=["UpToDate", "OutOfDate"])
        assert verifier.allowed_tcb_status == ["UpToDate", "OutOfDate"]

    def test_init_with_all_valid_tcb_statuses(self):
        """Test initialization with all valid TCB statuses."""
        all_statuses = [
            "UpToDate",
            "OutOfDate",
            "ConfigurationNeeded",
            "TDRelaunchAdvised",
            "SWHardeningNeeded",
            "Revoked",
        ]
        verifier = DstackTDXVerifier(allowed_tcb_status=all_statuses)
        assert verifier.allowed_tcb_status == all_statuses

    def test_init_with_invalid_tcb_status_raises_error(self):
        """Test that providing invalid TCB status raises ValueError."""
        with pytest.raises(ValueError, match="TCB status must be one of"):
            DstackTDXVerifier(allowed_tcb_status=["InvalidStatus"])

    def test_init_with_mixed_valid_and_invalid_tcb_status_raises_error(self):
        """Test that mixing valid and invalid TCB statuses raises ValueError."""
        with pytest.raises(ValueError, match="TCB status must be one of"):
            DstackTDXVerifier(allowed_tcb_status=["UpToDate", "BadStatus"])

    def test_init_with_empty_tcb_status_raises_error(self):
        """Test that empty allowed_tcb_status list raises ValueError."""
        with pytest.raises(ValueError, match="allowed_tcb_status cannot be empty"):
            DstackTDXVerifier(allowed_tcb_status=[])

    def test_init_with_custom_collateral(self):
        """Test initialization with custom collateral."""
        # Minimal valid collateral structure
        custom_collateral = {
            "tcb_info_issuer_chain": "test",
            "tcb_info": "{}",
            "qe_identity_issuer_chain": "test",
            "qe_identity": "{}",
            "pck_crl_issuer_chain": "test",
            "root_ca_crl": "test",
            "pck_crl": "test",
        }

        with patch("dcap_qvl.QuoteCollateralV3.from_json") as mock_from_json:
            mock_from_json.return_value = "mocked_collateral"
            verifier = DstackTDXVerifier(collateral=custom_collateral)

            mock_from_json.assert_called_once()

        assert verifier.collateral == "mocked_collateral"

    def test_init_loads_default_collateral_when_none_provided(self):
        """Test that default collateral is loaded when none is provided."""
        verifier = DstackTDXVerifier()
        # Collateral should be loaded from the local file
        assert verifier.collateral is not None


class TestDstackTDXVerifierGetAppComposeHash:
    """Tests for DstackTDXVerifier.get_app_compose_hash method."""

    def test_get_app_compose_hash_returns_none_when_no_app_compose(self):
        """Test that get_app_compose_hash returns None when app_compose is not set."""
        verifier = DstackTDXVerifier()
        assert verifier.get_app_compose_hash() is None

    def test_get_app_compose_hash_returns_hash_when_app_compose_set(self):
        """Test that get_app_compose_hash returns a hash when app_compose is set."""
        docker_compose = "version: '3'\nservices:\n  web:\n    image: nginx"
        verifier = DstackTDXVerifier(docker_compose_file=docker_compose)

        hash_result = verifier.get_app_compose_hash()

        assert hash_result is not None
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA-256 hex encoded


class TestDefaultAppComposeFromDockerCompose:
    """Tests for the default_app_compose_from_docker_compose function."""

    def test_creates_valid_app_compose(self):
        """Test that function creates a valid app_compose structure."""
        docker_compose = "version: '3'\nservices:\n  app:\n    image: test"

        result = default_app_compose_from_docker_compose(docker_compose)

        assert result["docker_compose_file"] == docker_compose
        assert "allowed_envs" in result
        assert "features" in result
        assert "runner" in result
        assert result["runner"] == "docker-compose"

    def test_includes_expected_features(self):
        """Test that the default app_compose includes expected features."""
        docker_compose = "test compose content"

        result = default_app_compose_from_docker_compose(docker_compose)

        assert "kms" in result["features"]
        assert "tproxy-net" in result["features"]

    def test_includes_expected_settings(self):
        """Test that the default app_compose includes expected settings."""
        docker_compose = "test compose content"

        result = default_app_compose_from_docker_compose(docker_compose)

        assert result["gateway_enabled"] is True
        assert result["kms_enabled"] is True
        assert result["local_key_provider_enabled"] is False
        assert result["public_logs"] is True
        assert result["public_sysinfo"] is True
        assert result["public_tcbinfo"] is True


class TestDstackTDXVerifierClassAttributes:
    """Tests for DstackTDXVerifier class attributes."""

    def test_rtmr_count(self):
        """Test RTMR_COUNT class attribute."""
        assert DstackTDXVerifier.RTMR_COUNT == 4

    def test_default_quote_endpoint(self):
        """Test DEFAULT_QUOTE_ENDPOINT class attribute."""
        assert DstackTDXVerifier.DEFAULT_QUOTE_ENDPOINT == "/tdx_quote"

    def test_tcb_status_list_contains_expected_values(self):
        """Test TCB_STATUS_LIST contains all expected values."""
        expected_statuses = [
            "UpToDate",
            "OutOfDate",
            "ConfigurationNeeded",
            "TDRelaunchAdvised",
            "SWHardeningNeeded",
            "Revoked",
        ]

        assert DstackTDXVerifier.TCB_STATUS_LIST == expected_statuses

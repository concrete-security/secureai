"""Tests for provenance verification errors."""

import pytest

from secureai.provenance import ProvenanceVerificationError


class TestProvenanceVerificationError:
    """Tests for ProvenanceVerificationError."""

    def test_init_with_message_only(self):
        """Test creating error with message only."""
        error = ProvenanceVerificationError("Test error")
        assert str(error) == "Test error"
        assert error.service is None
        assert error.image is None
        assert error.reason is None

    def test_init_with_all_attributes(self):
        """Test creating error with all attributes."""
        error = ProvenanceVerificationError(
            message="Test error",
            service="web",
            image="ghcr.io/org/image@sha256:abc123",
            reason="No attestation found",
        )
        assert str(error) == "Test error"
        assert error.service == "web"
        assert error.image == "ghcr.io/org/image@sha256:abc123"
        assert error.reason == "No attestation found"

    def test_raise(self):
        """Test that error can be raised and caught."""
        with pytest.raises(ProvenanceVerificationError) as exc_info:
            raise ProvenanceVerificationError(
                "Verification failed",
                service="api",
            )

        assert exc_info.value.service == "api"
        assert "Verification failed" in str(exc_info.value)

    def test_inherits_from_exception(self):
        """Test that error inherits from Exception."""
        error = ProvenanceVerificationError("Test")
        assert isinstance(error, Exception)

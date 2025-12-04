import ssl
from unittest.mock import Mock, patch

import pytest

from secureai.ratls import ratls_verify
from secureai.verifiers import DstackTDXVerifier


class TestRatlsVerify:
    def test_hostname_not_in_verification_list(self):
        """Test that verification is skipped for hostnames not in the list"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        result = ratls_verify(
            ssl_sock,
            {
                "other.com": DstackTDXVerifier(disable_runtime_verification=True),
                "another.com": DstackTDXVerifier(disable_runtime_verification=True),
            },
        )

        assert result is True
        ssl_sock.getpeercert.assert_not_called()

    def test_hostname_in_verification_list(self):
        """Test that verification runs for hostnames in the list"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "httpbin.org"

        with patch(
            "secureai.verifiers.DstackTDXVerifier.get_quote_from_tls_conn"
        ) as mock_get_quote:
            mock_get_quote.side_effect = Exception("Failed to get quote")
            result = ratls_verify(
                ssl_sock,
                {
                    "httpbin.org": DstackTDXVerifier(disable_runtime_verification=True),
                    "google.com": DstackTDXVerifier(disable_runtime_verification=True),
                },
            )

        assert not result
        mock_get_quote.assert_called_once()

    def test_hostname_none_raises_assertion(self):
        """Test that None hostname raises AssertionError"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = None

        with pytest.raises(AssertionError):
            ratls_verify(
                ssl_sock,
                {"httpbin.org": DstackTDXVerifier(disable_runtime_verification=True)},
            )

    def test_empty_verifier_dict_returns_true(self):
        """Test that empty verifier dict returns True (no verification)"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        result = ratls_verify(ssl_sock, {})
        assert result is True

    def test_none_verifier_dict_returns_true(self):
        """Test that None verifier dict returns True (no verification)"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        result = ratls_verify(ssl_sock, None)
        assert result is True

    def test_verification_returns_false_when_verifier_fails(self):
        """Test that verification returns False when verifier.verify returns False"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        mock_verifier = Mock()
        mock_verifier.verify.return_value = False

        result = ratls_verify(ssl_sock, {"example.com": mock_verifier})

        assert result is False
        mock_verifier.verify.assert_called_once_with(ssl_sock)

    def test_verification_returns_true_when_verifier_succeeds(self):
        """Test that verification returns True when verifier.verify returns True"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        mock_verifier = Mock()
        mock_verifier.verify.return_value = True

        result = ratls_verify(ssl_sock, {"example.com": mock_verifier})

        assert result is True
        mock_verifier.verify.assert_called_once_with(ssl_sock)

    def test_verification_returns_false_on_exception(self):
        """Test that verification returns False when verifier raises exception"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = "example.com"

        mock_verifier = Mock()
        mock_verifier.verify.side_effect = Exception("Verification error")

        result = ratls_verify(ssl_sock, {"example.com": mock_verifier})

        assert result is False

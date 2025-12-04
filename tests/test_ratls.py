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
            {"other.com": DstackTDXVerifier(), "another.com": DstackTDXVerifier()},
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
                {"httpbin.org": DstackTDXVerifier(), "google.com": DstackTDXVerifier()},
            )

        assert not result
        mock_get_quote.assert_called_once()

    def test_hostname_none_raises_assertion(self):
        """Test that None hostname raises AssertionError"""
        ssl_sock = Mock(spec=ssl.SSLSocket)
        ssl_sock.server_hostname = None

        with pytest.raises(AssertionError):
            ratls_verify(ssl_sock, {"httpbin.org": DstackTDXVerifier()})

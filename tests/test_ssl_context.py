import ssl
from unittest.mock import MagicMock, Mock, patch

import pytest

from secureai.ssl_context import create_ssl_context_with_ratls
from secureai.verifiers import DstackTDXVerifier
from secureai.verifiers.errors import RATLSVerificationError


class TestCreateVerifyingSSLContext:
    def test_creates_ssl_context(self):
        """Test that function creates an SSL context"""
        ctx = create_ssl_context_with_ratls({"httpbin.org": DstackTDXVerifier()})
        assert isinstance(ctx, ssl.SSLContext)

    def test_ssl_context_verify_mode(self):
        """Test that SSL context has CERT_REQUIRED verify mode"""
        ctx = create_ssl_context_with_ratls({"httpbin.org": DstackTDXVerifier()})
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_ssl_context_check_hostname(self):
        """Test that SSL context has check_hostname enabled"""
        ctx = create_ssl_context_with_ratls({"httpbin.org": DstackTDXVerifier()})
        assert ctx.check_hostname is True

    def test_empty_hostname_list(self):
        """Test with empty hostname list"""
        ctx = create_ssl_context_with_ratls({})
        assert isinstance(ctx, ssl.SSLContext)

    def test_multiple_hostnames(self):
        """Test with multiple hostnames"""
        ctx = create_ssl_context_with_ratls(
            {
                "httpbin.org": DstackTDXVerifier(),
                "google.com": DstackTDXVerifier(),
                "example.com": DstackTDXVerifier(),
            }
        )
        assert isinstance(ctx, ssl.SSLContext)

    def test_wrap_socket_method_replaced(self):
        """Test that wrap_socket method is replaced"""
        original_ctx = ssl.create_default_context()
        ctx = create_ssl_context_with_ratls({"httpbin.org": DstackTDXVerifier()})

        # The wrap_socket should be different (replaced)
        assert ctx.wrap_socket.__name__ != original_ctx.wrap_socket.__name__

    def test_wrap_socket_performs_handshake_when_not_done(self):
        """Test that wrap_socket performs handshake when do_handshake_on_connect=False"""
        mock_ssl_sock = MagicMock(spec=ssl.SSLSocket)
        mock_ssl_sock.server_hostname = "example.com"

        with patch(
            "secureai.ssl_context.ssl.create_default_context"
        ) as mock_create_ctx:
            mock_ctx = MagicMock()
            mock_ctx.verify_mode = ssl.CERT_REQUIRED
            mock_ctx.check_hostname = True
            mock_ctx.wrap_socket.return_value = mock_ssl_sock
            mock_create_ctx.return_value = mock_ctx

            with patch("secureai.ssl_context.ratls_verify", return_value=True):
                ctx = create_ssl_context_with_ratls({})
                mock_sock = Mock()

                # Call with do_handshake_on_connect=False
                result = ctx.wrap_socket(
                    mock_sock,
                    server_hostname="example.com",
                    do_handshake_on_connect=False,
                )

                # Verify handshake was called
                mock_ssl_sock.do_handshake.assert_called_once()
                assert result == mock_ssl_sock

    def test_wrap_socket_raises_on_verification_failure(self):
        """Test that wrap_socket raises RATLSVerificationError on failure"""
        mock_ssl_sock = MagicMock(spec=ssl.SSLSocket)
        mock_ssl_sock.server_hostname = "example.com"

        with patch(
            "secureai.ssl_context.ssl.create_default_context"
        ) as mock_create_ctx:
            mock_ctx = MagicMock()
            mock_ctx.verify_mode = ssl.CERT_REQUIRED
            mock_ctx.check_hostname = True
            mock_ctx.wrap_socket.return_value = mock_ssl_sock
            mock_create_ctx.return_value = mock_ctx

            with patch("secureai.ssl_context.ratls_verify", return_value=False):
                ctx = create_ssl_context_with_ratls(
                    {"example.com": DstackTDXVerifier()}
                )
                mock_sock = Mock()

                with pytest.raises(RATLSVerificationError, match="Verification failed"):
                    ctx.wrap_socket(mock_sock, server_hostname="example.com")

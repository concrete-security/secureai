import ssl

from secureai.ssl_context import create_ssl_context_with_ratls
from secureai.verifiers import DstackTDXVerifier


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

import ssl

import httpx
import pytest
from unittest.mock import patch
from openai import OpenAI

from secureai.httpx import Client as RATLSClient
from secureai.openai import OpenAI as RATLSOpenAI


class TestRATLSClient:
    """Tests for the secureai.httpx.Client class.

    Some of the tests make sure RATLS is working as expected, while others make sure the client
    behaves like a normal httpx.Client.
    """

    def test_init_basic(self):
        """Test basic RATLSClient initialization"""
        client = RATLSClient(ratls_server_hostnames=["httpbin.org"])
        assert isinstance(client, httpx.Client)

    def test_init_empty_hostnames(self):
        """Test RATLSClient with empty hostname list"""
        client = RATLSClient(ratls_server_hostnames=[])
        assert isinstance(client, httpx.Client)

    def test_init_with_verify_raises_error(self):
        """Test that passing verify argument raises ValueError"""
        with pytest.raises(ValueError, match="setting verify argument isn't possible"):
            RATLSClient(ratls_server_hostnames=["httpbin.org"], verify=False)

    def test_init_with_custom_ssl_context_raises_error(self):
        """Test that passing custom SSL context raises ValueError"""
        ctx = ssl.create_default_context()
        with pytest.raises(ValueError, match="setting verify argument isn't possible"):
            RATLSClient(ratls_server_hostnames=["httpbin.org"], verify=ctx)

    def test_context_manager(self):
        """Test RATLSClient as context manager"""
        with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
            assert isinstance(client, httpx.Client)

    def test_get_request_to_httpbin(self):
        """Test actual GET request to httpbin.org"""
        # Make sure it works first
        with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
            response = client.get("https://httpbin.org/get")
            assert response.status_code == 200

        # Make sure ratls verify is called once while getting quote
        with patch("secureai.ssl_context.ratls_verify") as mock_ratls_verify:
            mock_ratls_verify.return_value = True
            with patch("secureai.ratls._get_quote_from_tls_conn") as mock_get_quote:
                mock_get_quote.return_value = b"fake_quote_data"
                with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
                    response = client.get("https://httpbin.org/get")
                    assert response.status_code == 200
                mock_get_quote.assert_not_called()
            mock_ratls_verify.assert_called_once()

    def test_get_request_without_ratls_verification(self):
        """Test GET request to server not in verification list"""
        # Make sure it works first
        with RATLSClient(ratls_server_hostnames=["other.com"]) as client:
            response = client.get("https://httpbin.org/get")
            assert response.status_code == 200

        # Make sure ratls verify is called once while not getting quote (ignored)
        with patch("secureai.ssl_context.ratls_verify") as mock_ratls_verify:
            mock_ratls_verify.return_value = True
            with patch("secureai.ratls._get_quote_from_tls_conn") as mock_get_quote:
                mock_get_quote.return_value = b"fake_quote_data"
                with RATLSClient(ratls_server_hostnames=["other.com"]) as client:
                    response = client.get("https://httpbin.org/get")
                    assert response.status_code == 200
                mock_get_quote.assert_not_called()
            mock_ratls_verify.assert_called_once()

    def test_post_request(self):
        """Test POST request with RATLSClient"""
        with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
            response = client.post("https://httpbin.org/post", json={"key": "value"})
            assert response.status_code == 200
            assert response.json()["json"]["key"] == "value"

    def test_multiple_requests(self):
        """Test multiple requests with same client"""
        with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
            response1 = client.get("https://httpbin.org/get")
            response2 = client.get("https://httpbin.org/status/200")
            assert response1.status_code == 200
            assert response2.status_code == 200

    def test_headers_preserved(self):
        """Test that custom headers are preserved"""
        with RATLSClient(ratls_server_hostnames=["httpbin.org"]) as client:
            response = client.get(
                "https://httpbin.org/get", headers={"X-Custom-Header": "test-value"}
            )
            assert response.status_code == 200
            assert "X-Custom-Header" in response.json()["headers"]

    def test_follow_redirects(self):
        """Test that redirects are followed"""
        with RATLSClient(
            ratls_server_hostnames=["httpbin.org"], follow_redirects=True
        ) as client:
            response = client.get("https://httpbin.org/redirect/1")
            assert response.status_code == 200


class TestRATLSOpenAI:
    def test_init_basic(self):
        """Test basic RATLSOpenAI initialization"""
        client = RATLSOpenAI(
            api_key="test-key", ratls_server_hostnames=["api.openai.com"]
        )
        assert isinstance(client, OpenAI)

    def test_init_empty_hostnames(self):
        """Test RATLSOpenAI with empty hostname list"""
        client = RATLSOpenAI(api_key="test-key", ratls_server_hostnames=[])
        assert isinstance(client, OpenAI)

    def test_init_with_http_client_raises_error(self):
        """Test that passing http_client argument raises ValueError"""
        custom_client = httpx.Client()
        with pytest.raises(
            ValueError, match="setting http_client argument isn't possible"
        ):
            RATLSOpenAI(
                api_key="test-key",
                ratls_server_hostnames=["api.openai.com"],
                http_client=custom_client,
            )

    def test_has_ratls_http_client(self):
        """Test that RATLSOpenAI uses RATLSClient"""
        client = RATLSOpenAI(
            api_key="test-key", ratls_server_hostnames=["api.openai.com"]
        )
        assert isinstance(client._client, RATLSClient)

    def test_context_manager(self):
        """Test RATLSOpenAI as context manager"""
        with RATLSOpenAI(
            api_key="test-key", ratls_server_hostnames=["api.openai.com"]
        ) as client:
            assert isinstance(client, OpenAI)

    def test_api_key_passed_through(self):
        """Test that API key is properly set"""
        client = RATLSOpenAI(
            api_key="sk-test-123", ratls_server_hostnames=["api.openai.com"]
        )
        assert client.api_key == "sk-test-123"

    def test_base_url_custom(self):
        """Test RATLSOpenAI with custom base URL"""
        client = RATLSOpenAI(
            api_key="test-key",
            base_url="https://custom.openai.com/v1",
            ratls_server_hostnames=["custom.openai.com"],
        )
        assert "custom.openai.com" in str(client.base_url)

import ssl
from unittest.mock import patch

import httpx
import pytest
from openai import OpenAI

from secureai.httpx import Client as RATLSClient
from secureai.openai import OpenAI as RATLSOpenAI
from secureai.verifiers import DstackTDXVerifier, RATLSVerificationError


class TestRATLSClient:
    """Tests for the secureai.httpx.Client class.

    Some of the tests make sure RATLS is working as expected, while others make sure the client
    behaves like a normal httpx.Client.
    """

    def test_init_basic(self):
        """Test basic RATLSClient initialization"""
        client = RATLSClient(
            ratls_verifier_per_hostname={
                "api.restful-api.dev": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            }
        )
        assert isinstance(client, httpx.Client)

    def test_init_empty_hostnames(self):
        """Test RATLSClient with empty hostname list"""
        client = RATLSClient(ratls_verifier_per_hostname={})
        assert isinstance(client, httpx.Client)

    def test_init_with_verify_raises_error(self):
        """Test that passing verify argument raises ValueError"""
        with pytest.raises(ValueError, match="setting verify argument isn't possible"):
            RATLSClient(
                ratls_verifier_per_hostname={
                    "api.restful-api.dev": DstackTDXVerifier(
                        disable_runtime_verification=True
                    )
                },
                verify=False,
            )

    def test_init_with_custom_ssl_context_raises_error(self):
        """Test that passing custom SSL context raises ValueError"""
        ctx = ssl.create_default_context()
        with pytest.raises(ValueError, match="setting verify argument isn't possible"):
            RATLSClient(
                ratls_verifier_per_hostname={
                    "api.restful-api.dev": DstackTDXVerifier(
                        disable_runtime_verification=True
                    )
                },
                verify=ctx,
            )

    def test_context_manager(self):
        """Test RATLSClient as context manager"""
        with RATLSClient(
            ratls_verifier_per_hostname={
                "api.restful-api.dev": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            }
        ) as client:
            assert isinstance(client, httpx.Client)

    def test_get_request_without_ratls_verification(self):
        """Test GET request to server not in verification list"""
        # Make sure ratls verify is called once while not getting quote (ignored)
        with patch("secureai.ssl_context.ratls_verify") as mock_ratls_verify:
            mock_ratls_verify.return_value = True
            with patch(
                "secureai.verifiers.DstackTDXVerifier.get_quote_from_tls_conn"
            ) as mock_get_quote:
                mock_get_quote.return_value = b"fake_quote_data"
                with RATLSClient(
                    ratls_verifier_per_hostname={
                        "other.com": DstackTDXVerifier(
                            disable_runtime_verification=True
                        )
                    }
                ) as client:
                    response = client.get("https://api.restful-api.dev/objects")
                    assert response.status_code == 200
                mock_get_quote.assert_not_called()
            mock_ratls_verify.assert_called_once()

    def test_post_request(self):
        """Test POST request with RATLSClient"""
        with RATLSClient(
            ratls_verifier_per_hostname={
                "vllm.concrete-security.com": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            }
        ) as client:
            response = client.post(
                "https://vllm.concrete-security.com/tdx_quote",
                json={"report_data": "000"},
            )
            assert response.status_code == 200

    def test_multiple_requests(self):
        """Test multiple requests with same client"""
        with RATLSClient(
            ratls_verifier_per_hostname={
                "vllm.concrete-security.com": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            }
        ) as client:
            response1 = client.get("https://vllm.concrete-security.com/health")
            response2 = client.get("https://vllm.concrete-security.com/v1/models")
            assert response1.status_code == 200
            assert response2.status_code == 200

    def test_ratls_verifier_with_app_compose_matching(
        self, test_os_image_hash, test_bootchain
    ):
        """Test DstackTDXVerifier with app-compose when hashes match"""
        with (
            patch("secureai.verifiers.tdx.get_compose_hash") as mock_get_compose_hash,
            patch(
                "secureai.verifiers.tdx.compose_hash_from_eventlog"
            ) as mock_compose_hash_from_eventlog,
        ):
            mock_get_compose_hash.return_value = "matching_hash_value"
            mock_compose_hash_from_eventlog.return_value = "matching_hash_value"
            verifier = DstackTDXVerifier(
                app_compose_docker_compose_file="test",
                expected_bootchain=test_bootchain,
                os_image_hash=test_os_image_hash,
            )
            with RATLSClient(
                ratls_verifier_per_hostname={"vllm.concrete-security.com": verifier}
            ) as client:
                response1 = client.get("https://vllm.concrete-security.com/health")
                assert response1.status_code == 200

            assert mock_get_compose_hash.call_count == 2
            mock_compose_hash_from_eventlog.assert_called_once()

    def test_ratls_verifier_with_app_compose_not_matching(
        self, test_os_image_hash, test_bootchain
    ):
        """Test DstackTDXVerifier with app-compose when hashes don't match"""
        # appcompose hashes won't match since docker_compose isn't "test" in the remote machine
        verifier = DstackTDXVerifier(
            app_compose_docker_compose_file="test",
            expected_bootchain=test_bootchain,
            os_image_hash=test_os_image_hash,
        )
        with RATLSClient(
            ratls_verifier_per_hostname={"vllm.concrete-security.com": verifier}
        ) as client:
            with pytest.raises(RATLSVerificationError):
                client.get("https://vllm.concrete-security.com/health")


class TestRATLSOpenAI:
    def test_init_basic(self):
        """Test basic RATLSOpenAI initialization"""
        client = RATLSOpenAI(
            api_key="test-key",
            ratls_verifier_per_hostname={
                "api.openai.com": DstackTDXVerifier(disable_runtime_verification=True)
            },
        )
        assert isinstance(client, OpenAI)

    def test_init_empty_hostnames(self):
        """Test RATLSOpenAI with empty hostname list"""
        client = RATLSOpenAI(api_key="test-key", ratls_verifier_per_hostname={})
        assert isinstance(client, OpenAI)

    def test_init_with_http_client_raises_error(self):
        """Test that passing http_client argument raises ValueError"""
        custom_client = httpx.Client()
        with pytest.raises(
            ValueError, match="setting http_client argument isn't possible"
        ):
            RATLSOpenAI(
                api_key="test-key",
                ratls_verifier_per_hostname={
                    "api.openai.com": DstackTDXVerifier(
                        disable_runtime_verification=True
                    )
                },
                http_client=custom_client,
            )

    def test_has_ratls_http_client(self):
        """Test that RATLSOpenAI uses RATLSClient"""
        client = RATLSOpenAI(
            api_key="test-key",
            ratls_verifier_per_hostname={
                "api.openai.com": DstackTDXVerifier(disable_runtime_verification=True)
            },
        )
        assert isinstance(client._client, RATLSClient)

    def test_context_manager(self):
        """Test RATLSOpenAI as context manager"""
        with RATLSOpenAI(
            api_key="test-key",
            ratls_verifier_per_hostname={
                "api.openai.com": DstackTDXVerifier(disable_runtime_verification=True)
            },
        ) as client:
            assert isinstance(client, OpenAI)

    def test_api_key_passed_through(self):
        """Test that API key is properly set"""
        client = RATLSOpenAI(
            api_key="sk-test-123",
            ratls_verifier_per_hostname={
                "api.openai.com": DstackTDXVerifier(disable_runtime_verification=True)
            },
        )
        assert client.api_key == "sk-test-123"

    def test_base_url_custom(self):
        """Test RATLSOpenAI with custom base URL"""
        client = RATLSOpenAI(
            api_key="test-key",
            base_url="https://custom.openai.com/v1",
            ratls_verifier_per_hostname={
                "custom.openai.com": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            },
        )
        assert "custom.openai.com" in str(client.base_url)

    def test_openai_call_ratls_verify(self):
        """Test that RATLS verification is called when using OpenAI client"""
        with patch("secureai.ssl_context.ratls_verify") as mock_ratls_verify:
            mock_ratls_verify.return_value = True
            client = RATLSOpenAI(
                api_key="",
                base_url="https://vllm.concrete-security.com/v1",
                ratls_verifier_per_hostname={
                    "vllm.concrete-security.com": DstackTDXVerifier(
                        disable_runtime_verification=True
                    )
                },
            )

            # Make a request that should trigger RATLS verification
            try:
                client.models.list()
            except Exception:
                # The request might fail due to mocking, but we just want to verify
                # that RATLS verification was attempted
                pass

            # Verify that RATLS verification was called
            mock_ratls_verify.assert_called()

    def test_openai_chat_completion(self):
        """Test OpenAI chat completion with RATLS verification"""
        client = RATLSOpenAI(
            api_key="",
            base_url="https://vllm.concrete-security.com/v1",
            ratls_verifier_per_hostname={
                "vllm.concrete-security.com": DstackTDXVerifier(
                    disable_runtime_verification=True
                )
            },
        )
        models = client.models.list()
        model_id = models.data[0].id
        completion = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": "You are a concise assistant."},
                {"role": "user", "content": "Summarize the benefits of RATLS."},
            ],
            temperature=0.3,
        )
        assert completion.choices[0].message.content is not None
        assert len(completion.choices[0].message.content) > 0

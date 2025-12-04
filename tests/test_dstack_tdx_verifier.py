"""Tests for DstackTDXVerifier initialization and configuration."""

import json
import warnings
from unittest.mock import Mock, patch

import pytest
from dstack_sdk import EventLog

from secureai.verifiers.tdx import (
    DstackTDXVerifier,
    cert_hash_from_eventlog,
    compose_hash_from_eventlog,
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


class TestCertHashFromEventlog:
    """Tests for the cert_hash_from_eventlog function."""

    def _create_event_log(self, event: str, event_payload: str) -> EventLog:
        """Helper to create EventLog with required fields."""
        return EventLog(
            imr=0,
            event_type=0,
            digest="0" * 64,
            event=event,
            event_payload=event_payload,
        )

    def test_returns_none_when_no_cert_events(self):
        """Test that function returns None when no cert events exist."""
        event_log = [
            self._create_event_log("other-event", "data"),
        ]
        result = cert_hash_from_eventlog(event_log)
        assert result is None

    def test_returns_none_with_empty_event_log(self):
        """Test that function returns None with empty event log."""
        result = cert_hash_from_eventlog([])
        assert result is None

    def test_returns_cert_hash_when_cert_event_exists(self):
        """Test that function returns cert hash when cert event exists."""
        # "test_hash" encoded as hex
        cert_hash = "test_hash"
        cert_hash_hex = cert_hash.encode().hex()
        event_log = [
            self._create_event_log("New TLS Certificate", cert_hash_hex),
        ]
        result = cert_hash_from_eventlog(event_log)
        assert result == cert_hash

    def test_returns_last_cert_hash_when_multiple_exist(self):
        """Test that function returns the last cert hash when multiple exist."""
        first_hash = "first_hash"
        last_hash = "last_hash"
        event_log = [
            self._create_event_log("New TLS Certificate", first_hash.encode().hex()),
            self._create_event_log("New TLS Certificate", last_hash.encode().hex()),
        ]
        result = cert_hash_from_eventlog(event_log)
        assert result == last_hash


class TestComposeHashFromEventlog:
    """Tests for the compose_hash_from_eventlog function."""

    def _create_event_log(self, event: str, event_payload: str) -> EventLog:
        """Helper to create EventLog with required fields."""
        return EventLog(
            imr=0,
            event_type=0,
            digest="0" * 64,
            event=event,
            event_payload=event_payload,
        )

    def test_returns_none_when_no_compose_events(self):
        """Test that function returns None when no compose events exist."""
        event_log = [
            self._create_event_log("other-event", "data"),
        ]
        result = compose_hash_from_eventlog(event_log)
        assert result is None

    def test_returns_none_with_empty_event_log(self):
        """Test that function returns None with empty event log."""
        result = compose_hash_from_eventlog([])
        assert result is None

    def test_returns_compose_hash_when_event_exists(self):
        """Test that function returns compose hash when event exists."""
        compose_hash = "abc123def456"
        event_log = [
            self._create_event_log("compose-hash", compose_hash),
        ]
        result = compose_hash_from_eventlog(event_log)
        assert result == compose_hash


class TestDstackTDXVerifierGetQuote:
    """Tests for DstackTDXVerifier.get_quote_from_tls_conn method."""

    def test_report_data_too_long_raises_error(self):
        """Test that report_data longer than 64 bytes raises ValueError."""
        mock_ssl_sock = Mock()
        report_data = b"x" * 65  # 65 bytes, too long

        with pytest.raises(ValueError, match="report_data must be at most 64 bytes"):
            DstackTDXVerifier.get_quote_from_tls_conn(
                report_data=report_data,
                ssl_sock=mock_ssl_sock,
                host="example.com",
            )


class TestDstackTDXVerifierVerifyCertInEventlog:
    """Tests for DstackTDXVerifier.verify_cert_in_eventlog method."""

    def _create_event_log(self, event: str, event_payload: str) -> EventLog:
        """Helper to create EventLog with required fields."""
        return EventLog(
            imr=0,
            event_type=0,
            digest="0" * 64,
            event=event,
            event_payload=event_payload,
        )

    def test_returns_false_when_no_certificate(self):
        """Test that function returns False when no certificate is received."""
        verifier = DstackTDXVerifier()
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"
        mock_ssl_sock.getpeercert.return_value = None

        result = verifier.verify_cert_in_eventlog(mock_ssl_sock, [])
        assert result is False

    def test_returns_false_when_cert_hash_mismatch(self):
        """Test that function returns False when cert hash doesn't match."""
        verifier = DstackTDXVerifier()
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"
        mock_ssl_sock.getpeercert.return_value = b"fake_cert_data"

        # Event log with a different hash
        event_log = [
            self._create_event_log(
                "New TLS Certificate", "different_hash".encode().hex()
            ),
        ]

        result = verifier.verify_cert_in_eventlog(mock_ssl_sock, event_log)
        assert result is False


class TestDstackTDXVerifierVerifyAppCompose:
    """Tests for DstackTDXVerifier.verify_app_compose method."""

    def _create_event_log(self, event: str, event_payload: str) -> EventLog:
        """Helper to create EventLog with required fields."""
        return EventLog(
            imr=0,
            event_type=0,
            digest="0" * 64,
            event=event,
            event_payload=event_payload,
        )

    def test_returns_false_when_hash_mismatch_with_tcbinfo(self):
        """Test that verify_app_compose returns False when hash doesn't match TCBInfo."""
        docker_compose = "version: '3'\nservices:\n  web:\n    image: nginx"
        verifier = DstackTDXVerifier(docker_compose_file=docker_compose)

        # Create an app_compose JSON that will have a different hash
        # This needs to be a valid app_compose structure

        different_app_compose = json.dumps(
            default_app_compose_from_docker_compose("different_compose_content")
        )
        event_log = []

        result = verifier.verify_app_compose(different_app_compose, event_log)
        assert result is False

    def test_returns_false_when_hash_mismatch_with_eventlog(self):
        """Test that verify_app_compose returns False when hash doesn't match event log."""
        docker_compose = "version: '3'\nservices:\n  web:\n    image: nginx"
        verifier = DstackTDXVerifier(docker_compose_file=docker_compose)

        # Create an event log with a different hash
        event_log = [
            self._create_event_log("compose-hash", "different_hash_value"),
        ]

        # Use the same app_compose as the verifier so TCBInfo check passes
        app_compose_json = json.dumps(verifier.app_compose)

        result = verifier.verify_app_compose(app_compose_json, event_log)
        assert result is False

    def test_returns_true_when_no_app_compose_configured(self):
        """Test that verify_app_compose returns True when no app_compose configured."""
        verifier = DstackTDXVerifier()  # No app_compose

        result = verifier.verify_app_compose("{}", [])
        assert result is True


class TestDstackTDXVerifierGetQuoteFailure:
    """Tests for get_quote_from_tls_conn failure cases."""

    def test_raises_error_on_unsuccessful_quote(self):
        """Test that unsuccessful quote response raises RATLSVerificationError."""
        from secureai.verifiers.errors import RATLSVerificationError

        mock_ssl_sock = Mock()
        mock_response = Mock()
        mock_response.read.return_value = b'{"success": false, "error": "test error"}'
        mock_response.status = 200
        mock_response.reason = "OK"

        with patch(
            "secureai.verifiers.tdx.post_json_from_tls_conn", return_value=mock_response
        ):
            with pytest.raises(RATLSVerificationError, match="Quote retrieval failed"):
                DstackTDXVerifier.get_quote_from_tls_conn(
                    report_data=b"test",
                    ssl_sock=mock_ssl_sock,
                    host="example.com",
                )


class TestDstackTDXVerifierVerify:
    """Tests for DstackTDXVerifier.verify method."""

    def test_verify_returns_false_when_get_quote_fails(self):
        """Test that verify returns False when get_quote_from_tls_conn raises exception."""
        verifier = DstackTDXVerifier()
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        with patch.object(
            DstackTDXVerifier,
            "get_quote_from_tls_conn",
            side_effect=Exception("Failed to get quote"),
        ):
            result = verifier.verify(mock_ssl_sock)
            assert result is False

    def test_verify_returns_false_when_cert_verification_fails(self):
        """Test that verify returns False when cert verification fails."""
        verifier = DstackTDXVerifier()
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_tcb_info = Mock()

        with patch.object(
            DstackTDXVerifier,
            "get_quote_from_tls_conn",
            return_value=(mock_quote_response, mock_tcb_info),
        ):
            with patch.object(verifier, "verify_cert_in_eventlog", return_value=False):
                result = verifier.verify(mock_ssl_sock)
                assert result is False

    def test_verify_raises_when_collateral_is_none(self):
        """Test that verify raises RuntimeError when collateral is None."""
        verifier = DstackTDXVerifier()
        verifier.collateral = None  # Force collateral to None
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_tcb_info = Mock()

        with patch.object(
            DstackTDXVerifier,
            "get_quote_from_tls_conn",
            return_value=(mock_quote_response, mock_tcb_info),
        ):
            with patch.object(verifier, "verify_cert_in_eventlog", return_value=True):
                with pytest.raises(
                    RuntimeError, match="Collateral are not properly set"
                ):
                    verifier.verify(mock_ssl_sock)

    def test_verify_returns_false_when_tcb_status_not_allowed(self):
        """Test that verify returns False when TCB status is not in allowed list."""
        verifier = DstackTDXVerifier(allowed_tcb_status=["UpToDate"])
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_tcb_info = Mock()

        mock_report = Mock()
        mock_report.to_json.return_value = (
            '{"status": "OutOfDate", "report": {"TD10": {}}}'
        )

        with patch.object(
            DstackTDXVerifier,
            "get_quote_from_tls_conn",
            return_value=(mock_quote_response, mock_tcb_info),
        ):
            with patch.object(verifier, "verify_cert_in_eventlog", return_value=True):
                with patch(
                    "secureai.verifiers.tdx.dcap_qvl.verify", return_value=mock_report
                ):
                    result = verifier.verify(mock_ssl_sock)
                    assert result is False

    def test_verify_returns_false_when_rtmr_mismatch(self):
        """Test that verify returns False when RTMR values don't match."""
        verifier = DstackTDXVerifier(allowed_tcb_status=["UpToDate"])
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_quote_response.replay_rtmrs.return_value = {
            0: "replayed0",
            1: "replayed1",
            2: "replayed2",
            3: "replayed3",
        }
        mock_tcb_info = Mock()

        mock_report = Mock()
        mock_report.to_json.return_value = (
            '{"status": "UpToDate", "report": {"TD10": {'
            '"rt_mr0": "different0", "rt_mr1": "replayed1", '
            '"rt_mr2": "replayed2", "rt_mr3": "replayed3", '
            '"report_data": "7465737400000000000000000000000000000000000000000000000000000000"'
            "}}}"
        )

        with patch.object(
            DstackTDXVerifier,
            "get_quote_from_tls_conn",
            return_value=(mock_quote_response, mock_tcb_info),
        ):
            with patch.object(verifier, "verify_cert_in_eventlog", return_value=True):
                with patch(
                    "secureai.verifiers.tdx.dcap_qvl.verify", return_value=mock_report
                ):
                    result = verifier.verify(mock_ssl_sock)
                    assert result is False

    def test_verify_returns_false_when_report_data_mismatch(self):
        """Test that verify returns False when report_data doesn't match."""
        verifier = DstackTDXVerifier(allowed_tcb_status=["UpToDate"])
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        # The report_data used in verify is generated via secrets.token_bytes(64)
        # We need to mock it to control the value
        test_report_data = b"\x00" * 64
        test_report_data_hex = test_report_data.hex()

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_quote_response.replay_rtmrs.return_value = {
            0: "rtmr0",
            1: "rtmr1",
            2: "rtmr2",
            3: "rtmr3",
        }
        # The quote response should match what was sent
        mock_quote_response.report_data = test_report_data_hex
        mock_tcb_info = Mock()

        mock_report = Mock()
        # But the report from dcap_qvl has a different report_data
        mock_report.to_json.return_value = (
            '{"status": "UpToDate", "report": {"TD10": {'
            '"rt_mr0": "rtmr0", "rt_mr1": "rtmr1", '
            '"rt_mr2": "rtmr2", "rt_mr3": "rtmr3", '
            '"report_data": "different_report_data"'
            "}}}"
        )

        with patch(
            "secureai.verifiers.tdx.secrets.token_bytes", return_value=test_report_data
        ):
            with patch.object(
                DstackTDXVerifier,
                "get_quote_from_tls_conn",
                return_value=(mock_quote_response, mock_tcb_info),
            ):
                with patch.object(
                    verifier, "verify_cert_in_eventlog", return_value=True
                ):
                    with patch(
                        "secureai.verifiers.tdx.dcap_qvl.verify",
                        return_value=mock_report,
                    ):
                        result = verifier.verify(mock_ssl_sock)
                        assert result is False

    def test_verify_returns_false_when_app_compose_fails(self):
        """Test that verify returns False when app compose verification fails."""
        docker_compose = "version: '3'\nservices:\n  web:\n    image: nginx"
        verifier = DstackTDXVerifier(
            docker_compose_file=docker_compose, allowed_tcb_status=["UpToDate"]
        )
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        # Create test report_data
        test_report_data = b"\x00" * 64
        test_report_data_hex = test_report_data.hex()

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_quote_response.replay_rtmrs.return_value = {
            0: "rtmr0",
            1: "rtmr1",
            2: "rtmr2",
            3: "rtmr3",
        }
        mock_quote_response.report_data = test_report_data_hex
        mock_tcb_info = Mock()
        mock_tcb_info.app_compose = "{}"  # Different app compose

        mock_report = Mock()
        mock_report.to_json.return_value = (
            '{"status": "UpToDate", "report": {"TD10": {'
            '"rt_mr0": "rtmr0", "rt_mr1": "rtmr1", '
            '"rt_mr2": "rtmr2", "rt_mr3": "rtmr3", '
            f'"report_data": "{test_report_data_hex}"'
            "}}}"
        )

        with patch(
            "secureai.verifiers.tdx.secrets.token_bytes", return_value=test_report_data
        ):
            with patch.object(
                DstackTDXVerifier,
                "get_quote_from_tls_conn",
                return_value=(mock_quote_response, mock_tcb_info),
            ):
                with patch.object(
                    verifier, "verify_cert_in_eventlog", return_value=True
                ):
                    with patch(
                        "secureai.verifiers.tdx.dcap_qvl.verify",
                        return_value=mock_report,
                    ):
                        with patch.object(
                            verifier, "verify_app_compose", return_value=False
                        ):
                            result = verifier.verify(mock_ssl_sock)
                            assert result is False

    def test_verify_returns_true_on_success(self):
        """Test that verify returns True when all checks pass."""
        verifier = DstackTDXVerifier(allowed_tcb_status=["UpToDate"])
        mock_ssl_sock = Mock()
        mock_ssl_sock.server_hostname = "example.com"

        # Create test report_data
        test_report_data = b"\x00" * 64
        test_report_data_hex = test_report_data.hex()

        mock_quote_response = Mock()
        mock_quote_response.decode_event_log.return_value = []
        mock_quote_response.decode_quote.return_value = b"fake_quote"
        mock_quote_response.replay_rtmrs.return_value = {
            0: "rtmr0",
            1: "rtmr1",
            2: "rtmr2",
            3: "rtmr3",
        }
        mock_quote_response.report_data = test_report_data_hex
        mock_tcb_info = Mock()
        mock_tcb_info.app_compose = "{}"

        mock_report = Mock()
        mock_report.to_json.return_value = (
            '{"status": "UpToDate", "report": {"TD10": {'
            '"rt_mr0": "rtmr0", "rt_mr1": "rtmr1", '
            '"rt_mr2": "rtmr2", "rt_mr3": "rtmr3", '
            f'"report_data": "{test_report_data_hex}"'
            "}}}"
        )

        with patch(
            "secureai.verifiers.tdx.secrets.token_bytes", return_value=test_report_data
        ):
            with patch.object(
                DstackTDXVerifier,
                "get_quote_from_tls_conn",
                return_value=(mock_quote_response, mock_tcb_info),
            ):
                with patch.object(
                    verifier, "verify_cert_in_eventlog", return_value=True
                ):
                    with patch(
                        "secureai.verifiers.tdx.dcap_qvl.verify",
                        return_value=mock_report,
                    ):
                        with patch.object(
                            verifier, "verify_app_compose", return_value=True
                        ):
                            result = verifier.verify(mock_ssl_sock)
                            assert result is True

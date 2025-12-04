"""TDX Quote Verifier Module.

This module provides functionality to verify TDX quotes using DCAP QVL library.
"""

import binascii
import json
import os
import secrets
import ssl
import time
import warnings
from hashlib import sha256
from pprint import pformat
from typing import Optional

import dcap_qvl
from dstack_sdk import EventLog
from dstack_sdk import GetQuoteResponse as QuoteResponse
from dstack_sdk.dstack_client import TcbInfoV05x
from dstack_sdk.get_compose_hash import get_compose_hash

from ..utils import _get_default_logger, post_json_from_tls_conn
from .base import RATLSVerifier
from .errors import RATLSVerificationError

logger = _get_default_logger()


CERT_EVENT_NAME = "New TLS Certificate"
COMPOSE_HASH_EVENT_NAME = "compose-hash"
# Downloaded from https://api.trustedservices.intel.com via dcap_qvl
LOCAL_COLLATERAL_PATH = os.path.join(os.path.dirname(__file__), "collateral.json")


def cert_hash_from_eventlog(event_log: list[EventLog]) -> Optional[str]:
    """Extract the certificate hash from the event log.

    Args:
        event_log: The event log entries.

    Returns:
        The certificate hash if found, otherwise None.
    """
    cert_events: list[EventLog] = []
    for event in event_log:
        if event.event == CERT_EVENT_NAME:
            cert_events.append(event)
    if cert_events:
        # Multiple cert events may exist due to certificate renewals, so we take the last one.
        return binascii.unhexlify(cert_events[-1].event_payload).decode()
    return None


def compose_hash_from_eventlog(event_log: list[EventLog]) -> Optional[str]:
    """Extract the compose hash from the event log.

    Args:
        event_log: The event log entries.

    Returns:
        The compose hash if found, otherwise None.
    """
    for event in event_log:
        if event.event == COMPOSE_HASH_EVENT_NAME:
            return event.event_payload
    return None


def default_app_compose_from_docker_compose(docker_compose_file: str) -> dict:
    """Create a default app_compose from a docker-compose file."""
    return {
        "allowed_envs": [],
        "docker_compose_file": docker_compose_file,
        "features": ["kms", "tproxy-net"],
        "gateway_enabled": True,
        "kms_enabled": True,
        "local_key_provider_enabled": False,
        "manifest_version": 2,
        "name": "",
        "no_instance_id": False,
        "pre_launch_script": '#!/bin/bash\necho "----------------------------------------------"\necho "Running Phala Cloud Pre-Launch Script v0.0.10"\necho "----------------------------------------------"\nset -e\n\n# Function: notify host\n\nnotify_host() {\n    if command -v dstack-util >/dev/null 2>&1; then\n        dstack-util notify-host -e "$1" -d "$2"\n    else\n        tdxctl notify-host -e "$1" -d "$2"\n    fi\n}\n\nnotify_host_hoot_info() {\n    notify_host "boot.progress" "$1"\n}\n\nnotify_host_hoot_error() {\n    notify_host "boot.error" "$1"\n}\n\n# Function: Perform Docker cleanup\nperform_cleanup() {\n    echo "Pruning unused images"\n    docker image prune -af\n    echo "Pruning unused volumes"\n    docker volume prune -f\n    notify_host_hoot_info "docker cleanup completed"\n}\n\n# Function: Check Docker login status without exposing credentials\ncheck_docker_login() {\n    # Try to verify login status without exposing credentials\n    if docker info 2>/dev/null | grep -q "Username"; then\n        return 0\n    else\n        return 1\n    fi\n}\n\n# Main logic starts here\necho "Starting login process..."\n\n# Check if Docker credentials exist\nif [[ -n "$DSTACK_DOCKER_USERNAME" && -n "$DSTACK_DOCKER_PASSWORD" ]]; then\n    echo "Docker credentials found"\n    \n    # Check if already logged in\n    if check_docker_login; then\n        echo "Already logged in to Docker registry"\n    else\n        echo "Logging in to Docker registry..."\n        # Login without exposing password in process list\n        if [[ -n "$DSTACK_DOCKER_REGISTRY" ]]; then\n            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin "$DSTACK_DOCKER_REGISTRY"\n        else\n            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin\n        fi\n        \n        if [ $? -eq 0 ]; then\n            echo "Docker login successful"\n        else\n            echo "Docker login failed"\n            notify_host_hoot_error "docker login failed"\n            exit 1\n        fi\n    fi\n# Check if AWS ECR credentials exist\nelif [[ -n "$DSTACK_AWS_ACCESS_KEY_ID" && -n "$DSTACK_AWS_SECRET_ACCESS_KEY" && -n "$DSTACK_AWS_REGION" && -n "$DSTACK_AWS_ECR_REGISTRY" ]]; then\n    echo "AWS ECR credentials found"\n    \n    # Check if AWS CLI is installed\n    if [ ! -f "./aws/dist/aws" ]; then\n        notify_host_hoot_info "awscli not installed, installing..."\n        echo "AWS CLI not installed, installing..."\n        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.24.14.zip" -o "awscliv2.zip"\n        echo "6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip" | md5sum -c\n        if [ $? -ne 0 ]; then\n            echo "MD5 checksum failed"\n            notify_host_hoot_error "awscli install failed"\n            exit 1\n        fi\n        unzip awscliv2.zip &> /dev/null\n    else\n        echo "AWS CLI is already installed: ./aws/dist/aws"\n    fi\n\n    # Set AWS credentials as environment variables\n    export AWS_ACCESS_KEY_ID="$DSTACK_AWS_ACCESS_KEY_ID"\n    export AWS_SECRET_ACCESS_KEY="$DSTACK_AWS_SECRET_ACCESS_KEY"\n    export AWS_DEFAULT_REGION="$DSTACK_AWS_REGION"\n    \n    # Set session token if provided (for temporary credentials)\n    if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then\n        echo "AWS session token found, using temporary credentials"\n        export AWS_SESSION_TOKEN="$DSTACK_AWS_SESSION_TOKEN"\n    fi\n    \n    # Test AWS credentials before attempting ECR login\n    echo "Testing AWS credentials..."\n    if ! ./aws/dist/aws sts get-caller-identity &> /dev/null; then\n        echo "AWS credentials test failed"\n        # For session token credentials, this might be expected if they\'re expired\n        # Log warning but don\'t fail startup\n        if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then\n            echo "Warning: AWS temporary credentials may have expired, continuing startup"\n            notify_host_hoot_info "AWS temporary credentials may have expired"\n        else\n            echo "AWS credentials test failed"\n            notify_host_hoot_error "Invalid AWS credentials"\n            exit 1\n        fi\n    else\n        echo "Logging in to AWS ECR..."\n        ./aws/dist/aws ecr get-login-password --region $DSTACK_AWS_REGION | docker login --username AWS --password-stdin "$DSTACK_AWS_ECR_REGISTRY"\n        if [ $? -eq 0 ]; then\n            echo "AWS ECR login successful"\n            notify_host_hoot_info "AWS ECR login successful"\n        else\n            echo "AWS ECR login failed"\n            # For session token credentials, don\'t fail startup if login fails\n            if [[ -n "$DSTACK_AWS_SESSION_TOKEN" ]]; then\n                echo "Warning: AWS ECR login failed with temporary credentials, continuing startup"\n                notify_host_hoot_info "AWS ECR login failed with temporary credentials"\n            else\n                notify_host_hoot_error "AWS ECR login failed"\n                exit 1\n            fi\n        fi\n    fi\nfi\n\nperform_cleanup\n\n#\n# Set root password.\n#\nif [ -n "$DSTACK_ROOT_PASSWORD" ]; then\n    echo "$DSTACK_ROOT_PASSWORD" | passwd --stdin root 2>/dev/null         || printf \'%s\n%s\n\' "$DSTACK_ROOT_PASSWORD" "$DSTACK_ROOT_PASSWORD" | passwd root\n    unset DSTACK_ROOT_PASSWORD\n    echo "Root password set/updated from DSTACK_ROOT_PASSWORD"\n\nelif [ -z "$(grep \'^root:\' /etc/shadow 2>/dev/null | cut -d: -f2)" ]; then\n    DSTACK_ROOT_PASSWORD=$(\n        dd if=/dev/urandom bs=32 count=1 2>/dev/null         | sha256sum         | awk \'{print $1}\'         | cut -c1-32\n    )\n    echo "$DSTACK_ROOT_PASSWORD" | passwd --stdin root 2>/dev/null         || printf \'%s\n%s\n\' "$DSTACK_ROOT_PASSWORD" "$DSTACK_ROOT_PASSWORD" | passwd root\n    unset DSTACK_ROOT_PASSWORD\n    echo "Root password set (random auto-init)"\n\nelse\n    echo "Root password already set; no changes."\nfi\n\nif [[ -n "$DSTACK_ROOT_PUBLIC_KEY" ]]; then\n    mkdir -p /home/root/.ssh\n    echo "$DSTACK_ROOT_PUBLIC_KEY" > /home/root/.ssh/authorized_keys\n    unset $DSTACK_ROOT_PUBLIC_KEY\n    echo "Root public key set"\nfi\nif [[ -n "$DSTACK_AUTHORIZED_KEYS" ]]; then\n    mkdir -p /home/root/.ssh\n    echo "$DSTACK_AUTHORIZED_KEYS" > /home/root/.ssh/authorized_keys\n    unset $DSTACK_AUTHORIZED_KEYS\n    echo "Root authorized_keys set"\nfi\n\n\nif [[ -S /var/run/dstack.sock ]]; then\n    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/dstack.sock http://dstack/Info | jq -j .app_id)\nelif [[ -S /var/run/tappd.sock ]]; then\n    export DSTACK_APP_ID=$(curl -s --unix-socket /var/run/tappd.sock http://dstack/prpc/Tappd.Info | jq -j .app_id)\nfi\n# Check if DSTACK_GATEWAY_DOMAIN is not set, try to get it from user_config or app-compose.json\n# Priority: user_config > app-compose.json\nif [[ -z "$DSTACK_GATEWAY_DOMAIN" ]]; then\n    # First try to get from /dstack/user_config if it exists and is valid JSON\n    if [[ -f /dstack/user_config ]] && jq empty /dstack/user_config 2>/dev/null; then\n        if [[ $(jq \'has("default_gateway_domain")\' /dstack/user_config 2>/dev/null) == "true" ]]; then\n            export DSTACK_GATEWAY_DOMAIN=$(jq -j \'.default_gateway_domain\' /dstack/user_config)\n        fi\n    fi\n\n    # If still not set, try to get from app-compose.json\n    if [[ -z "$DSTACK_GATEWAY_DOMAIN" ]] && [[ $(jq \'has("default_gateway_domain")\' app-compose.json) == "true" ]]; then\n        export DSTACK_GATEWAY_DOMAIN=$(jq -j \'.default_gateway_domain\' app-compose.json)\n    fi\nfi\nif [[ -n "$DSTACK_GATEWAY_DOMAIN" ]]; then\n    export DSTACK_APP_DOMAIN=$DSTACK_APP_ID"."$DSTACK_GATEWAY_DOMAIN\nfi\n\necho "----------------------------------------------"\necho "Script execution completed"\necho "----------------------------------------------"\n',
        "public_logs": True,
        "public_sysinfo": True,
        "public_tcbinfo": True,
        "runner": "docker-compose",
        "secure_time": False,
        "storage_fs": "zfs",
        "tproxy_enabled": True,
    }


class DstackTDXVerifier(RATLSVerifier):
    """Dstack TDX Quote Verifier using DCAP QVL.

    The main verification method is `verify`, but the verification depends on how the verifier was
    configured.
    """

    RTMR_COUNT = 4
    DEFAULT_QUOTE_ENDPOINT = "/tdx_quote"
    TCB_STATUS_LIST = [
        "UpToDate",
        "OutOfDate",
        "ConfigurationNeeded",
        "TDRelaunchAdvised",
        "SWHardeningNeeded",
        "Revoked",
    ]

    # TODO: It should allow to set what is acceptable for a TEE environment.
    def __init__(
        self,
        app_compose: dict | None = None,
        docker_compose_file: str | None = None,
        collateral: Optional[dict] = None,
        allowed_tcb_status: list[str] = ["UpToDate"],
        disable_runtime_verification: bool = False,
    ):
        """Initialize and configure the verifier.

        Args:
            app_compose: Application compose configuration. Defaults to None.
            docker_compose_file: docker-compose file content to generate a default app_compose.
                Defaults to None. Setting this value means using a default app_compose based on
                the provided docker-compose file. You cannot set both app_compose and
                docker_compose_file.
            collateral: dictionary of collateral data. Defaults to using local collateral file.
            allowed_tcb_status: List of accepteble TCB status. Default to ['UpToDate',]
            disable_runtime_verification: Whether to disable runtime verification. Defaults to False.
                This is NOT recommended. Use it only if you understand the security implications.
        """
        self._no_rt_verify = disable_runtime_verification
        if self.is_runtime_verification_disabled():
            self.app_compose = None
            warnings.warn(
                "You have disabled runtime verification. "
                "RATLS won't verify remote TEE runs a specific application",
                UserWarning,
            )
        else:
            # docker_compose_file is only used to create a default app_compose
            if docker_compose_file is not None and app_compose is not None:
                raise ValueError(
                    "You can only provide one of docker_compose_file or app_compose"
                )
            if docker_compose_file is not None:
                app_compose = default_app_compose_from_docker_compose(
                    docker_compose_file
                )
            self.app_compose = app_compose

            if self.app_compose is None:
                raise ValueError(
                    "You haven't configured the expected app_compose. "
                    "Runtime verification cannot be performed without it. "
                    "Either provide app_compose or docker_compose_file."
                )

        if not allowed_tcb_status:
            raise ValueError("allowed_tcb_status cannot be empty")
        for status in allowed_tcb_status:
            if status not in self.TCB_STATUS_LIST:
                raise ValueError(
                    f"TCB status must be one of {self.TCB_STATUS_LIST}, but {status} was provided"
                )
        self.allowed_tcb_status = allowed_tcb_status

        if collateral is None:
            with open(LOCAL_COLLATERAL_PATH, "r") as f:
                collateral = json.load(f)
        self.collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral))

    def get_app_compose_hash(self) -> str | None:
        """Get the app-compose hash from the configuration.

        Returns:
            The compose hash as a hex string, or None if not available.
        """
        if self.is_runtime_verification_disabled():
            return None
        return get_compose_hash(self.app_compose)

    def is_runtime_verification_disabled(self) -> bool:
        """Check if runtime verification is disabled.

        Returns:
            bool: True if runtime verification is disabled, False otherwise.
        """
        return self._no_rt_verify

    @classmethod
    def get_quote_from_tls_conn(
        cls,
        report_data: bytes,
        ssl_sock: ssl.SSLSocket,
        host,
        quote_endpoint: Optional[str] = None,
    ) -> tuple[QuoteResponse, TcbInfoV05x]:
        """Get a quote from the server using an existing TLS connection.

        Args:
            report_data: The report data to send to the server (not hex-encoded). Max 64 bytes.
            ssl_sock: An established SSL socket connected to the server.
            quote_endpoint: The HTTP endpoint to request the quote from.
            host: The server hostname.

        Returns:
            tuple[QuoteResponse, TcbInfoV05x]: The quote response and TCB info from the server.
        Raises:
            RATLSVerificationError: If the quote retrieval fails.
        """

        if len(report_data) > 64:
            raise ValueError("report_data must be at most 64 bytes")

        if quote_endpoint is None:
            quote_endpoint = cls.DEFAULT_QUOTE_ENDPOINT

        # Create an HTTPSConnection that uses our existing SSL socket
        logger.debug(f"Creating HTTPS client with existing socket for {host}")

        response = post_json_from_tls_conn(
            ssl_sock,
            host,
            {
                "report_data_hex": report_data.hex(),
            },
            quote_endpoint,
        )
        logger.debug(f"Sent POST request to {host}{quote_endpoint}")

        # Get the response
        response_data = response.read()

        logger.debug(f"Received HTTP response: {response.status} {response.reason}")
        logger.debug(f"Response body: {len(response_data)} bytes")

        quote_data = json.loads(response_data)
        if not quote_data["success"]:
            logger.debug(f"Quote retrieval failed. Server returned: {quote_data}")
            raise RATLSVerificationError(
                "Quote retrieval failed. Use debug mode for more logs"
            )

        # Never close the socket, as it's externally managed
        # the socket should still be usable after this function returns
        return (
            QuoteResponse(**quote_data["quote"]),
            TcbInfoV05x(**quote_data["tcb_info"]),
        )

    def verify_cert_in_eventlog(
        self, ssl_sock: ssl.SSLSocket, event_log: list[EventLog]
    ) -> bool:
        """Verifies that the TLS certificate is in the event log.

        This verification itself is not sufficient alone. We also need to verify the event log
        matches the expected RTMRs.

        Args:
            ssl_sock: An SSL socket to run the verification on.
            event_log: The event log entries.

        Returns:
            bool: True if verification passes, False otherwise.
        """
        hostname = ssl_sock.server_hostname
        assert hostname is not None

        # Get server certificate
        cert_der = ssl_sock.getpeercert(binary_form=True)
        if cert_der is None:
            logger.debug(f"No certificate received from {hostname}")
            return False
        logger.debug(f"Certificate received for {hostname} ({len(cert_der)} bytes)")

        # Compute cert hash
        cert_hash = sha256(cert_der).hexdigest()
        logger.debug(f"Certificate hash: {cert_hash}")

        # Verify that the received cert hash matches the one in the event log.
        # This makes sure the TEE is the one that generated the TLS cert.
        # This verification itself is not sufficient. We also need to verify the event log matches
        # the expected RTMRs
        computed_cert_hash = cert_hash_from_eventlog(event_log)
        logger.debug(f"Computed Cert Hash from Event Log: {computed_cert_hash}")

        if computed_cert_hash == cert_hash:
            logger.debug("Certificate hash matches the event log.")
        else:
            logger.debug("Certificate hash does NOT match the event log.")
            return False

        return True

    def verify_app_compose(
        self, tcb_info_app_compose: dict, event_log: list[EventLog]
    ) -> bool:
        """Verifies that the expected compose hash matches the one in the event log.

        This makes sure the TEE is running the expected application (mainly the docker-compose).
        This verification itself is not sufficient alone. We also need to verify the event log
        matches the expected RTMRs.

        The TCBInfo app_compose is metadata sent by the server to claim what it's running.

        Args:
            tcb_info_app_compose: The app_compose as returned by the server.
            event_log: The event log entries.

        Returns:
            bool: True if verification passes, False otherwise.
        """
        if self.is_runtime_verification_disabled():
            return True

        expected_app_compose_hash = self.get_app_compose_hash()
        logger.debug(f"App compose hash: {expected_app_compose_hash}")

        # Compare with what the app claims to be running first
        remote_app_compose = json.loads(tcb_info_app_compose)
        remote_app_compose_hash = get_compose_hash(app_compose=remote_app_compose)
        if expected_app_compose_hash != remote_app_compose_hash:
            logger.debug(
                "App compose hash does NOT match TCBInfo. AppCompose from TCBInfo:\n"
                f"{pformat(remote_app_compose)}"
            )
            return False
        # Then we compare with what's in the eventlog
        eventlog_compose_hash = compose_hash_from_eventlog(event_log)
        if expected_app_compose_hash == eventlog_compose_hash:
            logger.debug("App compose hash matches the event log.")
        else:
            logger.debug(
                f"App compose hash does NOT match the event log. event log: {eventlog_compose_hash}, "
                f"computed: {expected_app_compose_hash}"
            )
            return False

        return True

    def verify(self, ssl_sock: ssl.SSLSocket) -> bool:
        """Verify a TDX quote.

        The verification depends on how the verifier was configured.

        Args:
            ssl_sock: An SSL socket to run the verification on.

        Returns:
            bool: True if verification passes, False otherwise.
        """
        hostname = ssl_sock.server_hostname
        assert hostname is not None

        # Get quote from server
        # TODO: Can we also add something about the TLS connection state?
        # The goal would be to bind the quote to the TLS session (avoid replay attacks)
        report_data = secrets.token_bytes(64)
        try:
            quote_response, tcb_info = DstackTDXVerifier.get_quote_from_tls_conn(
                report_data, ssl_sock, hostname
            )
        except Exception as e:
            logger.debug(f"Failed to get quote from {hostname}: {e}")
            return False
        logger.debug(f"Quote received for {hostname}")

        # Get event log. It's metadata to replay the RTMRs
        event_log = quote_response.decode_event_log()

        if not self.verify_cert_in_eventlog(ssl_sock, event_log):
            return False

        # Verify the quote using DCAP QVL
        quote_bytes = quote_response.decode_quote()
        if self.collateral is None:
            raise RuntimeError("Collateral are not properly set")
        report = dcap_qvl.verify(quote_bytes, self.collateral, int(time.time()))
        json_report = json.loads(report.to_json())
        logger.debug(f"TDX verification report:\n{pformat(json_report)}")

        # Check TCB status is in the allowed list
        if json_report["status"] not in self.allowed_tcb_status:
            logger.debug(
                f"TCB status not in the allowed list: {json_report['status']} "
                f"not in {self.allowed_tcb_status}"
            )
            return False
        logger.debug(f"TCB Status verified: {json_report['status']}")

        # Replay RTMRs and check them in quote
        replayed_rtmrs = quote_response.replay_rtmrs()
        replayed_rtmrs = [replayed_rtmrs[i] for i in range(self.RTMR_COUNT)]
        TD_10 = json_report["report"]["TD10"]
        for i, replayed in enumerate(replayed_rtmrs):
            quote_rtmr = TD_10[f"rt_mr{i}"]
            if quote_rtmr != replayed:
                logger.debug(
                    f"RTMR{i} values don't match: replayed({replayed}) != quote({quote_rtmr})"
                )
                return False
            else:
                logger.debug(f"RTMR{i} values match!")
        logger.debug("RTMRs values verified!")

        # This report_data is just metadata, so we make sure the server didn't get it wrong first
        assert report_data.hex() == quote_response.report_data, (
            f"Report data mismatch {report_data.hex()} != {quote_response.report_data}"
        )
        # We check the report data in the quote now
        report_data_in_quote = json_report["report"]["TD10"]["report_data"]
        if report_data_in_quote != report_data.hex():
            logger.debug(
                f"report_data don't match: sent({report_data}) != quote({report_data_in_quote})"
            )
            return False
        logger.debug("Report data verified!")

        if not self.verify_app_compose(tcb_info.app_compose, event_log):
            return False

        # Never close the socket, as it's externally managed
        # the socket should still be usable after this function returns
        return True

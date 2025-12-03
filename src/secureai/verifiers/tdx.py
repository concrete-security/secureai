"""TDX Quote Verifier Module.

This module provides functionality to verify TDX quotes using DCAP QVL library.

It includes the TDXVerifier class, which extends the BaseVerifier abstract class,
and utility functions to replay RTMR histories and event logs."""

import binascii
import json
import os
import time
from pprint import pformat
from typing import Optional

import dcap_qvl
from dstack_sdk import EventLog

from ..utils import _get_default_logger
from .base import BaseVerifier

logger = _get_default_logger()


CERT_EVENT_NAME = "New TLS Certificate"
INIT_MR = "0" * 96  # 48 bytes of zeros in hex
# Downloaded from https://api.trustedservices.intel.com via dcap_qvl
LOCAL_COLLATERAL_PATH = os.path.join(os.path.dirname(__file__), "collateral.json")


def get_leaf_keys(d: dict, base_key: Optional[tuple] = ()):
    """
    Get leaf keys in a dictionary.

    Leaf keys are the ones that don't have dict values.

    Args:
        d: base dictionary
        base_key: the prefix key to append next keys to
    Returns:
        Generators of tuples representing paths to leaf keys
    """
    for key, value in d.items():
        next_base_key = base_key + (key,)
        if isinstance(value, dict):
            yield from get_leaf_keys(value, base_key=next_base_key)
        else:
            yield next_base_key


class TDXVerifier(BaseVerifier):
    """TDX Quote Verifier using DCAP QVL.

    The main verification method is `verify`, but the verifier must be configured first
    by calling the available setter methods (set_*).
    """

    RTMR_COUNT = 4

    def __init__(self):
        self._verif_dict = {}
        self._collateral = None

    def set_rtmrs(self, rtmr_values: list):
        """Set RTMR values.

        Args:
            rtmr_values: List of RTMR values as hex strings.
        """
        if len(rtmr_values) != self.RTMR_COUNT:
            raise ValueError(
                f"You must provide {self.RTMR_COUNT} rtmr values, not {len(rtmr_values)}"
            )

        verifier = {"report": {"TD10": {}}}
        for i, value in enumerate(rtmr_values):
            verifier["report"]["TD10"][f"rt_mr{i}"] = value

        self._verif_dict.update(verifier)

    def set_report_data(self, report_data):
        """Set expected report data.
        Args:
            report_data: Hex string of expected report data.
        """
        verifier = {"report": {"TD10": {"report_data": report_data}}}
        self._verif_dict.update(verifier)

    def set_collaterals(self, collateral_json: Optional[dict] = None):
        """Set collateral for quote verification.

        Args:
            collateral_json: JSON dictionary of collateral data.
                Defaults to using local collateral file.
        """
        if collateral_json is None:
            with open(LOCAL_COLLATERAL_PATH, "r") as f:
                collateral_json = json.load(f)
        # Create collateral object
        self._collateral = dcap_qvl.QuoteCollateralV3.from_json(
            json.dumps(collateral_json)
        )

    def set_check_up_to_date(self):
        """Set verifier to check for UpToDate status."""
        verifier = {"status": "UpToDate"}
        self._verif_dict.update(verifier)

    def verify(self, quote: bytes) -> bool:
        """Verify a TDX quote.

        The verifier must be configured first by calling the available setter methods (set_*).

        Args:
            quote: Bytes representing the TDX quote to verify.

        Returns:
            bool: True if verification passes, False otherwise.
        """
        if self._collateral is None:
            raise RuntimeError(
                f"Setup collateral first by calling self.{self.set_collaterals.__name__}"
            )

        report = dcap_qvl.verify(quote, self._collateral, int(time.time()))
        json_report = json.loads(report.to_json())
        logger.debug(f"TDX verification report:\n{pformat(json_report)}")

        # Match all values in self._verif_dict to what's in the report
        for keys in get_leaf_keys(self._verif_dict):
            expected_cursor = self._verif_dict
            report_cursor = json_report
            for key in keys:
                expected_cursor = expected_cursor[key]
                report_cursor = report_cursor[key]

            keys_str = "[" + "][".join(keys) + "]"
            if expected_cursor != report_cursor:
                logger.debug(
                    f"Values don't match for report{keys_str}: expected({expected_cursor}) != report({report_cursor})"
                )
                return False
            else:
                logger.debug(f"Values matched for report{keys_str}")

        return True


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

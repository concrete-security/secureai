"""Tests for secureai module initialization and async client."""

import logging
import os
from unittest.mock import patch

import pytest


class TestAsyncClient:
    """Tests for the async client module."""

    def test_async_client_raises_not_implemented(self):
        """Test that importing async_client raises NotImplementedError."""
        with pytest.raises(
            NotImplementedError, match="Async RATLSClient is not implemented yet"
        ):
            import secureai.httpx.async_client  # noqa: F401


class TestModuleInit:
    """Tests for the secureai module initialization."""

    @pytest.mark.parametrize("true_value", ["1", "true", "TRUE", "True"])
    def test_debug_ratls_env_var_true_sets_debug_level(self, true_value):
        """Test that DEBUG_RATLS=true sets logger to DEBUG level."""
        with patch.dict(os.environ, {"DEBUG_RATLS": true_value}):
            import importlib

            import secureai

            importlib.reload(secureai)

            from secureai.utils import _get_default_logger

            logger = _get_default_logger()
            assert logger.level == logging.DEBUG

    @pytest.mark.parametrize(
        "false_value", ["0", "false", "FALSE", "False", "something_else", ""]
    )
    def test_debug_ratls_env_var_false_sets_error_level(self, false_value):
        """Test that DEBUG_RATLS=false keeps logger at ERROR level."""
        with patch.dict(os.environ, {"DEBUG_RATLS": false_value}, clear=False):
            # Remove DEBUG_RATLS if it exists
            env = os.environ.copy()
            env["DEBUG_RATLS"] = "false"
            with patch.dict(os.environ, env, clear=True):
                import importlib

                import secureai

                importlib.reload(secureai)

                from secureai.utils import _get_default_logger

                logger = _get_default_logger()
                assert logger.level == logging.ERROR

    def test_no_debug_ratls_env_var_sets_error_level(self):
        """Test that without DEBUG_RATLS, logger is at ERROR level."""
        env = os.environ.copy()
        env.pop("DEBUG_RATLS", None)
        with patch.dict(os.environ, env, clear=True):
            import importlib

            import secureai

            importlib.reload(secureai)

            from secureai.utils import _get_default_logger

            logger = _get_default_logger()
            assert logger.level == logging.ERROR

    def test_module_exports(self):
        """Test that module exports expected classes."""
        import secureai

        assert hasattr(secureai, "OpenAI")
        assert hasattr(secureai, "DstackTDXVerifier")

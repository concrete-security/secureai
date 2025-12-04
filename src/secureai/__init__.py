import logging
import os

from .openai import OpenAI
from .utils import _get_default_logger
from .verifiers import DstackTDXVerifier

logging.basicConfig(
    level=logging.ERROR, format="%(asctime)s - RATLS - %(levelname)s - %(message)s"
)

logger = _get_default_logger()


# TODO: maybe use RATLS_LOGLEVEL to set level instead of DEBUG/ERROR levels only
if os.getenv("DEBUG_RATLS", "").lower() in ("1", "true"):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.ERROR)


__all__ = ["OpenAI", "DstackTDXVerifier"]

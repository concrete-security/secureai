import logging


def _get_provenance_logger() -> logging.Logger:
    """Get the provenance module logger."""
    return logging.getLogger("provenance")

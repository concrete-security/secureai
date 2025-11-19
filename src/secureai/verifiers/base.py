from abc import ABC, abstractmethod


class BaseVerifier(ABC):
    """Base class for all quote verifiers."""

    @abstractmethod
    def verify(self, quote: bytes) -> bool:
        """
        Verify a quote.

        Args:
            quote: Bytes representing the quote to verify

        Returns:
            bool: True if verification passes, False otherwise
        """
        pass

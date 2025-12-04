import ssl
from abc import ABC, abstractmethod


class RATLSVerifier(ABC):
    """Base class for all RATLS verifiers."""

    @abstractmethod
    def verify(self, ssl_sock: ssl.SSLSocket) -> bool:
        """
        Run RATLS verification on the given SSL socket.

        Args:
            ssl_sock: An SSL socket to run the verification on.

        Returns:
            bool: True if verification passes, False otherwise
        """
        pass

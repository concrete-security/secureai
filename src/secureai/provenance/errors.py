"""Provenance verification errors."""


class ProvenanceVerificationError(Exception):
    """Exception raised when provenance verification fails.

    Attributes:
        service: The service name that caused the failure (if applicable)
        image: The image reference that failed verification (if applicable)
        reason: Detailed reason for the failure
    """

    def __init__(
        self,
        message: str,
        service: str | None = None,
        image: str | None = None,
        reason: str | None = None,
    ):
        """Initialize the error.

        Args:
            message: The main error message
            service: The service name that caused the failure
            image: The image reference that failed verification
            reason: Detailed reason for the failure
        """
        self.service = service
        self.image = image
        self.reason = reason
        super().__init__(message)

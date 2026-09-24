"""AIShield - Base Connector Interface (Stage 6B).

Defines the abstract interface for all platform ingestion connectors.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional

from services.ingestion_service import NormalizedPost


class BaseConnector(ABC):
    """Abstract base class for external data source connectors."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Return the unique registered identifier for this source (e.g. 'manual', 'bluesky')."""
        pass

    @abstractmethod
    def connect(self) -> None:
        """Establish connection or initialize connector runtime."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Terminate connection or cleanup connector runtime."""
        pass

    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the connector is currently active and ready to receive data."""
        pass

    @abstractmethod
    def receive(self) -> Optional[Any]:
        """Fetch or retrieve raw item payload from the connector if available."""
        pass

    @abstractmethod
    def normalize(self, raw_item: Any) -> NormalizedPost:
        """Transform platform-specific raw payload into a standardized NormalizedPost."""
        pass

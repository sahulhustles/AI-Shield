"""AIShield - Connector Registry (Stage 6B).

Registers, tracks, and provides access to platform ingestion connectors.
"""

from typing import Any, Dict, List, Optional

from services.connectors.base_connector import BaseConnector
from services.connectors.bluesky_connector import BlueskyConnector
from services.connectors.manual_connector import ManualConnector
from services.connectors.mastodon_connector import MastodonConnector
from services.connectors.youtube_connector import YouTubeConnector
from services.source_post_service import SUPPORTED_SOURCES


class ConnectorRegistry:
    """Registry maintaining active and placeholder platform connectors."""

    def __init__(
        self,
        auto_register_defaults: bool = True,
        bluesky_connector: Optional[BlueskyConnector] = None,
        mastodon_connector: Optional[MastodonConnector] = None,
        youtube_connector: Optional[YouTubeConnector] = None,
    ) -> None:
        """Initialize ConnectorRegistry and optionally register default connectors."""
        self._connectors: Dict[str, BaseConnector] = {}
        if auto_register_defaults:
            self.register_defaults(
                bluesky_connector=bluesky_connector,
                mastodon_connector=mastodon_connector,
                youtube_connector=youtube_connector,
            )

    def register_defaults(
        self,
        bluesky_connector: Optional[BlueskyConnector] = None,
        mastodon_connector: Optional[MastodonConnector] = None,
        youtube_connector: Optional[YouTubeConnector] = None,
    ) -> None:
        """Register initial default connectors (manual, Bluesky, Mastodon, YouTube)."""
        manual = ManualConnector()
        manual.connect()
        self.register(manual)

        bsky = bluesky_connector or BlueskyConnector()
        self.register(bsky)

        masto = mastodon_connector or MastodonConnector()
        self.register(masto)

        yt = youtube_connector or YouTubeConnector()
        self.register(yt)

    def register(self, connector: BaseConnector) -> None:
        """Register a connector instance for its source_name."""
        if not isinstance(connector, BaseConnector):
            raise TypeError(f"Connector must be an instance of BaseConnector, got {type(connector).__name__}.")
        source_name = connector.source_name.strip().lower()
        self._connectors[source_name] = connector

    def get(self, source_name: str) -> Optional[BaseConnector]:
        """Retrieve a registered connector by source name."""
        if not source_name:
            return None
        return self._connectors.get(source_name.strip().lower())

    def list_sources(self) -> List[str]:
        """Return all supported source names in a deterministic sorted order."""
        return sorted(list(SUPPORTED_SOURCES))

    def get_connector_states(self) -> Dict[str, Dict[str, Any]]:
        """Return operational state summary for all supported source platforms."""
        states = {}
        for src in sorted(list(SUPPORTED_SOURCES)):
            connector = self.get(src)
            if connector is not None:
                if hasattr(connector, "get_status") and callable(connector.get_status):
                    st = dict(connector.get_status())
                    st_val = st.get("status") or st.get("state") or ("CONNECTED" if connector.is_running() else "DISABLED")
                    st["status"] = st_val
                    st["state"] = st_val
                    states[src] = st
                else:
                    states[src] = {
                        "status": "available",
                        "state": "AVAILABLE",
                        "running": connector.is_running(),
                    }
            else:
                states[src] = {
                    "status": "NOT_CONFIGURED",
                    "state": "NOT_CONFIGURED",
                    "running": False,
                }
        return states

    def disconnect_all(self) -> None:
        """Disconnect and gracefully stop all registered connectors."""
        for connector in list(self._connectors.values()):
            try:
                if hasattr(connector, "disconnect") and callable(connector.disconnect):
                    connector.disconnect()
            except Exception:
                pass

"""
Phishing Detector - Live Cyber Attack Map WebSocket
Copyright (c) 2026 BaoZ

Broadcasts scan events (source -> target) to all connected clients for real-time map visualization.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Handles active WebSocket connections: connect, disconnect, broadcast."""

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)
        logger.info("[LiveMap] Client connected. Total: %s", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)
        logger.debug("[LiveMap] Client disconnected. Total: %s", len(self._connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Send JSON message to all connected clients."""
        if not self._connections:
            return
        payload = json.dumps(message)
        dead: List[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception as e:
                logger.debug("[LiveMap] Send failed for one client: %s", e)
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


# Singleton for use from scan router
live_map_manager = ConnectionManager()


@router.websocket("/live-map")
async def websocket_live_map(websocket: WebSocket):
    """
    WebSocket endpoint for Live Cyber Attack Map.
    Clients receive broadcast messages: { source: {lat, lon}, target: {lat, lon}, type: "PHISHING"|"SAFE" }.
    """
    await live_map_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; optional: handle pings or client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        live_map_manager.disconnect(websocket)

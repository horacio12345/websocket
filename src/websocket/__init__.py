# src/websocket/__init__.py
"""
WebSocket - Servidor WebSocket seguro con autenticación
"""

from .server import WebSocketServer, create_websocket_server, ClientConnection

__all__ = [
    'WebSocketServer',
    'create_websocket_server', 
    'ClientConnection'
]
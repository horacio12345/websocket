# src/__init__.py
"""
Email Monitor - Sistema de monitoreo de emails en tiempo real
Arquitectura modular para producción
"""

__version__ = "1.0.0"
__author__ = "Email Monitor Team"
__description__ = "Sistema de monitoreo de emails con WebSocket y autenticación JWT"

# Exportar configuración principal
from .core.config import config

# Exportar excepciones principales
from .core.exceptions import (
    EmailMonitorError,
    AuthenticationError,
    SecurityError,
    EmailError,
    WebSocketError
)

# Exportar constantes principales
from .core.constants import VERSION, WSMessageTypes

__all__ = [
    'config',
    'EmailMonitorError',
    'AuthenticationError', 
    'SecurityError',
    'EmailError',
    'WebSocketError',
    'VERSION',
    'WSMessageTypes'
]
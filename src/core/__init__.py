# src/core/__init__.py
"""
Core - Módulos fundamentales del sistema
"""

from .config import config, Config
from .exceptions import *
from .constants import *

__all__ = [
    'config',
    'Config',
    'VERSION',
    'WSMessageTypes',
    'WSCloseCodes',
    'Limits',
    'Timeouts',
    'Permissions',
    'Roles'
]
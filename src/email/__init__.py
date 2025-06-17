# src/email/__init__.py
"""
Email - Sistema de monitoreo y procesamiento de emails
"""

from .monitor import EmailMonitor, EmailMonitorManager, create_email_monitor, create_email_monitor_manager
from .processor import EmailProcessor, EmailData, AttachmentData, create_email_processor

__all__ = [
    'EmailMonitor',
    'EmailMonitorManager', 
    'create_email_monitor',
    'create_email_monitor_manager',
    'EmailProcessor', 
    'EmailData',
    'AttachmentData',
    'create_email_processor'
]
# src/main.py
import asyncio
import signal
import sys
from datetime import datetime
from typing import Optional

from .core.config import config
from .core.constants import VERSION, SystemEvents, Permissions
from .core.exceptions import EmailMonitorError
from .websocket import WebSocketServer, create_websocket_server
from .email import EmailMonitorManager, EmailData, create_email_monitor_manager
from .utils.logger import setup_application_logging, get_logger, get_security_logger

logger = get_logger(__name__)
security_logger = get_security_logger()

class EmailMonitorApplication:
    """Aplicación principal del Email Monitor"""
    
    def __init__(self):
        self.websocket_server: Optional[WebSocketServer] = None
        self.email_manager: Optional[EmailMonitorManager] = None
        self.running = False
        self.startup_time: Optional[datetime] = None
        
        logger.info(f"🚀 Email Monitor v{VERSION} inicializando...")
        logger.info(f"Entorno: {config.environment}")
        logger.info(f"Debug: {config.debug}")
    
    async def start(self):
        """Inicia la aplicación completa"""
        try:
            self.startup_time = datetime.now()
            self.running = True
            
            # 1. Configurar logging
            setup_application_logging(
                log_level=config.logging.level,
                log_file=config.logging.file_path,
                security_log_file=config.logging.security_log_path,
                environment=config.environment
            )
            
            logger.info("📋 Logging configurado")
            
            # 2. Validar configuración
            self._validate_configuration()
            
            # 3. Inicializar servicios
            await self._initialize_services()
            
            # 4. Configurar handlers de señales
            self._setup_signal_handlers()
            
            # 5. Iniciar monitoreo de emails
            self._start_email_monitoring()
            
            # 6. Iniciar servidor WebSocket
            logger.info("🌐 Iniciando WebSocket Server...")
            await self.websocket_server.start()
            
        except Exception as e:
            logger.critical(f"Error crítico iniciando aplicación: {e}")
            security_logger.suspicious_activity(SystemEvents.SERVER_ERROR, {
                "error": str(e),
                "startup_time": self.startup_time.isoformat() if self.startup_time else None
            })
            raise
    
    async def stop(self):
        """Detiene la aplicación de forma limpia"""
        if not self.running:
            return
        
        self.running = False
        logger.info("🛑 Deteniendo Email Monitor...")
        
        try:
            # 1. Detener monitoreo de emails
            if self.email_manager:
                logger.info("Deteniendo monitores de email...")
                self.email_manager.stop_all()
            
            # 2. Detener servidor WebSocket
            if self.websocket_server:
                logger.info("Deteniendo WebSocket Server...")
                await self.websocket_server.stop()
            
            # 3. Log de parada exitosa
            uptime = (datetime.now() - self.startup_time).total_seconds() if self.startup_time else 0
            logger.info(f"✅ Email Monitor detenido exitosamente (uptime: {uptime:.1f}s)")
            security_logger.suspicious_activity(SystemEvents.SERVER_STOP, {
                "uptime_seconds": uptime,
                "clean_shutdown": True
            })
            
        except Exception as e:
            logger.error(f"Error durante parada: {e}")
            security_logger.suspicious_activity(SystemEvents.SERVER_ERROR, {
                "error": str(e),
                "context": "shutdown"
            })
    
    def _validate_configuration(self):
        """Valida la configuración antes de iniciar"""
        logger.info("🔍 Validando configuración...")
        
        # Verificar configuración de email
        if not config.email.username or not config.email.password:
            raise EmailMonitorError("Configuración de email incompleta")
        
        # Verificar configuración JWT
        if not config.jwt.secret_key:
            raise EmailMonitorError("JWT secret key no configurado")
        
        # Verificar configuración SSL en producción
        if config.is_production() and not config.ssl.is_enabled:
            logger.warning("⚠️ SSL no configurado en producción")
        
        logger.info("✅ Configuración validada")
    
    async def _initialize_services(self):
        """Inicializa todos los servicios del sistema"""
        logger.info("⚙️ Inicializando servicios...")
        
        # 1. Crear WebSocket Server
        self.websocket_server = create_websocket_server(config)
        logger.info("✅ WebSocket Server creado")
        
        # 2. Crear Email Manager
        self.email_manager = create_email_monitor_manager()
        logger.info("✅ Email Manager creado")
        
        # 3. Agregar monitor de email principal
        email_monitor = self.email_manager.add_monitor("primary", config.email)
        logger.info(f"✅ Monitor de email agregado: {config.email.username}")
        
        # 4. Probar conexión de email
        if not email_monitor.test_connection():
            raise EmailMonitorError("No se pudo conectar al servidor de email")
        logger.info("✅ Conexión de email verificada")
        
        # 5. Configurar callback entre email y websocket
        self._setup_email_websocket_bridge()
        
        logger.info("🎯 Todos los servicios inicializados")
    
    def _setup_email_websocket_bridge(self):
        """Configura el puente entre el monitor de email y WebSocket"""
        async def email_callback(email_data: EmailData):
            """Callback para enviar emails vía WebSocket"""
            try:
                # Convertir EmailData a formato WebSocket
                message = {
                    "type": "new_email",
                    "id": email_data.id,
                    "subject": email_data.subject,
                    "sender": email_data.sender,
                    "to": email_data.to,
                    "cc": email_data.cc,
                    "date": email_data.date,
                    "timestamp": email_data.timestamp,
                    "text_content": email_data.text_content,
                    "html_content": email_data.html_content,
                    "attachments": [
                        {
                            "filename": att.filename,
                            "content_type": att.content_type,
                            "size": att.size,
                            "is_safe": att.is_safe,
                            "hash": att.hash,
                            "data": att.data.hex() if att.data else None
                        }
                        for att in email_data.attachments
                    ],
                    "images": [
                        {
                            "filename": img.filename,
                            "content_type": img.content_type,
                            "size": img.size,
                            "data": img.data.hex() if img.data else None
                        }
                        for img in email_data.images
                    ],
                    "security_flags": email_data.security_flags,
                    "raw_size": email_data.raw_size
                }
                
                # Broadcast a clientes con permiso de lectura
                await self.websocket_server.broadcast_to_all(
                    message, 
                    permission_required=Permissions.READ_EMAILS
                )
                
                logger.debug(f"Email enviado vía WebSocket: {email_data.subject[:50]}...")
                
            except Exception as e:
                logger.error(f"Error enviando email vía WebSocket: {e}")
        
        # Configurar el callback
        self.email_manager.set_global_callback(email_callback)
        logger.info("🔗 Puente Email-WebSocket configurado")
    
    def _start_email_monitoring(self):
        """Inicia el monitoreo de emails"""
        logger.info("📧 Iniciando monitoreo de emails...")
        
        # Obtener el loop de asyncio actual
        loop = asyncio.get_event_loop()
        
        # Iniciar todos los monitores
        self.email_manager.start_all(loop)
        
        logger.info("✅ Monitoreo de emails activo")
    
    def _setup_signal_handlers(self):
        """Configura handlers para señales del sistema"""
        if sys.platform != "win32":
            # Unix/Linux
            for sig in [signal.SIGTERM, signal.SIGINT]:
                signal.signal(sig, self._signal_handler)
        else:
            # Windows
            signal.signal(signal.SIGINT, self._signal_handler)
        
        logger.info("🔧 Signal handlers configurados")
    
    def _signal_handler(self, signum, frame):
        """Handler para señales del sistema"""
        logger.info(f"🚨 Señal recibida: {signum}")
        
        # Crear tarea para parada limpia
        loop = asyncio.get_event_loop()
        loop.create_task(self.stop())
    
    def get_system_status(self) -> dict:
        """Obtiene el estado del sistema completo"""
        uptime = None
        if self.startup_time:
            uptime = (datetime.now() - self.startup_time).total_seconds()
        
        return {
            "version": VERSION,
            "environment": config.environment,
            "running": self.running,
            "uptime_seconds": uptime,
            "startup_time": self.startup_time.isoformat() if self.startup_time else None,
            "websocket_stats": self.websocket_server.get_stats() if self.websocket_server else None,
            "email_stats": self.email_manager.get_all_stats() if self.email_manager else None,
            "config_summary": {
                "websocket_url": config.get_websocket_url(),
                "email_server": f"{config.email.server}:{config.email.port}",
                "ssl_enabled": config.ssl.is_enabled,
                "max_connections": config.security.max_connections,
                "log_level": config.logging.level
            }
        }

# Función principal
async def main():
    """Función principal de la aplicación"""
    app = EmailMonitorApplication()
    
    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("Interrupción por teclado recibida")
    except Exception as e:
        logger.critical(f"Error fatal: {e}")
        sys.exit(1)
    finally:
        await app.stop()

# Punto de entrada
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Aplicación interrumpida por el usuario")
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)
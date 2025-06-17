# src/email/monitor.py
import imaplib
import email as email_lib
import asyncio
import threading
import time
from typing import Optional, Callable, Dict, Any
from datetime import datetime

from ..core.config import EmailConfig
from ..core.exceptions import EmailConnectionError, EmailAuthenticationError, EmailError
from ..core.constants import Permissions
from ..utils.logger import get_logger, log_performance
from .processor import EmailProcessor, EmailData, create_email_processor

logger = get_logger(__name__)

class EmailMonitor:
    """Monitor de emails IMAP con reconexión automática"""
    
    def __init__(self, email_config: EmailConfig):
        self.config = email_config
        self.processor = create_email_processor()
        
        # Estado del monitor
        self.running = False
        self.connected = False
        self.thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Callback para enviar emails procesados
        self.email_callback: Optional[Callable[[EmailData], None]] = None
        
        # Estadísticas
        self.stats = {
            "emails_processed": 0,
            "connection_errors": 0,
            "last_check": None,
            "last_email": None,
            "uptime_start": None
        }
        
        # Control de errores
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5
        
        logger.info(f"Email Monitor inicializado para {self.config.username}")
    
    def set_email_callback(self, callback: Callable[[EmailData], None]):
        """Configura el callback para emails procesados"""
        self.email_callback = callback
        logger.debug("Callback de emails configurado")
    
    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """Inicia el monitor de emails en un hilo separado"""
        if self.running:
            logger.warning("Email monitor ya está ejecutándose")
            return
        
        self.running = True
        self.loop = loop
        self.stats["uptime_start"] = datetime.now()
        
        # Iniciar en hilo separado
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        
        logger.info("🚀 Email Monitor iniciado")
    
    def stop(self):
        """Detiene el monitor de emails"""
        if not self.running:
            return
        
        self.running = False
        logger.info("🛑 Deteniendo Email Monitor...")
        
        # Esperar a que termine el hilo
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=10)
            if self.thread.is_alive():
                logger.warning("Email Monitor no se detuvo en tiempo esperado")
        
        logger.info("✅ Email Monitor detenido")
    
    def _monitor_loop(self):
        """Loop principal del monitor de emails"""
        logger.info(f"Iniciando monitoreo de {self.config.server}:{self.config.port}")
        
        while self.running:
            try:
                self._check_emails()
                self.consecutive_errors = 0  # Reset en éxito
                
                # Pausa entre chequeos
                time.sleep(self.config.check_interval)
                
            except Exception as e:
                self.consecutive_errors += 1
                self.stats["connection_errors"] += 1
                
                logger.error(f"Error en monitor de emails ({self.consecutive_errors}/{self.max_consecutive_errors}): {e}")
                
                # Si hay demasiados errores consecutivos, parar
                if self.consecutive_errors >= self.max_consecutive_errors:
                    logger.critical("Demasiados errores consecutivos. Deteniendo monitor.")
                    self.running = False
                    break
                
                # Backoff exponencial
                sleep_time = min(60, 5 * (2 ** self.consecutive_errors))
                logger.info(f"Reintentando en {sleep_time} segundos...")
                time.sleep(sleep_time)
        
        logger.info("Monitor de emails terminado")
    
    @log_performance
    def _check_emails(self):
        """Verifica emails nuevos en el servidor"""
        self.stats["last_check"] = datetime.now()
        
        mail = None
        try:
            # Conectar al servidor IMAP
            mail = self._connect_imap()
            self.connected = True
            
            # Seleccionar INBOX
            mail.select("INBOX")
            
            # Buscar emails no leídos
            status, messages = mail.search(None, 'UNSEEN')
            
            if status != 'OK':
                raise EmailError(f"Error buscando emails: {status}")
            
            if messages[0]:
                email_ids = messages[0].split()
                logger.info(f"Encontrados {len(email_ids)} emails nuevos")
                
                # Procesar cada email
                for msg_id in email_ids:
                    if not self.running:
                        break
                    
                    try:
                        self._process_email(mail, msg_id.decode())
                    except Exception as e:
                        logger.error(f"Error procesando email {msg_id}: {e}")
                        continue
            
        except imaplib.IMAP4.error as e:
            self.connected = False
            if "authentication" in str(e).lower():
                raise EmailAuthenticationError(f"Error de autenticación IMAP: {e}")
            else:
                raise EmailConnectionError(f"Error IMAP: {e}")
        
        except Exception as e:
            self.connected = False
            raise EmailConnectionError(f"Error conectando a email: {e}")
        
        finally:
            # Cerrar conexión
            if mail:
                try:
                    mail.close()
                    mail.logout()
                except Exception as e:
                    logger.debug(f"Error cerrando conexión IMAP: {e}")
    
    def _connect_imap(self) -> imaplib.IMAP4_SSL:
        """Establece conexión IMAP SSL"""
        try:
            # Crear conexión SSL
            mail = imaplib.IMAP4_SSL(
                self.config.server,
                self.config.port,
                timeout=self.config.timeout
            )
            
            # Autenticar
            mail.login(self.config.username, self.config.password)
            
            logger.debug(f"Conectado a {self.config.server} como {self.config.username}")
            return mail
            
        except imaplib.IMAP4.error as e:
            if "authentication" in str(e).lower():
                logger.error(f"Credenciales incorrectas para {self.config.username}")
                raise EmailAuthenticationError(f"Autenticación fallida: {e}")
            else:
                raise EmailConnectionError(f"Error IMAP: {e}")
        
        except Exception as e:
            logger.error(f"Error conectando a {self.config.server}: {e}")
            raise EmailConnectionError(f"No se pudo conectar al servidor: {e}")
    
    def _process_email(self, mail: imaplib.IMAP4_SSL, msg_id: str):
        """Procesa un email individual"""
        try:
            # Obtener email completo
            status, msg_data = mail.fetch(msg_id, '(RFC822)')
            
            if status != 'OK' or not msg_data:
                logger.warning(f"No se pudo obtener email {msg_id}")
                return
            
            # Parsear email
            email_body = email_lib.message_from_bytes(msg_data[0][1])
            
            # Procesar con EmailProcessor
            email_data = self.processor.process_email(email_body, msg_id)
            
            # Actualizar estadísticas
            self.stats["emails_processed"] += 1
            self.stats["last_email"] = datetime.now()
            
            # Enviar a través del callback si está configurado
            if self.email_callback:
                try:
                    if self.loop:
                        # Ejecutar callback en el loop de asyncio
                        asyncio.run_coroutine_threadsafe(
                            self._async_email_callback(email_data),
                            self.loop
                        )
                    else:
                        # Ejecutar callback directamente
                        self.email_callback(email_data)
                        
                except Exception as e:
                    logger.error(f"Error en callback de email: {e}")
            
            logger.info(f"✅ Email procesado: {email_data.subject[:50]}...")
            
        except Exception as e:
            logger.error(f"Error procesando email {msg_id}: {e}")
            raise
    
    async def _async_email_callback(self, email_data: EmailData):
        """Wrapper async para el callback de emails"""
        if self.email_callback:
            if asyncio.iscoroutinefunction(self.email_callback):
                await self.email_callback(email_data)
            else:
                self.email_callback(email_data)
    
    def test_connection(self) -> bool:
        """Prueba la conexión IMAP"""
        try:
            mail = self._connect_imap()
            mail.select("INBOX")  # ← AGREGAR ESTA LÍNEA
            mail.close()
            mail.logout()
            logger.info("✅ Conexión IMAP exitosa")
            return True
        except Exception as e:
            logger.error(f"❌ Error de conexión IMAP: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del monitor"""
        uptime = None
        if self.stats["uptime_start"]:
            uptime = (datetime.now() - self.stats["uptime_start"]).total_seconds()
        
        return {
            "running": self.running,
            "connected": self.connected,
            "server": f"{self.config.server}:{self.config.port}",
            "username": self.config.username,
            "check_interval": self.config.check_interval,
            "uptime_seconds": uptime,
            "consecutive_errors": self.consecutive_errors,
            "max_consecutive_errors": self.max_consecutive_errors,
            **self.stats,
            "last_check": self.stats["last_check"].isoformat() if self.stats["last_check"] else None,
            "last_email": self.stats["last_email"].isoformat() if self.stats["last_email"] else None,
            "processor_stats": self.processor.get_stats()
        }
    
    def force_check(self):
        """Fuerza un chequeo inmediato de emails (para testing/debug)"""
        if not self.running:
            logger.warning("Monitor no está ejecutándose")
            return
        
        logger.info("Forzando chequeo de emails...")
        threading.Thread(target=self._check_emails, daemon=True).start()

class EmailMonitorManager:
    """Gestor de múltiples monitores de email"""
    
    def __init__(self):
        self.monitors: Dict[str, EmailMonitor] = {}
        self.global_callback: Optional[Callable[[EmailData], None]] = None
        
    def add_monitor(self, name: str, email_config: EmailConfig) -> EmailMonitor:
        """Agrega un nuevo monitor de email"""
        if name in self.monitors:
            raise ValueError(f"Monitor '{name}' ya existe")
        
        monitor = EmailMonitor(email_config)
        
        # Configurar callback global si existe
        if self.global_callback:
            monitor.set_email_callback(self.global_callback)
        
        self.monitors[name] = monitor
        logger.info(f"Monitor '{name}' agregado")
        
        return monitor
    
    def remove_monitor(self, name: str):
        """Remueve un monitor de email"""
        if name not in self.monitors:
            logger.warning(f"Monitor '{name}' no existe")
            return
        
        monitor = self.monitors.pop(name)
        monitor.stop()
        logger.info(f"Monitor '{name}' removido")
    
    def set_global_callback(self, callback: Callable[[EmailData], None]):
        """Configura un callback global para todos los monitores"""
        self.global_callback = callback
        
        # Aplicar a monitores existentes
        for monitor in self.monitors.values():
            monitor.set_email_callback(callback)
        
        logger.info("Callback global configurado")
    
    def start_all(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """Inicia todos los monitores"""
        for name, monitor in self.monitors.items():
            try:
                monitor.start(loop)
                logger.info(f"Monitor '{name}' iniciado")
            except Exception as e:
                logger.error(f"Error iniciando monitor '{name}': {e}")
    
    def stop_all(self):
        """Detiene todos los monitores"""
        for name, monitor in self.monitors.items():
            try:
                monitor.stop()
                logger.info(f"Monitor '{name}' detenido")
            except Exception as e:
                logger.error(f"Error deteniendo monitor '{name}': {e}")
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Obtiene estadísticas de todos los monitores"""
        return {
            name: monitor.get_stats()
            for name, monitor in self.monitors.items()
        }

# Factory functions
def create_email_monitor(email_config: EmailConfig) -> EmailMonitor:
    """Factory para crear EmailMonitor"""
    return EmailMonitor(email_config)

def create_email_monitor_manager() -> EmailMonitorManager:
    """Factory para crear EmailMonitorManager"""
    return EmailMonitorManager()
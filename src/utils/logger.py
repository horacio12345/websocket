# src/utils/logger.py
import logging
import logging.handlers
import json
import os
import re
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Patrones para filtrar información sensible
SENSITIVE_PATTERNS = [
    (re.compile(r'password["\s]*[:=]["\s]*[^"\s,}]+', re.IGNORECASE), 'password":"***"'),
    (re.compile(r'token["\s]*[:=]["\s]*[^"\s,}]+', re.IGNORECASE), 'token":"***"'),
    (re.compile(r'secret["\s]*[:=]["\s]*[^"\s,}]+', re.IGNORECASE), 'secret":"***"'),
    (re.compile(r'key["\s]*[:=]["\s]*[^"\s,}]+', re.IGNORECASE), 'key":"***"'),
    (re.compile(r'auth["\s]*[:=]["\s]*[^"\s,}]+', re.IGNORECASE), 'auth":"***"'),
]

class SensitiveDataFilter(logging.Filter):
    """Filtro para remover información sensible de los logs"""
    
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern, replacement in SENSITIVE_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        
        # Filtrar también args si existen
        if hasattr(record, 'args') and record.args:
            filtered_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    for pattern, replacement in SENSITIVE_PATTERNS:
                        arg = pattern.sub(replacement, arg)
                filtered_args.append(arg)
            record.args = tuple(filtered_args)
        
        return True

class ProductionJSONFormatter(logging.Formatter):
    """Formatter JSON para producción - logs estructurados y minimalistas"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Agregar información de excepción si existe
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Agregar campos extra si existen
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

class DevelopmentFormatter(logging.Formatter):
    """Formatter para desarrollo - más legible"""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

class SecurityLogger:
    """Logger especializado para eventos de seguridad"""
    
    def __init__(self, logger_name: str = 'security'):
        self.logger = logging.getLogger(logger_name)
    
    def auth_failure(self, username: str, ip: str, reason: str):
        """Log de fallo de autenticación"""
        self.logger.warning("Authentication failed", extra={
            'event_type': 'auth_failure',
            'username': username,
            'ip_address': ip,
            'reason': reason
        })
    
    def auth_success(self, username: str, ip: str):
        """Log de autenticación exitosa"""
        self.logger.info("Authentication successful", extra={
            'event_type': 'auth_success',
            'username': username,
            'ip_address': ip
        })
    
    def rate_limit_exceeded(self, identifier: str, endpoint: str):
        """Log de rate limit excedido"""
        self.logger.warning("Rate limit exceeded", extra={
            'event_type': 'rate_limit_exceeded',
            'identifier': identifier,
            'endpoint': endpoint
        })
    
    def ip_blocked(self, ip: str, reason: str):
        """Log de IP bloqueada"""
        self.logger.warning("IP blocked", extra={
            'event_type': 'ip_blocked',
            'ip_address': ip,
            'reason': reason
        })
    
    def suspicious_activity(self, activity_type: str, details: Dict[str, Any]):
        """Log de actividad sospechosa"""
        self.logger.warning("Suspicious activity detected", extra={
            'event_type': 'suspicious_activity',
            'activity_type': activity_type,
            **details
        })

def setup_logger(
    name: str,
    log_file: str = None,
    level: str = "INFO",
    environment: str = "development",
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    Configura un logger según el entorno
    
    Args:
        name: Nombre del logger
        log_file: Archivo de log (opcional)
        level: Nivel de logging
        environment: Entorno (development/production)
        max_file_size: Tamaño máximo del archivo antes de rotar
        backup_count: Número de archivos de backup a mantener
    """
    logger = logging.getLogger(name)
    
    # Evitar duplicar handlers si ya está configurado
    if logger.handlers:
        return logger
    
    # Configurar nivel según entorno
    if environment == "production":
        # En producción: solo ERROR, WARNING, INFO
        if level == "DEBUG":
            level = "INFO"
    
    logger.setLevel(getattr(logging, level.upper()))
    
    # Agregar filtro para información sensible
    sensitive_filter = SensitiveDataFilter()
    
    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.addFilter(sensitive_filter)
    
    if environment == "production":
        # Producción: formato JSON estructurado
        console_formatter = ProductionJSONFormatter()
        # En producción, solo WARNING y ERROR en consola
        console_handler.setLevel(logging.WARNING)
    else:
        # Desarrollo: formato legible
        console_formatter = DevelopmentFormatter()
    
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Handler para archivo (si se especifica)
    if log_file:
        # Crear directorio si no existe
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Usar RotatingFileHandler para rotación automática
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.addFilter(sensitive_filter)
        
        if environment == "production":
            file_formatter = ProductionJSONFormatter()
        else:
            file_formatter = DevelopmentFormatter()
        
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def setup_application_logging(
    log_level: str = "INFO",
    log_file: str = "logs/email_monitor.log",
    security_log_file: str = "logs/security.log",
    environment: str = "development"
):
    """
    Configura el logging de toda la aplicación
    """
    # Logger principal de la aplicación
    setup_logger(
        name="email_monitor",
        log_file=log_file,
        level=log_level,
        environment=environment
    )
    
    # Logger de seguridad separado
    setup_logger(
        name="security",
        log_file=security_log_file,
        level="INFO",  # Seguridad siempre en INFO o superior
        environment=environment
    )
    
    # Configurar loggers de librerías externas
    # Reducir ruido de librerías en producción
    if environment == "production":
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("websockets").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """
    Obtiene un logger hijo del logger principal
    
    Args:
        name: Nombre del módulo (__name__)
    
    Returns:
        Logger configurado
    """
    # Si no hay punto en el nombre, es un logger de nivel superior
    if '.' not in name:
        return logging.getLogger(f"email_monitor.{name}")
    
    # Si ya tiene prefijo, usarlo tal como está
    if name.startswith("email_monitor"):
        return logging.getLogger(name)
    
    # Agregar prefijo de la aplicación
    return logging.getLogger(f"email_monitor.{name}")

def get_security_logger() -> SecurityLogger:
    """Obtiene el logger especializado de seguridad"""
    return SecurityLogger()

# Función de utilidad para logging de performance
def log_performance(func):
    """Decorator para loggear el tiempo de ejecución de funciones críticas"""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = datetime.now()
        
        try:
            result = func(*args, **kwargs)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Solo loggear si toma más de 1 segundo
            if execution_time > 1.0:
                logger.info(f"Performance: {func.__name__} took {execution_time:.2f}s", extra={
                    'event_type': 'performance',
                    'function': func.__name__,
                    'execution_time': execution_time
                })
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Error in {func.__name__} after {execution_time:.2f}s: {e}", extra={
                'event_type': 'performance_error',
                'function': func.__name__,
                'execution_time': execution_time,
                'error': str(e)
            })
            raise
    
    return wrapper

# Inicialización automática básica
_initialized = False

def ensure_initialized():
    """Asegura que el logging esté inicializado con configuración básica"""
    global _initialized
    if not _initialized:
        # Configuración mínima por defecto
        environment = os.getenv("ENVIRONMENT", "development")
        log_level = os.getenv("LOG_LEVEL", "INFO")
        
        setup_application_logging(
            log_level=log_level,
            environment=environment
        )
        _initialized = True

# Auto-inicializar al importar el módulo
ensure_initialized()
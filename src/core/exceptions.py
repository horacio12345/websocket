# src/core/exceptions.py
"""
Excepciones personalizadas del sistema
"""

class EmailMonitorError(Exception):
    """Excepción base del sistema"""
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> dict:
        """Convierte la excepción a diccionario para APIs"""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details
        }

# === EXCEPCIONES DE AUTENTICACIÓN ===

class AuthenticationError(EmailMonitorError):
    """Error de autenticación"""
    pass

class TokenExpiredError(AuthenticationError):
    """Token JWT expirado"""
    pass

class InvalidTokenError(AuthenticationError):
    """Token JWT inválido o malformado"""
    pass

class InvalidCredentialsError(AuthenticationError):
    """Credenciales de usuario inválidas"""
    pass

class UserNotFoundError(AuthenticationError):
    """Usuario no encontrado"""
    pass

class UserLockedError(AuthenticationError):
    """Cuenta de usuario bloqueada"""
    def __init__(self, message: str, locked_until: str = None):
        super().__init__(message, details={"locked_until": locked_until})

class PermissionDeniedError(AuthenticationError):
    """Permisos insuficientes"""
    pass

# === EXCEPCIONES DE SEGURIDAD ===

class SecurityError(EmailMonitorError):
    """Error de seguridad"""
    pass

class RateLimitExceededError(SecurityError):
    """Límite de velocidad excedido"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message, details={"retry_after": retry_after})

class IPBlockedError(SecurityError):
    """IP bloqueada"""
    pass

class OriginNotAllowedError(SecurityError):
    """Origen no permitido"""
    pass

class MaxConnectionsExceededError(SecurityError):
    """Máximo de conexiones excedido"""
    pass

# === EXCEPCIONES DE WEBSOCKET ===

class WebSocketError(EmailMonitorError):
    """Error del servidor WebSocket"""
    pass

class ClientNotFoundError(WebSocketError):
    """Cliente WebSocket no encontrado"""
    pass

class ConnectionRejectedError(WebSocketError):
    """Conexión WebSocket rechazada"""
    pass

class MessageTooLargeError(WebSocketError):
    """Mensaje demasiado grande"""
    pass

class InvalidMessageFormatError(WebSocketError):
    """Formato de mensaje inválido"""
    pass

# === EXCEPCIONES DE EMAIL ===

class EmailError(EmailMonitorError):
    """Error del sistema de email"""
    pass

class EmailConnectionError(EmailError):
    """Error de conexión al servidor de email"""
    pass

class EmailAuthenticationError(EmailError):
    """Error de autenticación con el servidor de email"""
    pass

class EmailParsingError(EmailError):
    """Error parseando un email"""
    pass

class AttachmentTooLargeError(EmailError):
    """Adjunto demasiado grande"""
    pass

class UnsafeAttachmentError(EmailError):
    """Adjunto potencialmente peligroso"""
    pass

# === EXCEPCIONES DE BASE DE DATOS ===

class DatabaseError(EmailMonitorError):
    """Error de base de datos"""
    pass

class DatabaseConnectionError(DatabaseError):
    """Error de conexión a la base de datos"""
    pass

class UserAlreadyExistsError(DatabaseError):
    """Usuario ya existe"""
    pass

class MigrationError(DatabaseError):
    """Error en migración de base de datos"""
    pass

# === EXCEPCIONES DE CONFIGURACIÓN ===

class ConfigurationError(EmailMonitorError):
    """Error de configuración"""
    pass

class MissingConfigurationError(ConfigurationError):
    """Configuración requerida faltante"""
    pass

class InvalidConfigurationError(ConfigurationError):
    """Configuración inválida"""
    pass

# === EXCEPCIONES DE VALIDACIÓN ===

class ValidationError(EmailMonitorError):
    """Error de validación de datos"""
    pass

class InvalidInputError(ValidationError):
    """Entrada de datos inválida"""
    pass

class MissingFieldError(ValidationError):
    """Campo requerido faltante"""
    pass

# === UTILIDADES ===

def handle_exception(exc: Exception) -> dict:
    """
    Convierte cualquier excepción a un formato estándar
    """
    if isinstance(exc, EmailMonitorError):
        return exc.to_dict()
    
    # Para excepciones no manejadas
    return {
        "error": "InternalError",
        "message": "Error interno del servidor",
        "details": {
            "original_error": str(exc),
            "error_type": exc.__class__.__name__
        }
    }

def is_client_error(exc: Exception) -> bool:
    """
    Determina si el error es causado por el cliente (4xx)
    """
    client_errors = (
        AuthenticationError,
        ValidationError,
        InvalidInputError,
        PermissionDeniedError,
        RateLimitExceededError,
        InvalidMessageFormatError
    )
    return isinstance(exc, client_errors)

def is_server_error(exc: Exception) -> bool:
    """
    Determina si el error es del servidor (5xx)
    """
    server_errors = (
        DatabaseError,
        EmailConnectionError,
        WebSocketError,
        ConfigurationError
    )
    return isinstance(exc, server_errors)

def get_http_status_code(exc: Exception) -> int:
    """
    Obtiene el código HTTP correspondiente a la excepción
    """
    if isinstance(exc, (AuthenticationError, TokenExpiredError, InvalidTokenError)):
        return 401
    elif isinstance(exc, PermissionDeniedError):
        return 403
    elif isinstance(exc, (UserNotFoundError, ClientNotFoundError)):
        return 404
    elif isinstance(exc, (ValidationError, InvalidInputError)):
        return 400
    elif isinstance(exc, RateLimitExceededError):
        return 429
    elif isinstance(exc, MaxConnectionsExceededError):
        return 503
    elif is_server_error(exc):
        return 500
    else:
        return 500  # Default para errores no categorizados
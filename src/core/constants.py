# src/core/constants.py
"""
Constantes del sistema Email Monitor
"""

# === VERSIÓN DEL SISTEMA ===
VERSION = "1.0.0"
API_VERSION = "v1"
BUILD_DATE = "2025-06-17"

# === WEBSOCKET PROTOCOL ===
class WSMessageTypes:
    """Tipos de mensajes WebSocket"""
    # Autenticación
    AUTH_REQUIRED = "auth_required"
    LOGIN = "login"
    TOKEN_AUTH = "token_auth"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILED = "auth_failed"
    
    # Tokens
    REFRESH_TOKEN = "refresh_token"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REFRESH_FAILED = "token_refresh_failed"
    
    # Comunicación
    PING = "ping"
    PONG = "pong"
    LOGOUT = "logout"
    
    # Emails
    NEW_EMAIL = "new_email"
    EMAIL_STATUS = "email_status"
    
    # Errores
    ERROR = "error"
    INVALID_MESSAGE = "invalid_message"

class WSCloseCodes:
    """Códigos de cierre WebSocket"""
    NORMAL_CLOSURE = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    INVALID_FRAME_PAYLOAD_DATA = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014

# === LÍMITES DEL SISTEMA ===
class Limits:
    """Límites y cuotas del sistema"""
    # WebSocket
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
    MAX_CONNECTIONS_PER_IP = 5
    MAX_TOTAL_CONNECTIONS = 1000
    
    # Tokens
    MAX_ACTIVE_TOKENS_PER_USER = 10
    TOKEN_CLEANUP_INTERVAL = 3600  # 1 hora en segundos
    
    # Rate Limiting
    DEFAULT_RATE_LIMIT = 100  # requests per minute
    AUTH_RATE_LIMIT = 10     # login attempts per minute
    MESSAGE_RATE_LIMIT = 60  # messages per minute
    
    # Email
    MAX_EMAIL_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_EMAILS_PER_BROADCAST = 50
    
    # Database
    MAX_DB_CONNECTIONS = 20
    DB_QUERY_TIMEOUT = 30
    
    # Logging
    MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_LOG_FILES = 10

# === TIMEOUTS ===
class Timeouts:
    """Timeouts del sistema en segundos"""
    WEBSOCKET_PING = 20
    WEBSOCKET_PONG = 10
    WEBSOCKET_CLOSE = 10
    
    EMAIL_CONNECTION = 30
    EMAIL_READ = 60
    
    DATABASE_QUERY = 30
    DATABASE_CONNECTION = 10
    
    AUTH_TOKEN_EXPIRY = 900  # 15 minutos
    REFRESH_TOKEN_EXPIRY = 604800  # 7 días
    
    USER_LOCKOUT = 1800  # 30 minutos
    RATE_LIMIT_WINDOW = 60  # 1 minuto

# === PERMISOS Y ROLES ===
class Permissions:
    """Permisos del sistema"""
    READ_EMAILS = "read_emails"
    WRITE_EMAILS = "write_emails"
    MANAGE_USERS = "manage_users"
    MANAGE_SYSTEM = "manage_system"
    VIEW_LOGS = "view_logs"
    ADMIN = "admin"

class Roles:
    """Roles predefinidos"""
    GUEST = {
        "name": "guest",
        "permissions": []
    }
    
    USER = {
        "name": "user", 
        "permissions": [Permissions.READ_EMAILS]
    }
    
    MODERATOR = {
        "name": "moderator",
        "permissions": [
            Permissions.READ_EMAILS,
            Permissions.WRITE_EMAILS,
            Permissions.VIEW_LOGS
        ]
    }
    
    ADMIN = {
        "name": "admin",
        "permissions": [
            Permissions.READ_EMAILS,
            Permissions.WRITE_EMAILS,
            Permissions.MANAGE_USERS,
            Permissions.MANAGE_SYSTEM,
            Permissions.VIEW_LOGS,
            Permissions.ADMIN
        ]
    }

# === CONFIGURACIÓN DE EMAIL ===
class EmailTypes:
    """Tipos de contenido de email"""
    TEXT_PLAIN = "text/plain"
    TEXT_HTML = "text/html"
    MULTIPART_MIXED = "multipart/mixed"
    MULTIPART_ALTERNATIVE = "multipart/alternative"
    MULTIPART_RELATED = "multipart/related"

class AttachmentTypes:
    """Tipos de adjuntos permitidos/peligrosos"""
    SAFE_TYPES = {
        "image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp",
        "application/pdf", "text/plain", "text/csv",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip", "application/x-zip-compressed"
    }
    
    DANGEROUS_TYPES = {
        "application/x-executable", "application/x-msdownload",
        "application/x-msdos-program", "application/octet-stream"
    }
    
    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js",
        ".jar", ".app", ".deb", ".rpm", ".dmg", ".pkg", ".msi"
    }

# === CÓDIGOS DE ESTADO ===
class StatusCodes:
    """Códigos de estado del sistema"""
    # Sistema
    SYSTEM_STARTING = "starting"
    SYSTEM_RUNNING = "running"
    SYSTEM_STOPPING = "stopping"
    SYSTEM_ERROR = "error"
    
    # Conexiones
    CLIENT_CONNECTING = "connecting"
    CLIENT_AUTHENTICATING = "authenticating"
    CLIENT_CONNECTED = "connected"
    CLIENT_DISCONNECTED = "disconnected"
    CLIENT_ERROR = "error"
    
    # Email
    EMAIL_MONITORING = "monitoring"
    EMAIL_PROCESSING = "processing"
    EMAIL_ERROR = "error"

# === CONFIGURACIÓN POR DEFECTO ===
class Defaults:
    """Valores por defecto del sistema"""
    # Usuario admin por defecto
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"  # CAMBIAR EN PRODUCCIÓN
    
    # Configuración de servidor
    WEBSOCKET_HOST = "0.0.0.0"
    WEBSOCKET_PORT = 8765
    
    # Email
    EMAIL_SERVER = "imap.gmail.com"
    EMAIL_PORT = 993
    
    # Base de datos
    DATABASE_PATH = "data/users.db"
    
    # Logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"

# === PATRONES Y REGEX ===
class Patterns:
    """Patrones de validación"""
    EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    USERNAME_REGEX = r'^[a-zA-Z0-9_]{3,32}$'
    PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$'
    IP_REGEX = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    IPV6_REGEX = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

# === HEADERS HTTP ===
class HTTPHeaders:
    """Headers HTTP estándar"""
    AUTHORIZATION = "Authorization"
    CONTENT_TYPE = "Content-Type"
    USER_AGENT = "User-Agent"
    X_FORWARDED_FOR = "X-Forwarded-For"
    X_REAL_IP = "X-Real-IP"
    ORIGIN = "Origin"
    REFERER = "Referer"

# === EVENTOS DEL SISTEMA ===
class SystemEvents:
    """Eventos del sistema para logging/auditoría"""
    # Autenticación
    USER_LOGIN_SUCCESS = "user_login_success"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_LOGOUT = "user_logout"
    TOKEN_REFRESH = "token_refresh"
    USER_LOCKED = "user_locked"
    
    # Sistema
    SERVER_START = "server_start"
    SERVER_STOP = "server_stop"
    SERVER_ERROR = "server_error"
    
    # Seguridad
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    IP_BLOCKED = "ip_blocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # Email
    EMAIL_RECEIVED = "email_received"
    EMAIL_PROCESSED = "email_processed"
    EMAIL_ERROR = "email_error"

# === CONFIGURACIÓN DE MONITOREO ===
class Monitoring:
    """Configuración de monitoreo y métricas"""
    METRICS_PORT = 9090
    HEALTH_CHECK_INTERVAL = 30
    STATS_UPDATE_INTERVAL = 60
    
    # Métricas importantes
    METRIC_CONNECTIONS = "email_monitor_connections_total"
    METRIC_MESSAGES = "email_monitor_messages_total"
    METRIC_ERRORS = "email_monitor_errors_total"
    METRIC_EMAILS = "email_monitor_emails_processed_total"
    METRIC_AUTH_ATTEMPTS = "email_monitor_auth_attempts_total"

# === ENVIRONMENT TYPES ===
class Environments:
    """Tipos de entorno"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
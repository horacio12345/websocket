# src/core/config.py
import os
import secrets
from dataclasses import dataclass
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

@dataclass
class DatabaseConfig:
    """Configuración de base de datos"""
    path: str = "data/users.db"
    pool_size: int = 10
    timeout: int = 30

@dataclass 
class JWTConfig:
    """Configuración JWT"""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expiry_minutes: int = 15
    refresh_token_expiry_days: int = 7
    
    def __post_init__(self):
        if not self.secret_key:
            raise ValueError("JWT_SECRET_KEY es requerido")

@dataclass
class EmailConfig:
    """Configuración del servidor de email"""
    server: str
    username: str
    password: str
    port: int = 993
    use_ssl: bool = True
    timeout: int = 30
    check_interval: int = 10  # AGREGADO: intervalo de chequeo en segundos
    
    def __post_init__(self):
        if not all([self.server, self.username, self.password]):
            raise ValueError("Configuración de email incompleta")

@dataclass
class WebSocketConfig:
    """Configuración del servidor WebSocket"""
    host: str = "0.0.0.0"
    port: int = 8765
    ping_interval: int = 20
    ping_timeout: int = 10
    max_size: int = 1024 * 1024  # 1MB
    max_queue: int = 32
    close_timeout: int = 10  # AGREGADO

@dataclass
class SecurityConfig:
    """Configuración de seguridad"""
    max_connections: int = 100
    rate_limit_requests: int = 10
    rate_limit_window_minutes: int = 1
    allowed_ips: List[str] = None
    allowed_origins: List[str] = None
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30
    
    def __post_init__(self):
        if self.allowed_ips is None:
            self.allowed_ips = ["127.0.0.1", "::1"]
        if self.allowed_origins is None:
            self.allowed_origins = ["http://localhost:3000", "https://localhost:3000"]  # AGREGADO HTTPS

@dataclass
class SSLConfig:
    """Configuración SSL/TLS"""
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    
    @property
    def is_enabled(self) -> bool:
        return bool(self.cert_file and self.key_file and 
                   os.path.exists(self.cert_file) and 
                   os.path.exists(self.key_file))

@dataclass
class LoggingConfig:
    """Configuración de logging"""
    level: str = "INFO"
    file_path: str = "logs/email_monitor.log"
    security_log_path: str = "logs/security.log"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    format: str = "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"

class Config:
    """Configuración principal del sistema"""
    
    def __init__(self):
        # Crear directorios necesarios
        os.makedirs("data", exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        self.database = DatabaseConfig(
            path=os.getenv("DATABASE_PATH", "data/users.db"),
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            timeout=int(os.getenv("DB_TIMEOUT", "30"))
        )
        
        self.jwt = JWTConfig(
            secret_key=os.getenv("JWT_SECRET_KEY") or self._generate_secret(),
            algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            access_token_expiry_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES", "15")),
            refresh_token_expiry_days=int(os.getenv("REFRESH_TOKEN_EXPIRY_DAYS", "7"))
        )
        
        self.email = EmailConfig(
            server=os.getenv("EMAIL_SERVER", "imap.gmail.com"),
            username=os.getenv("EMAIL_USERNAME", ""),
            password=os.getenv("EMAIL_PASSWORD", ""),
            port=int(os.getenv("EMAIL_PORT", "993")),
            timeout=int(os.getenv("EMAIL_TIMEOUT", "30")),
            check_interval=int(os.getenv("EMAIL_CHECK_INTERVAL", "10"))
        )
        
        self.websocket = WebSocketConfig(
            host=os.getenv("WEBSOCKET_HOST", "0.0.0.0"),
            port=int(os.getenv("WEBSOCKET_PORT", "8765")),
            ping_interval=int(os.getenv("WS_PING_INTERVAL", "20")),
            ping_timeout=int(os.getenv("WS_PING_TIMEOUT", "10")),
            close_timeout=int(os.getenv("WS_CLOSE_TIMEOUT", "10"))
        )
        
        self.security = SecurityConfig(
            max_connections=int(os.getenv("MAX_CONNECTIONS", "100")),
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "10")),
            rate_limit_window_minutes=int(os.getenv("RATE_LIMIT_WINDOW", "1")),
            allowed_ips=self._parse_list(os.getenv("ALLOWED_IPS", "127.0.0.1,::1")),
            allowed_origins=self._parse_list(os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,https://localhost:3000")),
            max_failed_attempts=int(os.getenv("MAX_FAILED_ATTEMPTS", "5")),
            lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))
        )
        
        self.ssl = SSLConfig(
            cert_file=os.getenv("SSL_CERT_FILE"),
            key_file=os.getenv("SSL_KEY_FILE")
        )
        
        self.logging = LoggingConfig(
            level=os.getenv("LOG_LEVEL", "INFO"),
            file_path=os.getenv("LOG_FILE", "logs/email_monitor.log"),
            security_log_path=os.getenv("SECURITY_LOG_FILE", "logs/security.log")
        )
        
        # Configuración de entorno
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.debug = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
        
        # Validar configuración crítica
        self._validate()
    
    def _generate_secret(self) -> str:
        """Genera una clave secreta si no está configurada"""
        secret = secrets.token_urlsafe(64)
        print(f"⚠️  JWT_SECRET_KEY no configurado. Generado automáticamente: {secret[:16]}...")
        print("   Para producción, configura JWT_SECRET_KEY en .env")
        return secret
    
    def _parse_list(self, value: str) -> List[str]:
        """Parsea una lista separada por comas"""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]
    
    def _validate(self):
        """Valida la configuración"""
        errors = []
        
        # Validar email en producción
        if self.environment == "production":
            if not self.email.username or not self.email.password:
                errors.append("EMAIL_USERNAME y EMAIL_PASSWORD son requeridos en producción")
            
            if not self.ssl.is_enabled:
                print("⚠️  SSL no configurado - recomendado para producción")
            
            if self.jwt.secret_key == "development_secret":
                errors.append("JWT_SECRET_KEY debe ser único en producción")
        
        if errors:
            raise ValueError(f"Errores de configuración: {'; '.join(errors)}")
    
    def is_production(self) -> bool:
        """Verifica si está en entorno de producción"""
        return self.environment == "production"
    
    def is_development(self) -> bool:
        """Verifica si está en entorno de desarrollo"""
        return self.environment == "development"
    
    def get_database_url(self) -> str:
        """Obtiene la URL de la base de datos"""
        return f"sqlite:///{self.database.path}"
    
    def get_websocket_url(self) -> str:
        """Obtiene la URL del WebSocket"""
        protocol = "wss" if self.ssl.is_enabled else "ws"
        return f"{protocol}://{self.websocket.host}:{self.websocket.port}"

# Instancia global de configuración
config = Config()

# Factory function para testing
def create_test_config() -> Config:
    """Crea configuración para tests"""
    os.environ.update({
        "ENVIRONMENT": "testing",
        "DATABASE_PATH": ":memory:",
        "EMAIL_USERNAME": "test@example.com",
        "EMAIL_PASSWORD": "test_password",
        "JWT_SECRET_KEY": "test_secret_key_for_testing_only"
    })
    return Config()
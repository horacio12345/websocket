# src/auth/user_service.py
import bcrypt
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from dataclasses import dataclass

from ..core.config import DatabaseConfig, SecurityConfig
from ..core.exceptions import (
    UserNotFoundError, InvalidCredentialsError, UserAlreadyExistsError,
    UserLockedError, DatabaseError
)
from ..core.constants import Roles, Permissions
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class User:
    """Modelo de usuario"""
    id: int
    username: str
    permissions: List[str]
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None

class UserService:
    """Servicio para gestión de usuarios"""
    
    def __init__(self, db_config: DatabaseConfig, security_config: SecurityConfig):
        self.db_path = db_config.path
        self.security = security_config
        self._init_database()
        self._create_default_admin()
    
    def _init_database(self):
        """Inicializa las tablas de usuarios"""
        # Crear directorio data si no existe
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    token_jti TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_revoked BOOLEAN DEFAULT FALSE,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
        
        logger.info("Base de datos de usuarios inicializada")
    
    def _create_default_admin(self):
        """Crea el usuario admin por defecto si no existe"""
        try:
            # En producción, esto vendría de variables de entorno
            admin_password = "admin123"  
            self.create_user("admin", admin_password, Roles.ADMIN["permissions"])
            logger.info("✅ Usuario admin creado - CAMBIAR contraseña por defecto")
            logger.warning("🚨 SECURITY: Cambiar contraseña por defecto del admin en producción")
        except UserAlreadyExistsError:
            logger.debug("Usuario admin ya existe")
        except Exception as e:
            logger.error(f"Error creando usuario admin: {e}")
    
    def create_user(self, username: str, password: str, permissions: List[str]) -> User:
        """Crea un nuevo usuario"""
        if not username or len(username) < 3:
            raise ValueError("Username debe tener al menos 3 caracteres")
        
        if not password or len(password) < 6:
            raise ValueError("Password debe tener al menos 6 caracteres")
        
        # Hash de la contraseña
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        permissions_str = json.dumps(permissions)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO users (username, password_hash, permissions) 
                       VALUES (?, ?, ?)""",
                    (username, password_hash.decode('utf-8'), permissions_str)
                )
                user_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Usuario creado: {username} (ID: {user_id})")
                
                return User(
                    id=user_id,
                    username=username,
                    permissions=permissions,
                    created_at=datetime.now()
                )
                
        except sqlite3.IntegrityError:
            raise UserAlreadyExistsError(f"Usuario '{username}' ya existe")
        except Exception as e:
            raise DatabaseError(f"Error creando usuario: {e}")
    
    def authenticate_user(self, username: str, password: str, ip_address: str) -> User:
        """
        Autentica un usuario y maneja intentos fallidos
        
        Returns:
            User: Usuario autenticado
            
        Raises:
            UserNotFoundError: Usuario no existe
            InvalidCredentialsError: Contraseña incorrecta
            UserLockedError: Cuenta bloqueada
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Buscar usuario
            user_row = cursor.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = TRUE", 
                (username,)
            ).fetchone()
            
            if not user_row:
                logger.warning(f"Intento de login con usuario inexistente: {username} desde {ip_address}")
                raise UserNotFoundError(f"Usuario '{username}' no encontrado")
            
            # Verificar si está bloqueado
            if user_row['locked_until']:
                locked_until = datetime.fromisoformat(user_row['locked_until'])
                if locked_until > datetime.now():
                    logger.warning(f"Intento de login en cuenta bloqueada: {username} desde {ip_address}")
                    raise UserLockedError(
                        f"Cuenta bloqueada hasta {locked_until.strftime('%Y-%m-%d %H:%M:%S')}",
                        locked_until.isoformat()
                    )
            
            # Verificar contraseña
            if bcrypt.checkpw(password.encode('utf-8'), user_row['password_hash'].encode('utf-8')):
                # Login exitoso - resetear intentos fallidos
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP, locked_until = NULL WHERE id = ?",
                    (user_row['id'],)
                )
                conn.commit()
                
                logger.info(f"Login exitoso: {username} desde {ip_address}")
                
                return User(
                    id=user_row['id'],
                    username=user_row['username'],
                    permissions=json.loads(user_row['permissions']),
                    created_at=datetime.fromisoformat(user_row['created_at']),
                    last_login=datetime.now(),
                    is_active=bool(user_row['is_active']),
                    failed_attempts=0
                )
            else:
                # Login fallido - incrementar contador
                failed_attempts = user_row['failed_attempts'] + 1
                locked_until = None
                
                if failed_attempts >= self.security.max_failed_attempts:
                    locked_until = datetime.now() + timedelta(minutes=self.security.lockout_duration_minutes)
                    logger.warning(f"Cuenta bloqueada por intentos fallidos: {username} desde {ip_address}")
                
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (failed_attempts, locked_until.isoformat() if locked_until else None, user_row['id'])
                )
                conn.commit()
                
                logger.warning(f"Intento de login fallido {failed_attempts}/{self.security.max_failed_attempts}: {username} desde {ip_address}")
                
                if locked_until:
                    raise UserLockedError(
                        f"Cuenta bloqueada por intentos fallidos hasta {locked_until.strftime('%Y-%m-%d %H:%M:%S')}",
                        locked_until.isoformat()
                    )
                else:
                    raise InvalidCredentialsError("Credenciales inválidas")
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Obtiene un usuario por ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                user_row = cursor.execute(
                    "SELECT * FROM users WHERE id = ? AND is_active = TRUE",
                    (user_id,)
                ).fetchone()
                
                if not user_row:
                    return None
                
                return User(
                    id=user_row['id'],
                    username=user_row['username'],
                    permissions=json.loads(user_row['permissions']),
                    created_at=datetime.fromisoformat(user_row['created_at']),
                    last_login=datetime.fromisoformat(user_row['last_login']) if user_row['last_login'] else None,
                    is_active=bool(user_row['is_active']),
                    failed_attempts=user_row['failed_attempts'],
                    locked_until=datetime.fromisoformat(user_row['locked_until']) if user_row['locked_until'] else None
                )
                
        except Exception as e:
            logger.error(f"Error obteniendo usuario {user_id}: {e}")
            return None
    
    def update_user_permissions(self, user_id: str, permissions: List[str]) -> bool:
        """Actualiza los permisos de un usuario"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET permissions = ? WHERE id = ?",
                    (json.dumps(permissions), user_id)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Permisos actualizados para usuario {user_id}: {permissions}")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Error actualizando permisos de usuario {user_id}: {e}")
            return False
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Cambia la contraseña de un usuario"""
        try:
            # Verificar contraseña actual
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                user_row = cursor.execute(
                    "SELECT password_hash FROM users WHERE id = ?",
                    (user_id,)
                ).fetchone()
                
                if not user_row:
                    return False
                
                if not bcrypt.checkpw(old_password.encode('utf-8'), user_row['password_hash'].encode('utf-8')):
                    raise InvalidCredentialsError("Contraseña actual incorrecta")
                
                # Actualizar contraseña
                new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_password_hash.decode('utf-8'), user_id)
                )
                conn.commit()
                
                logger.info(f"Contraseña cambiada para usuario {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error cambiando contraseña de usuario {user_id}: {e}")
            return False
    
    def deactivate_user(self, user_id: str) -> bool:
        """Desactiva un usuario"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET is_active = FALSE WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Usuario {user_id} desactivado")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Error desactivando usuario {user_id}: {e}")
            return False
    
    def unlock_user(self, user_id: str) -> bool:
        """Desbloquea un usuario"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Usuario {user_id} desbloqueado")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Error desbloqueando usuario {user_id}: {e}")
            return False
    
    def get_all_users(self) -> List[User]:
        """Obtiene todos los usuarios activos"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                rows = cursor.execute(
                    "SELECT * FROM users WHERE is_active = TRUE ORDER BY username"
                ).fetchall()
                
                users = []
                for row in rows:
                    users.append(User(
                        id=row['id'],
                        username=row['username'],
                        permissions=json.loads(row['permissions']),
                        created_at=datetime.fromisoformat(row['created_at']),
                        last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                        is_active=bool(row['is_active']),
                        failed_attempts=row['failed_attempts'],
                        locked_until=datetime.fromisoformat(row['locked_until']) if row['locked_until'] else None
                    ))
                
                return users
                
        except Exception as e:
            logger.error(f"Error obteniendo usuarios: {e}")
            return []

# Factory function
def create_user_service(db_config: DatabaseConfig, security_config: SecurityConfig) -> UserService:
    """Factory para crear UserService"""
    return UserService(db_config, security_config)
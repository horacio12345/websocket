# src/auth/jwt_manager.py
import jwt
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from dataclasses import dataclass

from ..core.config import JWTConfig
from ..core.exceptions import AuthenticationError, TokenExpiredError, InvalidTokenError
from ..core.constants import Timeouts

@dataclass
class TokenPayload:
    """Payload de un token JWT"""
    user_id: str
    permissions: List[str]
    token_type: str  # 'access' or 'refresh'
    issued_at: datetime
    expires_at: datetime
    jti: str  # JWT ID único

class JWTManager:
    """Manejador de tokens JWT profesional"""
    
    def __init__(self, config: JWTConfig):
        self.config = config
        self._revoked_tokens: set = set()  # En producción: Redis/DB
        
    def generate_access_token(self, user_id: str, permissions: List[str] = None) -> str:
        """Genera un token de acceso JWT"""
        if permissions is None:
            permissions = ['read_emails']
            
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=self.config.access_token_expiry_minutes)
        
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'type': 'access',
            'iat': now.timestamp(),
            'exp': expires_at.timestamp(),
            'jti': secrets.token_urlsafe(16),
            'iss': 'email-monitor',  # Issuer
            'aud': 'email-monitor-clients'  # Audience
        }
        
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
    
    def generate_refresh_token(self, user_id: str) -> str:
        """Genera un token de renovación de larga duración"""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=self.config.refresh_token_expiry_days)
        
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'iat': now.timestamp(),
            'exp': expires_at.timestamp(),
            'jti': secrets.token_urlsafe(32),
            'iss': 'email-monitor',
            'aud': 'email-monitor-refresh'
        }
        
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)
    
    def validate_token(self, token: str, expected_type: str = 'access') -> TokenPayload:
        """
        Valida y decodifica un token JWT
        
        Raises:
            InvalidTokenError: Token malformado o inválido
            TokenExpiredError: Token expirado
            AuthenticationError: Token revocado o tipo incorrecto
        """
        try:
            # Decodificar token
            payload = jwt.decode(
                token, 
                self.config.secret_key, 
                algorithms=[self.config.algorithm],
                audience=f'email-monitor-{expected_type}' if expected_type == 'refresh' else 'email-monitor-clients',
                issuer='email-monitor'
            )
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token expirado")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Token inválido: {str(e)}")
        
        # Verificar tipo de token
        if payload.get('type') != expected_type:
            raise AuthenticationError(f"Tipo de token incorrecto. Esperado: {expected_type}")
        
        # Verificar si está revocado
        jti = payload.get('jti')
        if jti in self._revoked_tokens:
            raise AuthenticationError("Token revocado")
        
        # Crear objeto TokenPayload
        return TokenPayload(
            user_id=payload['user_id'],
            permissions=payload.get('permissions', []),
            token_type=payload['type'],
            issued_at=datetime.fromtimestamp(payload['iat'], tz=timezone.utc),
            expires_at=datetime.fromtimestamp(payload['exp'], tz=timezone.utc),
            jti=jti
        )
    
    def revoke_token(self, token: str) -> bool:
        """Revoca un token específico"""
        try:
            payload = jwt.decode(
                token, 
                self.config.secret_key, 
                algorithms=[self.config.algorithm],
                options={"verify_exp": False}  # No verificar expiración para revocar
            )
            
            jti = payload.get('jti')
            if jti:
                self._revoked_tokens.add(jti)
                return True
                
        except jwt.InvalidTokenError:
            pass
            
        return False
    
    def revoke_all_user_tokens(self, user_id: str):
        """Revoca todos los tokens de un usuario (TODO: implementar)"""
        # TODO: Implementar cuando tengamos base de datos
        pass
    
    def get_token_info(self, token: str) -> Optional[Dict]:
        """Obtiene información de un token sin validar completamente"""
        try:
            payload = jwt.decode(
                token, 
                self.config.secret_key, 
                algorithms=[self.config.algorithm],
                options={"verify_exp": False, "verify_aud": False}
            )
            
            return {
                'user_id': payload.get('user_id'),
                'type': payload.get('type'),
                'permissions': payload.get('permissions', []),
                'issued_at': datetime.fromtimestamp(payload.get('iat', 0), tz=timezone.utc),
                'expires_at': datetime.fromtimestamp(payload.get('exp', 0), tz=timezone.utc),
                'is_expired': datetime.now(timezone.utc) > datetime.fromtimestamp(payload.get('exp', 0), tz=timezone.utc),
                'jti': payload.get('jti')
            }
            
        except jwt.InvalidTokenError:
            return None
    
    def is_token_expired(self, token: str) -> bool:
        """Verifica si un token está expirado"""
        info = self.get_token_info(token)
        return info['is_expired'] if info else True
    
    def get_remaining_time(self, token: str) -> Optional[timedelta]:
        """Obtiene el tiempo restante de un token"""
        info = self.get_token_info(token)
        if not info:
            return None
            
        remaining = info['expires_at'] - datetime.now(timezone.utc)
        return remaining if remaining.total_seconds() > 0 else timedelta(0)
    
    def cleanup_revoked_tokens(self):
        """Limpia tokens revocados expirados (para optimización de memoria)"""
        # En implementación real, esto se haría en base de datos con TTL
        # Esta es una implementación simplificada
        pass

# Factory function
def create_jwt_manager(config: JWTConfig) -> JWTManager:
    """Factory para crear JWTManager"""
    return JWTManager(config)
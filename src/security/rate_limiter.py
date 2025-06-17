# src/security/rate_limiter.py
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from dataclasses import dataclass

from ..core.config import SecurityConfig
from ..core.exceptions import RateLimitExceededError
from ..core.constants import Timeouts
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class RateLimitRule:
    """Regla de rate limiting"""
    max_requests: int
    window_seconds: int
    name: str

class RateLimiter:
    """Sistema de rate limiting por IP y endpoint"""
    
    def __init__(self, security_config: SecurityConfig):
        self.config = security_config
        
        # Estructura: {ip: {endpoint: deque of timestamps}}
        self._requests: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        
        # Reglas predefinidas
        self.rules = {
            "connection": RateLimitRule(5, 60, "Conexiones"),
            "login": RateLimitRule(5, 300, "Login attempts"),
            "message": RateLimitRule(60, 60, "Mensajes"),
            "token_refresh": RateLimitRule(10, 300, "Token refresh"),
            "default": RateLimitRule(
                self.config.rate_limit_requests, 
                self.config.rate_limit_window_minutes * 60, 
                "Default"
            )
        }
        
        logger.info(f"Rate limiter inicializado con {len(self.rules)} reglas")
    
    def check_limit(self, identifier: str, endpoint: str = "default") -> bool:
        """
        Verifica si el identificador (IP/usuario) puede hacer una request
        
        Args:
            identifier: IP address o user ID
            endpoint: Tipo de endpoint/acción
            
        Returns:
            bool: True si está permitido, False si excede el límite
        """
        rule = self.rules.get(endpoint, self.rules["default"])
        now = time.time()
        window_start = now - rule.window_seconds
        
        # Obtener o crear la queue para este identifier+endpoint
        request_queue = self._requests[identifier][endpoint]
        
        # Limpiar requests antiguos
        while request_queue and request_queue[0] <= window_start:
            request_queue.popleft()
        
        # Verificar límite
        if len(request_queue) >= rule.max_requests:
            logger.warning(f"Rate limit excedido: {identifier} en {endpoint} ({len(request_queue)}/{rule.max_requests})")
            return False
        
        # Registrar esta request
        request_queue.append(now)
        return True
    
    def add_request(self, identifier: str, endpoint: str = "default"):
        """
        Registra una request (sin verificar límites)
        Útil para tracking sin enforcement
        """
        now = time.time()
        self._requests[identifier][endpoint].append(now)
    
    def get_remaining_requests(self, identifier: str, endpoint: str = "default") -> int:
        """Obtiene el número de requests restantes en la ventana actual"""
        rule = self.rules.get(endpoint, self.rules["default"])
        now = time.time()
        window_start = now - rule.window_seconds
        
        request_queue = self._requests[identifier][endpoint]
        
        # Limpiar requests antiguos
        while request_queue and request_queue[0] <= window_start:
            request_queue.popleft()
        
        return max(0, rule.max_requests - len(request_queue))
    
    def get_reset_time(self, identifier: str, endpoint: str = "default") -> float:
        """Obtiene el timestamp cuando se resetea el límite"""
        rule = self.rules.get(endpoint, self.rules["default"])
        request_queue = self._requests[identifier][endpoint]
        
        if not request_queue:
            return time.time()
        
        # El reset será cuando expire la request más antigua
        return request_queue[0] + rule.window_seconds
    
    def is_blocked(self, identifier: str, endpoint: str = "default") -> bool:
        """Verifica si un identificador está bloqueado"""
        return not self.check_limit(identifier, endpoint)
    
    def block_identifier(self, identifier: str, duration_seconds: int = 3600):
        """
        Bloquea un identificador por un tiempo específico
        (Implementación simple: llena su queue)
        """
        rule = self.rules.get("default")
        now = time.time()
        
        # Llenar la queue con requests ficticias
        request_queue = self._requests[identifier]["blocked"]
        request_queue.clear()
        
        # Crear requests ficticias que expiren después de duration_seconds
        block_until = now + duration_seconds
        for i in range(rule.max_requests):
            request_queue.append(block_until - rule.window_seconds + 1)
        
        logger.warning(f"Identificador bloqueado: {identifier} por {duration_seconds} segundos")
    
    def unblock_identifier(self, identifier: str):
        """Desbloquea un identificador"""
        if identifier in self._requests:
            del self._requests[identifier]
            logger.info(f"Identificador desbloqueado: {identifier}")
    
    def cleanup_expired(self):
        """Limpia entradas expiradas para liberar memoria"""
        now = time.time()
        cleaned_ips = 0
        cleaned_endpoints = 0
        
        for ip in list(self._requests.keys()):
            endpoints_to_remove = []
            
            for endpoint in list(self._requests[ip].keys()):
                rule = self.rules.get(endpoint, self.rules["default"])
                window_start = now - rule.window_seconds
                request_queue = self._requests[ip][endpoint]
                
                # Limpiar requests antiguos
                while request_queue and request_queue[0] <= window_start:
                    request_queue.popleft()
                
                # Si la queue está vacía, marcar endpoint para eliminación
                if not request_queue:
                    endpoints_to_remove.append(endpoint)
            
            # Eliminar endpoints vacíos
            for endpoint in endpoints_to_remove:
                del self._requests[ip][endpoint]
                cleaned_endpoints += 1
            
            # Si no quedan endpoints para esta IP, eliminar la IP
            if not self._requests[ip]:
                del self._requests[ip]
                cleaned_ips += 1
        
        if cleaned_ips > 0 or cleaned_endpoints > 0:
            logger.debug(f"Rate limiter cleanup: {cleaned_ips} IPs, {cleaned_endpoints} endpoints eliminados")
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas del rate limiter"""
        total_ips = len(self._requests)
        total_endpoints = sum(len(endpoints) for endpoints in self._requests.values())
        total_requests = sum(
            len(queue) 
            for endpoints in self._requests.values() 
            for queue in endpoints.values()
        )
        
        # Top IPs por número de requests
        ip_stats = []
        for ip, endpoints in self._requests.items():
            total_ip_requests = sum(len(queue) for queue in endpoints.values())
            ip_stats.append((ip, total_ip_requests))
        
        ip_stats.sort(key=lambda x: x[1], reverse=True)
        top_ips = ip_stats[:10]
        
        return {
            "total_tracked_ips": total_ips,
            "total_endpoints": total_endpoints,
            "total_active_requests": total_requests,
            "rules": {name: f"{rule.max_requests}/{rule.window_seconds}s" for name, rule in self.rules.items()},
            "top_ips": [{"ip": ip, "requests": count} for ip, count in top_ips]
        }
    
    def add_custom_rule(self, endpoint: str, max_requests: int, window_seconds: int):
        """Agrega una regla personalizada de rate limiting"""
        self.rules[endpoint] = RateLimitRule(max_requests, window_seconds, f"Custom {endpoint}")
        logger.info(f"Regla personalizada agregada: {endpoint} -> {max_requests}/{window_seconds}s")
    
    def remove_rule(self, endpoint: str):
        """Elimina una regla de rate limiting"""
        if endpoint in self.rules and endpoint != "default":
            del self.rules[endpoint]
            logger.info(f"Regla eliminada: {endpoint}")
    
    def get_violations(self, minutes: int = 60) -> List[Dict]:
        """Obtiene violaciones recientes de rate limiting"""
        # En una implementación real, esto vendría de logs estructurados
        # Por ahora, retornamos IPs que están cerca del límite
        violations = []
        now = time.time()
        
        for ip, endpoints in self._requests.items():
            for endpoint, request_queue in endpoints.items():
                rule = self.rules.get(endpoint, self.rules["default"])
                window_start = now - rule.window_seconds
                
                # Contar requests en la ventana
                recent_requests = sum(1 for req_time in request_queue if req_time > window_start)
                
                # Si está cerca del límite (>80%), reportar
                if recent_requests > (rule.max_requests * 0.8):
                    violations.append({
                        "ip": ip,
                        "endpoint": endpoint,
                        "requests": recent_requests,
                        "limit": rule.max_requests,
                        "window_seconds": rule.window_seconds,
                        "percentage": (recent_requests / rule.max_requests) * 100
                    })
        
        return sorted(violations, key=lambda x: x["percentage"], reverse=True)

# Factory function
def create_rate_limiter(security_config: SecurityConfig) -> RateLimiter:
    """Factory para crear RateLimiter"""
    return RateLimiter(security_config)
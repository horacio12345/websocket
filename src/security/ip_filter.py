# src/security/ip_filter.py
import ipaddress
import time
from typing import Set, List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

from ..core.config import SecurityConfig
from ..core.exceptions import IPBlockedError, SecurityError
from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class IPBlockEntry:
    """Entrada de IP bloqueada"""
    ip: str
    blocked_at: datetime
    expires_at: Optional[datetime]
    reason: str
    block_count: int = 1

class IPFilter:
    """Filtro de IPs con whitelist, blacklist y bloqueos temporales"""
    
    def __init__(self, security_config: SecurityConfig):
        self.config = security_config
        
        # Whitelist - IPs siempre permitidas
        self.whitelist: Set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        
        # Blacklist permanente - IPs siempre bloqueadas
        self.permanent_blacklist: Set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        
        # Bloqueos temporales
        self.temporary_blocks: Dict[str, IPBlockEntry] = {}
        
        # Estadísticas
        self.connection_attempts: Dict[str, List[float]] = {}
        
        # Inicializar con IPs permitidas de configuración
        self._init_whitelist()
        
        logger.info(f"IP Filter inicializado - Whitelist: {len(self.whitelist)} rangos")
    
    def _init_whitelist(self):
        """Inicializa la whitelist con IPs de configuración"""
        for ip_str in self.config.allowed_ips:
            try:
                # Soporta tanto IPs individuales como rangos CIDR
                if '/' not in ip_str:
                    # IP individual - convertir a red /32 o /128
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.version == 4:
                        network = ipaddress.IPv4Network(f"{ip_str}/32")
                    else:
                        network = ipaddress.IPv6Network(f"{ip_str}/128")
                else:
                    # Rango CIDR
                    network = ipaddress.ip_network(ip_str, strict=False)
                
                self.whitelist.add(network)
                logger.debug(f"IP/Rango agregado a whitelist: {network}")
                
            except ValueError as e:
                logger.error(f"IP inválida en whitelist: {ip_str} - {e}")
    
    def is_allowed(self, client_ip: str) -> bool:
        """
        Verifica si una IP está permitida
        
        Returns:
            bool: True si está permitida, False si está bloqueada
            
        Raises:
            IPBlockedError: Si la IP está bloqueada
        """
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            
            # 1. Verificar whitelist primero (siempre permitir)
            if self._is_in_whitelist(ip_obj):
                return True
            
            # 2. Verificar blacklist permanente
            if self._is_in_permanent_blacklist(ip_obj):
                logger.warning(f"IP en blacklist permanente: {client_ip}")
                raise IPBlockedError(f"IP {client_ip} está permanentemente bloqueada")
            
            # 3. Verificar bloqueos temporales
            if self._is_temporarily_blocked(client_ip):
                block_entry = self.temporary_blocks[client_ip]
                logger.warning(f"IP temporalmente bloqueada: {client_ip} - {block_entry.reason}")
                raise IPBlockedError(
                    f"IP {client_ip} bloqueada hasta {block_entry.expires_at.strftime('%Y-%m-%d %H:%M:%S')} - {block_entry.reason}"
                )
            
            # 4. Registrar intento de conexión para análisis
            self._record_connection_attempt(client_ip)
            
            return True
            
        except ValueError:
            # IP malformada
            logger.error(f"IP malformada recibida: {client_ip}")
            raise SecurityError(f"Formato de IP inválido: {client_ip}")
    
    def _is_in_whitelist(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Verifica si la IP está en la whitelist"""
        for network in self.whitelist:
            if ip_obj in network:
                return True
        return False
    
    def _is_in_permanent_blacklist(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Verifica si la IP está en la blacklist permanente"""
        for network in self.permanent_blacklist:
            if ip_obj in network:
                return True
        return False
    
    def _is_temporarily_blocked(self, client_ip: str) -> bool:
        """Verifica si la IP está temporalmente bloqueada"""
        if client_ip not in self.temporary_blocks:
            return False
        
        block_entry = self.temporary_blocks[client_ip]
        
        # Si no tiene expiración, es permanente
        if block_entry.expires_at is None:
            return True
        
        # Verificar si ya expiró
        if datetime.now() > block_entry.expires_at:
            # Remover bloqueo expirado
            del self.temporary_blocks[client_ip]
            logger.info(f"Bloqueo temporal expirado removido: {client_ip}")
            return False
        
        return True
    
    def _record_connection_attempt(self, client_ip: str):
        """Registra un intento de conexión para análisis"""
        now = time.time()
        
        if client_ip not in self.connection_attempts:
            self.connection_attempts[client_ip] = []
        
        self.connection_attempts[client_ip].append(now)
        
        # Mantener solo los últimos 100 intentos por IP
        if len(self.connection_attempts[client_ip]) > 100:
            self.connection_attempts[client_ip] = self.connection_attempts[client_ip][-100:]
    
    def block_ip_temporary(self, ip: str, duration_minutes: int, reason: str):
        """Bloquea una IP temporalmente"""
        expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        
        # Si ya está bloqueada, incrementar contador
        if ip in self.temporary_blocks:
            self.temporary_blocks[ip].block_count += 1
            self.temporary_blocks[ip].expires_at = expires_at
            self.temporary_blocks[ip].reason = reason
        else:
            self.temporary_blocks[ip] = IPBlockEntry(
                ip=ip,
                blocked_at=datetime.now(),
                expires_at=expires_at,
                reason=reason
            )
        
        logger.warning(f"IP bloqueada temporalmente: {ip} por {duration_minutes} min - {reason}")
    
    def block_ip_permanent(self, ip_or_range: str, reason: str):
        """Agrega una IP o rango a la blacklist permanente"""
        try:
            if '/' not in ip_or_range:
                # IP individual
                ip_obj = ipaddress.ip_address(ip_or_range)
                if ip_obj.version == 4:
                    network = ipaddress.IPv4Network(f"{ip_or_range}/32")
                else:
                    network = ipaddress.IPv6Network(f"{ip_or_range}/128")
            else:
                # Rango CIDR
                network = ipaddress.ip_network(ip_or_range, strict=False)
            
            self.permanent_blacklist.add(network)
            logger.warning(f"IP/Rango agregado a blacklist permanente: {network} - {reason}")
            
        except ValueError as e:
            logger.error(f"Error agregando a blacklist: {ip_or_range} - {e}")
            raise SecurityError(f"IP/Rango inválido: {ip_or_range}")
    
    def unblock_ip(self, ip: str):
        """Desbloquea una IP temporalmente bloqueada"""
        if ip in self.temporary_blocks:
            del self.temporary_blocks[ip]
            logger.info(f"IP desbloqueada: {ip}")
        else:
            logger.warning(f"Intento de desbloquear IP no bloqueada: {ip}")
    
    def add_to_whitelist(self, ip_or_range: str):
        """Agrega una IP o rango a la whitelist"""
        try:
            if '/' not in ip_or_range:
                # IP individual
                ip_obj = ipaddress.ip_address(ip_or_range)
                if ip_obj.version == 4:
                    network = ipaddress.IPv4Network(f"{ip_or_range}/32")
                else:
                    network = ipaddress.IPv6Network(f"{ip_or_range}/128")
            else:
                # Rango CIDR
                network = ipaddress.ip_network(ip_or_range, strict=False)
            
            self.whitelist.add(network)
            logger.info(f"IP/Rango agregado a whitelist: {network}")
            
        except ValueError as e:
            logger.error(f"Error agregando a whitelist: {ip_or_range} - {e}")
            raise SecurityError(f"IP/Rango inválido: {ip_or_range}")
    
    def remove_from_whitelist(self, ip_or_range: str):
        """Remueve una IP o rango de la whitelist"""
        try:
            if '/' not in ip_or_range:
                ip_obj = ipaddress.ip_address(ip_or_range)
                if ip_obj.version == 4:
                    network = ipaddress.IPv4Network(f"{ip_or_range}/32")
                else:
                    network = ipaddress.IPv6Network(f"{ip_or_range}/128")
            else:
                network = ipaddress.ip_network(ip_or_range, strict=False)
            
            if network in self.whitelist:
                self.whitelist.remove(network)
                logger.info(f"IP/Rango removido de whitelist: {network}")
            else:
                logger.warning(f"IP/Rango no estaba en whitelist: {network}")
                
        except ValueError as e:
            logger.error(f"Error removiendo de whitelist: {ip_or_range} - {e}")
    
    def get_suspicious_ips(self, time_window_minutes: int = 60, min_connections: int = 20) -> List[Dict]:
        """Obtiene IPs con actividad sospechosa"""
        suspicious = []
        now = time.time()
        window_start = now - (time_window_minutes * 60)
        
        for ip, attempts in self.connection_attempts.items():
            # Contar intentos en la ventana de tiempo
            recent_attempts = [t for t in attempts if t > window_start]
            
            if len(recent_attempts) >= min_connections:
                suspicious.append({
                    "ip": ip,
                    "connections": len(recent_attempts),
                    "time_window_minutes": time_window_minutes,
                    "rate_per_minute": len(recent_attempts) / time_window_minutes,
                    "first_seen": datetime.fromtimestamp(min(recent_attempts)),
                    "last_seen": datetime.fromtimestamp(max(recent_attempts)),
                    "is_whitelisted": self._is_in_whitelist(ipaddress.ip_address(ip)),
                    "is_blocked": ip in self.temporary_blocks
                })
        
        return sorted(suspicious, key=lambda x: x["connections"], reverse=True)
    
    def cleanup_expired_blocks(self):
        """Limpia bloqueos temporales expirados"""
        now = datetime.now()
        expired_ips = []
        
        for ip, block_entry in self.temporary_blocks.items():
            if block_entry.expires_at and now > block_entry.expires_at:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.temporary_blocks[ip]
            logger.debug(f"Bloqueo temporal expirado removido: {ip}")
        
        # Limpiar intentos de conexión antiguos (más de 24 horas)
        old_threshold = time.time() - (24 * 60 * 60)
        cleaned_ips = 0
        
        for ip in list(self.connection_attempts.keys()):
            # Filtrar intentos antiguos
            self.connection_attempts[ip] = [
                t for t in self.connection_attempts[ip] if t > old_threshold
            ]
            
            # Si no quedan intentos recientes, remover la entrada
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
                cleaned_ips += 1
        
        if cleaned_ips > 0:
            logger.debug(f"Limpieza de IP filter: {len(expired_ips)} bloqueos expirados, {cleaned_ips} IPs sin actividad reciente")
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas del filtro de IPs"""
        return {
            "whitelist_entries": len(self.whitelist),
            "permanent_blacklist_entries": len(self.permanent_blacklist),
            "temporary_blocks": len(self.temporary_blocks),
            "tracked_ips": len(self.connection_attempts),
            "whitelist_networks": [str(net) for net in self.whitelist],
            "blacklist_networks": [str(net) for net in self.permanent_blacklist],
            "active_blocks": [
                {
                    "ip": ip,
                    "blocked_at": entry.blocked_at.isoformat(),
                    "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
                    "reason": entry.reason,
                    "block_count": entry.block_count
                }
                for ip, entry in self.temporary_blocks.items()
            ]
        }

# Factory function
def create_ip_filter(security_config: SecurityConfig) -> IPFilter:
    """Factory para crear IPFilter"""
    return IPFilter(security_config)
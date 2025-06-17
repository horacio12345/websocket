# src/websocket/server.py
import asyncio
import websockets
import json
import ssl
from datetime import datetime
from typing import Dict, Set, Optional
from dataclasses import dataclass

from ..core.config import Config
from ..core.constants import WSMessageTypes, WSCloseCodes
from ..core.exceptions import (
    AuthenticationError, WebSocketError, RateLimitExceededError,
    MaxConnectionsExceededError, InvalidMessageFormatError
)
from ..auth import JWTManager, UserService, create_jwt_manager, create_user_service
from ..security import RateLimiter, IPFilter, create_rate_limiter, create_ip_filter
from ..utils.logger import get_logger, get_security_logger

logger = get_logger(__name__)
security_logger = get_security_logger()

@dataclass
class ClientConnection:
    """Información de conexión de cliente"""
    websocket: websockets.WebSocketServerProtocol
    user_id: str
    username: str
    permissions: list
    ip_address: str
    connected_at: datetime
    last_activity: datetime

class WebSocketServer:
    """Servidor WebSocket seguro con autenticación JWT"""
    
    def __init__(self, config: Config):
        self.config = config
        self.clients: Dict[websockets.WebSocketServerProtocol, ClientConnection] = {}
        self.running = False
        
        # Inicializar servicios
        self.jwt_manager = create_jwt_manager(config.jwt)
        self.user_service = create_user_service(config.database, config.security)
        self.rate_limiter = create_rate_limiter(config.security)
        self.ip_filter = create_ip_filter(config.security)
        
        logger.info("WebSocket Server inicializado")
    
    async def start(self):
        """Inicia el servidor WebSocket"""
        self.running = True
        
        # Configurar SSL si está habilitado
        ssl_context = None
        if self.config.ssl.is_enabled:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
                self.config.ssl.cert_file,
                self.config.ssl.key_file
            )
            logger.info("🔒 SSL habilitado")
        
        # Iniciar servidor
        host = self.config.websocket.host
        port = self.config.websocket.port
        
        logger.info(f"🚀 Iniciando WebSocket Server en {host}:{port}")
        
        try:
            async with websockets.serve(
                self.handle_client,
                host,
                port,
                ssl=ssl_context,
                ping_interval=self.config.websocket.ping_interval,
                ping_timeout=self.config.websocket.ping_timeout,
                close_timeout=self.config.websocket.close_timeout,
                max_size=self.config.websocket.max_size,
                max_queue=self.config.websocket.max_queue
            ):
                logger.info(f"✅ WebSocket Server activo en {self.config.get_websocket_url()}")
                await asyncio.Future()  # Run forever
                
        except Exception as e:
            logger.error(f"Error iniciando servidor WebSocket: {e}")
            raise
    
    async def stop(self):
        """Detiene el servidor WebSocket"""
        self.running = False
        
        # Cerrar todas las conexiones activas
        if self.clients:
            logger.info(f"Cerrando {len(self.clients)} conexiones activas...")
            close_tasks = []
            
            for websocket in list(self.clients.keys()):
                close_tasks.append(self._close_client(
                    websocket, 
                    WSCloseCodes.SERVICE_RESTART, 
                    "Server shutdown"
                ))
            
            await asyncio.gather(*close_tasks, return_exceptions=True)
        
        logger.info("🛑 WebSocket Server detenido")
    
    async def handle_client(self, websocket):
        """Maneja una nueva conexión de cliente"""
        client_ip = websocket.remote_address[0]
        
        try:
            # 1. Verificar IP
            self.ip_filter.is_allowed(client_ip)
            
            # 2. Rate limiting de conexiones
            if not self.rate_limiter.check_limit(client_ip, "connection"):
                await self._send_error(websocket, "Rate limit de conexiones excedido")
                await websocket.close(WSCloseCodes.POLICY_VIOLATION, "Rate limit exceeded")
                return
            
            # 3. Verificar límite de conexiones totales
            if len(self.clients) >= self.config.security.max_connections:
                await self._send_error(websocket, "Máximo de conexiones alcanzado")
                await websocket.close(WSCloseCodes.TRY_AGAIN_LATER, "Too many connections")
                raise MaxConnectionsExceededError("Límite de conexiones excedido")
            
            # 4. Autenticar cliente
            client = await self._authenticate_client(websocket, client_ip)
            if not client:
                return  # Autenticación falló
            
            # 5. Registrar cliente
            self.clients[websocket] = client
            security_logger.auth_success(client.username, client_ip)
            logger.info(f"Cliente conectado: {client.username} ({client_ip}) - Total: {len(self.clients)}")
            
            # 6. Manejar mensajes del cliente
            await self._handle_client_messages(websocket, client)
            
        except Exception as e:
            logger.error(f"Error manejando cliente {client_ip}: {e}")
            security_logger.suspicious_activity("connection_error", {
                "ip": client_ip,
                "error": str(e)
            })
        finally:
            # Limpiar al desconectar
            if websocket in self.clients:
                client = self.clients.pop(websocket)
                logger.info(f"Cliente desconectado: {client.username} ({client.ip_address}) - Total: {len(self.clients)}")
    
    async def _authenticate_client(self, websocket, client_ip: str) -> Optional[ClientConnection]:
        """Autentica un cliente WebSocket"""
        try:
            # Solicitar autenticación
            await self._send_message(websocket, {
                "type": WSMessageTypes.AUTH_REQUIRED,
                "message": "Autenticación requerida"
            })
            
            # Esperar respuesta de autenticación con timeout
            try:
                auth_message = await asyncio.wait_for(websocket.recv(), timeout=30)
                auth_data = json.loads(auth_message)
            except asyncio.TimeoutError:
                await self._send_error(websocket, "Timeout de autenticación")
                await websocket.close(WSCloseCodes.POLICY_VIOLATION, "Auth timeout")
                return None
            except json.JSONDecodeError:
                await self._send_error(websocket, "Formato de mensaje inválido")
                await websocket.close(WSCloseCodes.INVALID_FRAME_PAYLOAD_DATA, "Invalid JSON")
                return None
            
            # Verificar tipo de autenticación
            auth_type = auth_data.get("type")
            
            if auth_type == WSMessageTypes.LOGIN:
                # Autenticación con usuario/contraseña
                return await self._authenticate_with_credentials(websocket, auth_data, client_ip)
            
            elif auth_type == WSMessageTypes.TOKEN_AUTH:
                # Autenticación con token JWT
                return await self._authenticate_with_token(websocket, auth_data, client_ip)
            
            else:
                await self._send_error(websocket, "Tipo de autenticación no soportado")
                await websocket.close(WSCloseCodes.POLICY_VIOLATION, "Invalid auth type")
                return None
                
        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            await self._send_error(websocket, "Error interno de autenticación")
            return None
    
    async def _authenticate_with_credentials(self, websocket, auth_data: dict, client_ip: str) -> Optional[ClientConnection]:
        """Autentica con usuario y contraseña"""
        username = auth_data.get("username", "").strip()
        password = auth_data.get("password", "")
        
        if not username or not password:
            await self._send_auth_failed(websocket, "Username y password requeridos")
            return None
        
        # Rate limiting de login
        if not self.rate_limiter.check_limit(client_ip, "login"):
            await self._send_auth_failed(websocket, "Demasiados intentos de login")
            return None
        
        try:
            # Autenticar usuario
            user = self.user_service.authenticate_user(username, password, client_ip)
            
            # Generar tokens JWT
            access_token = self.jwt_manager.generate_access_token(
                str(user.id), 
                user.permissions
            )
            refresh_token = self.jwt_manager.generate_refresh_token(str(user.id))
            
            # Enviar respuesta exitosa
            await self._send_message(websocket, {
                "type": WSMessageTypes.AUTH_SUCCESS,
                "message": "Autenticación exitosa",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "permissions": user.permissions
                },
                "access_token": access_token,
                "refresh_token": refresh_token
            })
            
            return ClientConnection(
                websocket=websocket,
                user_id=str(user.id),
                username=user.username,
                permissions=user.permissions,
                ip_address=client_ip,
                connected_at=datetime.now(),
                last_activity=datetime.now()
            )
            
        except Exception as e:
            security_logger.auth_failure(username, client_ip, str(e))
            await self._send_auth_failed(websocket, "Credenciales inválidas")
            return None
    
    async def _authenticate_with_token(self, websocket, auth_data: dict, client_ip: str) -> Optional[ClientConnection]:
        """Autentica con token JWT"""
        token = auth_data.get("token", "")
        
        if not token:
            await self._send_auth_failed(websocket, "Token requerido")
            return None
        
        try:
            # Validar token
            token_payload = self.jwt_manager.validate_token(token, "access")
            
            # Obtener usuario
            user = self.user_service.get_user_by_id(token_payload.user_id)
            if not user:
                await self._send_auth_failed(websocket, "Usuario no encontrado")
                return None
            
            # Enviar confirmación
            await self._send_message(websocket, {
                "type": WSMessageTypes.AUTH_SUCCESS,
                "message": "Token válido",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "permissions": user.permissions
                }
            })
            
            return ClientConnection(
                websocket=websocket,
                user_id=str(user.id),
                username=user.username,
                permissions=user.permissions,
                ip_address=client_ip,
                connected_at=datetime.now(),
                last_activity=datetime.now()
            )
            
        except Exception as e:
            security_logger.auth_failure("token_auth", client_ip, str(e))
            await self._send_auth_failed(websocket, "Token inválido")
            return None
    
    async def _handle_client_messages(self, websocket, client: ClientConnection):
        """Maneja los mensajes de un cliente autenticado"""
        try:
            async for message in websocket:
                # Rate limiting de mensajes
                if not self.rate_limiter.check_limit(client.ip_address, "message"):
                    await self._send_error(websocket, "Rate limit de mensajes excedido")
                    break
                
                # Actualizar última actividad
                client.last_activity = datetime.now()
                
                try:
                    data = json.loads(message)
                    await self._process_message(websocket, client, data)
                    
                except json.JSONDecodeError:
                    await self._send_error(websocket, "Formato JSON inválido")
                except Exception as e:
                    logger.error(f"Error procesando mensaje de {client.username}: {e}")
                    await self._send_error(websocket, "Error procesando mensaje")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.debug(f"Conexión cerrada: {client.username}")
        except Exception as e:
            logger.error(f"Error en manejo de mensajes para {client.username}: {e}")
    
    async def _process_message(self, websocket, client: ClientConnection, data: dict):
        """Procesa un mensaje de cliente autenticado"""
        message_type = data.get("type")
        
        if message_type == WSMessageTypes.PING:
            await self._send_message(websocket, {"type": WSMessageTypes.PONG})
            
        elif message_type == WSMessageTypes.REFRESH_TOKEN:
            await self._handle_token_refresh(websocket, client, data)
            
        elif message_type == WSMessageTypes.LOGOUT:
            await self._handle_logout(websocket, client)
            
        else:
            await self._send_error(websocket, f"Tipo de mensaje no soportado: {message_type}")
    
    async def _handle_token_refresh(self, websocket, client: ClientConnection, data: dict):
        """Maneja la renovación de tokens"""
        refresh_token = data.get("refresh_token", "")
        
        if not refresh_token:
            await self._send_error(websocket, "Refresh token requerido")
            return
        
        try:
            # Validar refresh token
            token_payload = self.jwt_manager.validate_token(refresh_token, "refresh")
            
            if token_payload.user_id != client.user_id:
                await self._send_error(websocket, "Refresh token no corresponde al usuario")
                return
            
            # Generar nuevo access token
            user = self.user_service.get_user_by_id(client.user_id)
            new_access_token = self.jwt_manager.generate_access_token(
                str(user.id),
                user.permissions
            )
            
            await self._send_message(websocket, {
                "type": WSMessageTypes.TOKEN_REFRESHED,
                "access_token": new_access_token
            })
            
        except Exception as e:
            logger.warning(f"Error renovando token para {client.username}: {e}")
            await self._send_message(websocket, {
                "type": WSMessageTypes.TOKEN_REFRESH_FAILED,
                "message": "No se pudo renovar el token"
            })
    
    async def _handle_logout(self, websocket, client: ClientConnection):
        """Maneja el logout de un cliente"""
        logger.info(f"Logout solicitado: {client.username}")
        await websocket.close(WSCloseCodes.NORMAL_CLOSURE, "Logout")
    
    async def broadcast_to_all(self, message: dict, permission_required: str = None):
        """Envía un mensaje a todos los clientes conectados"""
        if not self.clients:
            return
        
        # Filtrar clientes por permisos si se especifica
        target_clients = []
        for client in self.clients.values():
            if permission_required is None or permission_required in client.permissions:
                target_clients.append(client)
        
        if not target_clients:
            logger.debug(f"No hay clientes con permiso '{permission_required}' para broadcast")
            return
        
        logger.info(f"Broadcasting a {len(target_clients)} clientes")
        
        # Enviar mensaje a todos los clientes objetivo
        tasks = []
        for client in target_clients:
            tasks.append(self._send_message(client.websocket, message))
        
        # Ejecutar envíos en paralelo
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Contar éxitos y fallos
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        error_count = len(results) - success_count
        
        if error_count > 0:
            logger.warning(f"Broadcast: {success_count} éxitos, {error_count} errores")
        else:
            logger.debug(f"Broadcast exitoso a {success_count} clientes")
    
    async def _send_message(self, websocket, message: dict):
        """Envía un mensaje JSON a un websocket"""
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            # Conexión ya cerrada
            pass
        except Exception as e:
            logger.error(f"Error enviando mensaje: {e}")
            raise
    
    async def _send_error(self, websocket, error_message: str):
        """Envía un mensaje de error"""
        await self._send_message(websocket, {
            "type": WSMessageTypes.ERROR,
            "message": error_message
        })
    
    async def _send_auth_failed(self, websocket, reason: str):
        """Envía mensaje de autenticación fallida"""
        await self._send_message(websocket, {
            "type": WSMessageTypes.AUTH_FAILED,
            "message": reason
        })
        await websocket.close(WSCloseCodes.POLICY_VIOLATION, "Authentication failed")
    
    async def _close_client(self, websocket, code: int, reason: str):
        """Cierra la conexión de un cliente"""
        try:
            await websocket.close(code, reason)
        except Exception as e:
            logger.debug(f"Error cerrando cliente: {e}")
    
    def get_stats(self) -> dict:
        """Obtiene estadísticas del servidor"""
        return {
            "total_connections": len(self.clients),
            "connected_users": [
                {
                    "username": client.username,
                    "ip": client.ip_address,
                    "connected_at": client.connected_at.isoformat(),
                    "last_activity": client.last_activity.isoformat()
                }
                for client in self.clients.values()
            ],
            "rate_limiter_stats": self.rate_limiter.get_stats(),
            "ip_filter_stats": self.ip_filter.get_stats()
        }

# Factory function
def create_websocket_server(config: Config) -> WebSocketServer:
    """Factory para crear WebSocketServer"""
    return WebSocketServer(config)
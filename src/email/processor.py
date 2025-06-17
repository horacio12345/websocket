# src/email/processor.py
import email
import hashlib
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from email.message import EmailMessage

from ..core.constants import AttachmentTypes, Limits
from ..core.exceptions import EmailParsingError, AttachmentTooLargeError, UnsafeAttachmentError
from ..utils.logger import get_logger, get_security_logger

logger = get_logger(__name__)
security_logger = get_security_logger()

@dataclass
class AttachmentData:
    """Datos de un adjunto"""
    filename: str
    content_type: str
    size: int
    data: Optional[bytes] = None
    hash: Optional[str] = None
    is_safe: bool = True
    
@dataclass
class EmailData:
    """Datos procesados de un email"""
    id: str
    subject: str
    sender: str
    to: str
    cc: str
    date: str
    timestamp: float
    text_content: str = ""
    html_content: str = ""
    attachments: List[AttachmentData] = field(default_factory=list)
    images: List[AttachmentData] = field(default_factory=list)
    security_flags: List[str] = field(default_factory=list)
    raw_size: int = 0

class EmailProcessor:
    """Procesador de emails con validaciones de seguridad"""
    
    def __init__(self):
        self.processed_count = 0
        logger.info("Email Processor inicializado")
    
    def process_email(self, email_message: EmailMessage, msg_id: str) -> EmailData:
        """
        Procesa un email completo con validaciones de seguridad
        
        Args:
            email_message: Mensaje de email parseado
            msg_id: ID único del mensaje
            
        Returns:
            EmailData: Datos procesados del email
            
        Raises:
            EmailParsingError: Error procesando el email
        """
        try:
            # Crear estructura básica
            email_data = EmailData(
                id=msg_id,
                subject=self._sanitize_header(email_message.get("Subject", "Sin asunto")),
                sender=self._sanitize_header(email_message.get("From", "")),
                to=self._sanitize_header(email_message.get("To", "")),
                cc=self._sanitize_header(email_message.get("Cc", "")),
                date=email_message.get("Date", ""),
                timestamp=time.time(),
                raw_size=len(str(email_message))
            )
            
            # Verificar tamaño del email
            if email_data.raw_size > Limits.MAX_EMAIL_SIZE:
                email_data.security_flags.append(f"Email muy grande: {email_data.raw_size} bytes")
                logger.warning(f"Email grande procesado: {msg_id} ({email_data.raw_size} bytes)")
            
            # Procesar contenido
            self._process_email_content(email_message, email_data)
            
            # Incrementar contador
            self.processed_count += 1
            
            logger.info(f"Email procesado: {email_data.subject[:50]}... ({len(email_data.attachments)} adjuntos)")
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error procesando email {msg_id}: {e}")
            raise EmailParsingError(f"Error procesando email: {e}")
    
    def _process_email_content(self, email_message: EmailMessage, email_data: EmailData):
        """Procesa el contenido del email (texto, HTML, adjuntos)"""
        if email_message.is_multipart():
            # Email con múltiples partes
            for part in email_message.walk():
                self._process_email_part(part, email_data)
        else:
            # Email simple
            self._process_email_part(email_message, email_data)
    
    def _process_email_part(self, part: EmailMessage, email_data: EmailData):
        """Procesa una parte individual del email"""
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        
        try:
            # Texto plano
            if content_type == "text/plain" and not filename:
                self._process_text_content(part, email_data)
                
            # HTML
            elif content_type == "text/html" and not filename:
                self._process_html_content(part, email_data)
                
            # Adjuntos
            elif filename or "attachment" in content_disposition:
                self._process_attachment(part, email_data, filename, content_type)
                
            # Imágenes embebidas
            elif content_type.startswith("image/"):
                self._process_image(part, email_data, filename, content_type)
                
        except Exception as e:
            logger.error(f"Error procesando parte del email: {e}")
            email_data.security_flags.append(f"Error procesando parte: {str(e)}")
    
    def _process_text_content(self, part: EmailMessage, email_data: EmailData):
        """Procesa contenido de texto plano"""
        try:
            payload = part.get_payload(decode=True)
            if payload:
                text_content = payload.decode('utf-8', errors='ignore')
                email_data.text_content += self._sanitize_content(text_content)
        except Exception as e:
            logger.warning(f"Error procesando texto plano: {e}")
            email_data.security_flags.append("Error procesando contenido de texto")
    
    def _process_html_content(self, part: EmailMessage, email_data: EmailData):
        """Procesa contenido HTML"""
        try:
            payload = part.get_payload(decode=True)
            if payload:
                html_content = payload.decode('utf-8', errors='ignore')
                email_data.html_content += self._sanitize_content(html_content)
        except Exception as e:
            logger.warning(f"Error procesando HTML: {e}")
            email_data.security_flags.append("Error procesando contenido HTML")
    
    def _process_attachment(self, part: EmailMessage, email_data: EmailData, filename: str, content_type: str):
        """Procesa un adjunto con validaciones de seguridad"""
        try:
            # Validar seguridad del adjunto
            if not self._is_attachment_safe(filename, content_type):
                email_data.security_flags.append(f"Adjunto peligroso bloqueado: {filename}")
                security_logger.suspicious_activity("unsafe_attachment", {
                    "filename": filename,
                    "content_type": content_type,
                    "subject": email_data.subject
                })
                return
            
            # Obtener datos del adjunto
            payload = part.get_payload(decode=True)
            if not payload:
                return
            
            # Verificar tamaño
            if len(payload) > Limits.MAX_ATTACHMENT_SIZE:
                email_data.security_flags.append(f"Adjunto muy grande omitido: {filename}")
                logger.warning(f"Adjunto grande omitido: {filename} ({len(payload)} bytes)")
                return
            
            # Crear datos del adjunto
            attachment = AttachmentData(
                filename=self._sanitize_filename(filename or f"attachment_{len(email_data.attachments)}"),
                content_type=content_type,
                size=len(payload),
                data=payload if len(payload) < 5 * 1024 * 1024 else None,  # Solo archivos < 5MB
                hash=hashlib.sha256(payload).hexdigest(),
                is_safe=True
            )
            
            email_data.attachments.append(attachment)
            logger.debug(f"Adjunto procesado: {attachment.filename} ({attachment.size} bytes)")
            
        except Exception as e:
            logger.error(f"Error procesando adjunto {filename}: {e}")
            email_data.security_flags.append(f"Error procesando adjunto: {filename}")
    
    def _process_image(self, part: EmailMessage, email_data: EmailData, filename: str, content_type: str):
        """Procesa una imagen embebida"""
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                return
            
            # Verificar tamaño (límite más generoso para imágenes)
            max_image_size = 10 * 1024 * 1024  # 10MB
            if len(payload) > max_image_size:
                email_data.security_flags.append(f"Imagen muy grande omitida: {filename}")
                return
            
            # Crear datos de la imagen
            image = AttachmentData(
                filename=self._sanitize_filename(filename or f"image_{len(email_data.images)}"),
                content_type=content_type,
                size=len(payload),
                data=payload,
                hash=hashlib.sha256(payload).hexdigest(),
                is_safe=True
            )
            
            email_data.images.append(image)
            logger.debug(f"Imagen procesada: {image.filename} ({image.size} bytes)")
            
        except Exception as e:
            logger.error(f"Error procesando imagen {filename}: {e}")
            email_data.security_flags.append(f"Error procesando imagen: {filename}")
    
    def _is_attachment_safe(self, filename: str, content_type: str) -> bool:
        """Verifica si un adjunto es seguro"""
        if not filename:
            return True
        
        filename_lower = filename.lower()
        
        # Verificar extensiones peligrosas
        for dangerous_ext in AttachmentTypes.DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(dangerous_ext):
                return False
        
        # Verificar tipos MIME peligrosos
        if content_type in AttachmentTypes.DANGEROUS_TYPES:
            return False
        
        # Lista blanca de tipos seguros
        if content_type in AttachmentTypes.SAFE_TYPES:
            return True
        
        # Por defecto, permitir si no está en la lista de peligrosos
        return True
    
    def _sanitize_content(self, content: str) -> str:
        """Sanitiza contenido para prevenir XSS y otros ataques"""
        if not content:
            return ""
        
        # Escapar caracteres peligrosos para HTML
        dangerous_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        sanitized = content
        for char, escape in dangerous_chars.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized
    
    def _sanitize_header(self, header: str) -> str:
        """Sanitiza headers de email"""
        if not header:
            return ""
        
        # Decodificar headers encoded
        try:
            decoded_header = email_lib.header.decode_header(header)
            decoded_text = ""
            
            for text, encoding in decoded_header:
                if isinstance(text, bytes):
                    text = text.decode(encoding or 'utf-8', errors='ignore')
                decoded_text += text
                
            return self._sanitize_content(decoded_text.strip())
        except Exception:
            # Si falla la decodificación, sanitizar como está
            return self._sanitize_content(header.strip())
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitiza nombres de archivo"""
        if not filename:
            return "unnamed_file"
        
        # Remover caracteres peligrosos
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Limitar longitud
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:250] + ('.' + ext if ext else '')
        
        return sanitized or "unnamed_file"
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del procesador"""
        return {
            "emails_processed": self.processed_count,
            "safe_attachment_types": len(AttachmentTypes.SAFE_TYPES),
            "dangerous_attachment_types": len(AttachmentTypes.DANGEROUS_TYPES),
            "dangerous_extensions": len(AttachmentTypes.DANGEROUS_EXTENSIONS),
            "max_email_size": Limits.MAX_EMAIL_SIZE,
            "max_attachment_size": Limits.MAX_ATTACHMENT_SIZE
        }

# Factory function
def create_email_processor() -> EmailProcessor:
    """Factory para crear EmailProcessor"""
    return EmailProcessor()
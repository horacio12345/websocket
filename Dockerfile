# Dockerfile
FROM python:3.11-slim as base

# Metadatos
LABEL maintainer="tu@email.com"
LABEL version="1.0.0"
LABEL description="Email Monitor - Sistema de Producción"

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Crear usuario no-root para seguridad
RUN groupadd -r emailmonitor && useradd -r -g emailmonitor emailmonitor

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Crear directorios de trabajo
WORKDIR /app
RUN chown emailmonitor:emailmonitor /app

# Copiar requirements primero (para cache de Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorios necesarios
RUN mkdir -p logs data tmp backups && \
    chown -R emailmonitor:emailmonitor /app

# Cambiar a usuario no-root
USER emailmonitor

# Exponer puerto
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python scripts/health_check.py || exit 1

# Comando por defecto
CMD ["python", "main.py"]

---

# docker-compose.yml
version: '3.8'

services:
  email-monitor:
    build: .
    container_name: email-monitor-prod
    restart: unless-stopped
    
    ports:
      - "8765:8765"
    
    environment:
      - ENVIRONMENT=production
      - PYTHONPATH=/app/src
    
    env_file:
      - .env.production
    
    volumes:
      # Persistir datos importantes
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
      # SSL certificates (si los tienes)
      - /etc/letsencrypt/live/yourdomain.com:/app/ssl:ro
    
    networks:
      - email-monitor-network
    
    depends_on:
      - redis
      - prometheus
    
    # Recursos limitados
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    
    # Logging estructurado
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  # Redis para cache de tokens y rate limiting
  redis:
    image: redis:7-alpine
    container_name: email-monitor-redis
    restart: unless-stopped
    
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    
    volumes:
      - redis-data:/data
    
    networks:
      - email-monitor-network
    
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.1'

  # Frontend web
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: email-monitor-frontend
    restart: unless-stopped
    
    ports:
      - "3000:3000"
    
    environment:
      - NODE_ENV=production
      - WEBSOCKET_URL=wss://yourdomain.com:8765
    
    networks:
      - email-monitor-network
    
    depends_on:
      - email-monitor

  # Monitoreo con Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: email-monitor-prometheus
    restart: unless-stopped
    
    ports:
      - "9090:9090"
    
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    
    networks:
      - email-monitor-network

  # Nginx como reverse proxy y SSL termination
  nginx:
    image: nginx:alpine
    container_name: email-monitor-nginx
    restart: unless-stopped
    
    ports:
      - "80:80"
      - "443:443"
    
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ./static:/var/www/static
    
    networks:
      - email-monitor-network
    
    depends_on:
      - email-monitor
      - frontend

volumes:
  redis-data:
  prometheus-data:

networks:
  email-monitor-network:
    driver: bridge

---

# scripts/deploy.sh
#!/bin/bash

echo "🚀 Desplegando Email Monitor..."

# Verificar que estamos en el directorio correcto
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml no encontrado"
    exit 1
fi

# Parar servicios existentes
echo "🛑 Deteniendo servicios existentes..."
docker-compose down

# Limpiar imágenes antiguas
echo "🧹 Limpiando imágenes antiguas..."
docker image prune -f

# Construir nuevas imágenes
echo "🔨 Construyendo imágenes..."
docker-compose build --no-cache

# Verificar configuración
echo "🔍 Verificando configuración..."
if [ ! -f ".env.production" ]; then
    echo "❌ .env.production no encontrado"
    exit 1
fi

# Iniciar servicios
echo "🚀 Iniciando servicios..."
docker-compose up -d

# Verificar que los servicios están corriendo
echo "🔍 Verificando servicios..."
sleep 10

docker-compose ps

# Health checks
echo "🏥 Verificando health checks..."
for i in {1..30}; do
    if docker exec email-monitor-prod python scripts/health_check.py; then
        echo "✅ Servicios funcionando correctamente"
        break
    fi
    
    if [ $i -eq 30 ]; then
        echo "❌ Health check falló después de 30 intentos"
        docker-compose logs email-monitor
        exit 1
    fi
    
    echo "⏳ Esperando servicios... ($i/30)"
    sleep 2
done

echo ""
echo "🎉 Deployment completado exitosamente!"
echo ""
echo "📋 URLs disponibles:"
echo "   Frontend:    http://localhost:3000"
echo "   WebSocket:   ws://localhost:8765"
echo "   Prometheus:  http://localhost:9090"
echo ""
echo "📊 Monitorear logs:"
echo "   docker-compose logs -f email-monitor"
echo ""

---

# requirements.txt
websockets==12.0
PyJWT==2.8.0
bcrypt==4.1.2
python-dotenv==1.0.0
flask==3.0.0
redis==5.0.1
prometheus-client==0.19.0
psutil==5.9.6

# Development dependencies
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
flake8==6.1.0
mypy==1.7.1
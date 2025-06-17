#!/usr/bin/env python3
"""
Email Monitor - Punto de entrada principal
Sistema de monitoreo de emails en tiempo real con WebSocket seguro

Usage:
    python main.py              # Modo normal
    python main.py --debug      # Modo debug
    python main.py --config PATH # Configuración personalizada
"""

import sys
import os
import argparse
from pathlib import Path

# Agregar el directorio src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Email Monitor - Sistema de monitoreo de emails en tiempo real"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Ejecutar en modo debug"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Ruta al archivo de configuración .env"
    )
    
    parser.add_argument(
        "--test-email",
        action="store_true",
        help="Solo probar conexión de email y salir"
    )
    
    parser.add_argument(
        "--version",
        action="store_true",
        help="Mostrar versión y salir"
    )
    
    return parser.parse_args()

def setup_environment(args):
    """Configura el entorno según los argumentos"""
    
    # Configurar archivo .env personalizado
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"❌ Archivo de configuración no encontrado: {config_path}")
            sys.exit(1)
        os.environ["ENV_FILE"] = str(config_path)
    
    # Configurar modo debug
    if args.debug:
        os.environ["DEBUG"] = "true"
        os.environ["LOG_LEVEL"] = "DEBUG"
        print("🐛 Modo DEBUG activado")

async def test_email_connection():
    """Prueba solo la conexión de email"""
    from src.core.config import config
    from src.email import create_email_monitor
    
    print(f"🔍 Probando conexión a {config.email.server}:{config.email.port}")
    print(f"👤 Usuario: {config.email.username}")
    
    monitor = create_email_monitor(config.email)
    
    if monitor.test_connection():
        print("✅ Conexión de email exitosa")
        return True
    else:
        print("❌ Error de conexión de email")
        return False

def main():
    """Función principal"""
    args = parse_arguments()
    
    # Mostrar versión
    if args.version:
        from src.core.constants import VERSION, BUILD_DATE
        print(f"Email Monitor v{VERSION} ({BUILD_DATE})")
        sys.exit(0)
    
    # Configurar entorno
    setup_environment(args)
    
    # Solo probar email
    if args.test_email:
        import asyncio
        success = asyncio.run(test_email_connection())
        sys.exit(0 if success else 1)
    
    # Ejecutar aplicación principal
    try:
        import asyncio
        from src.main import main as app_main
        
        print("🚀 Iniciando Email Monitor...")
        asyncio.run(app_main())
        
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        print("💡 Asegúrate de que todas las dependencias están instaladas:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Aplicación interrumpida por el usuario")
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Email Monitor - Main entry point
Real-time email monitoring system with secure WebSocket

Usage:
    python3 main.py              # Normal mode
    python3 main.py --debug      # Debug mode
    python3 main.py --config PATH # Custom configuration
"""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Email Monitor - Real-time email monitoring system"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to .env configuration file"
    )
    
    parser.add_argument(
        "--test-email",
        action="store_true",
        help="Only test email connection and exit"
    )
    
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit"
    )
    
    return parser.parse_args()

def setup_environment(args):
    """Setup environment according to arguments"""
    
    # Configure custom .env file
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"❌ Configuration file not found: {config_path}")
            sys.exit(1)
        os.environ["ENV_FILE"] = str(config_path)
    
    # Configure debug mode
    if args.debug:
        os.environ["DEBUG"] = "true"
        os.environ["LOG_LEVEL"] = "DEBUG"
        print("🐛 DEBUG mode activated")

async def test_email_connection():
    """Test email connection only"""
    try:
        from core.config import config
        from email_system import create_email_monitor
        
        print(f"🔍 Testing connection to {config.email.server}:{config.email.port}")
        print(f"👤 User: {config.email.username}")
        
        monitor = create_email_monitor(config.email)
        
        if monitor.test_connection():
            print("✅ Email connection successful")
            return True
        else:
            print("❌ Email connection error")
            return False
    except Exception as e:
        print(f"❌ Error testing email connection: {e}")
        return False

def main():
    """Main function"""
    args = parse_arguments()
    
    # Show version
    if args.version:
        try:
            from core.constants import VERSION, BUILD_DATE
            print(f"Email Monitor v{VERSION} ({BUILD_DATE})")
        except ImportError:
            print("Email Monitor v1.0.0")
        sys.exit(0)
    
    # Setup environment
    setup_environment(args)
    
    # Only test email
    if args.test_email:
        import asyncio
        success = asyncio.run(test_email_connection())
        sys.exit(0 if success else 1)
    
    # Run main application
    try:
        import asyncio
        from main import main as app_main
        
        print("🚀 Starting Email Monitor...")
        asyncio.run(app_main())
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all dependencies are installed:")
        print("   pip3 install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Application interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
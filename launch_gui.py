#!/usr/bin/env python3
"""
PhishGuard GUI Launcher

Simple launcher script to test the integrated GUI application.
This script can be run directly to launch the PhishGuard GUI.
"""

import sys
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

try:
    # Import and run the GUI
    from phishguard.cli.main import launch_gui
    
    print("🚀 Launching PhishGuard GUI...")
    launch_gui()
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all dependencies are installed")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting GUI: {e}")
    sys.exit(1)

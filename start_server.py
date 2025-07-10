#!/usr/bin/env python3
"""
AutoRedTeam Web Server Starter
Simple script to start both frontend and backend servers
"""

import os
import sys
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

def start_backend():
    """Start the Flask backend server"""
    print("🚀 Starting AutoRedTeam Backend Server...")
    backend_dir = Path("backend")
    
    if not backend_dir.exists():
        print("❌ Backend directory not found!")
        return False
    
    try:
        # Change to backend directory and start Flask app
        os.chdir(backend_dir)
        subprocess.run([sys.executable, "app.py"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Backend server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start backend: {e}")
        return False
    
    return True

def start_frontend():
    """Start a simple HTTP server for the frontend"""
    print("🌐 Starting Frontend Server...")
    frontend_dir = Path("frontend")
    
    if not frontend_dir.exists():
        print("❌ Frontend directory not found!")
        return False
    
    try:
        # Change to frontend directory and start HTTP server
        os.chdir(frontend_dir)
        subprocess.run([sys.executable, "-m", "http.server", "8000"], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Frontend server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start frontend: {e}")
        return False
    
    return True

def open_browser():
    """Open the web application in the default browser"""
    time.sleep(3)  # Wait for servers to start
    try:
        webbrowser.open("http://localhost:8000")
        print("🌍 Opened AutoRedTeam Web Interface in your browser")
    except Exception as e:
        print(f"⚠️ Could not open browser automatically: {e}")
        print("🌍 Please manually open: http://localhost:8000")

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    try:
        import flask
        import flask_cors
        print("✅ Flask dependencies found")
    except ImportError as e:
        print(f"❌ Missing Flask dependency: {e}")
        print("📦 Please run: pip install -r requirements.txt")
        return False
    
    return True

def main():
    """Main function to start the web application"""
    print("=" * 50)
    print("🔒 AutoRedTeam Web Application")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Check if directories exist
    if not Path("frontend").exists():
        print("❌ Frontend directory not found!")
        print("📁 Make sure you're in the autoredteam-website directory")
        return
    
    if not Path("backend").exists():
        print("❌ Backend directory not found!")
        print("📁 Make sure you're in the autoredteam-website directory")
        return
    
    print("🎯 Starting AutoRedTeam Web Application...")
    print("📋 Backend: http://localhost:5000")
    print("📋 Frontend: http://localhost:8000")
    print("=" * 50)
    
    # Start backend in a separate thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    
    # Start browser opener in a separate thread
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Start frontend (this will block)
    try:
        start_frontend()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down AutoRedTeam Web Application...")
        print("👋 Goodbye!")

if __name__ == "__main__":
    main() 
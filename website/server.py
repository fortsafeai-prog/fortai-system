#!/usr/bin/env python3
"""
Simple HTTP server for ForTAI landing page
Serves the website and provides CORS headers for local development
"""

import http.server
import socketserver
import os
import sys
from urllib.parse import urlparse, parse_qs
import json

class ForTAIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def end_headers(self):
        # Add CORS headers for local development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        # Serve the main page for root requests
        if self.path == '/' or self.path == '':
            self.path = '/index.html'

        # Handle status check requests
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            status = {
                "website": "online",
                "timestamp": "2025-09-16T12:00:00Z",
                "version": "1.0.0",
                "services": {
                    "frontend": "http://localhost:3000",
                    "backend": "http://localhost:8000",
                    "docs": "http://localhost:8000/docs",
                    "minio": "http://localhost:9001"
                }
            }

            self.wfile.write(json.dumps(status, indent=2).encode())
            return

        super().do_GET()

    def log_message(self, format, *args):
        # Custom log format
        print(f"[ForTAI Website] {self.address_string()} - {format % args}")

def main():
    PORT = 8080

    print("=" * 60)
    print("🚀 ForTAI Landing Website Server")
    print("=" * 60)
    print(f"Starting server on port {PORT}...")
    print(f"Website URL: http://localhost:{PORT}")
    print(f"Status API: http://localhost:{PORT}/status")
    print()
    print("This website connects to:")
    print("  - Frontend (Chat UI): http://localhost:3000")
    print("  - Backend API: http://localhost:8000")
    print("  - API Documentation: http://localhost:8000/docs")
    print("  - MinIO Console: http://localhost:9001")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 60)

    try:
        with socketserver.TCPServer(("", PORT), ForTAIHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Simple HTTP server for testing the p2pComm WASM demo.
Serves files with proper MIME types for WASM.
"""

import http.server
import socketserver
import os

PORT = 8000

class WAsmHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add WASM MIME type
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        http.server.SimpleHTTPRequestHandler.end_headers(self)

    def guess_type(self, path):
        mimetype = http.server.SimpleHTTPRequestHandler.guess_type(self, path)
        if path.endswith('.wasm'):
            mimetype = 'application/wasm'
        return mimetype

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with socketserver.TCPServer(("", PORT), WAsmHandler) as httpd:
    print("=" * 55)
    print("     p2pComm WASM Demo Server")
    print("=" * 55)
    print("")
    print(f"  Server running at: http://localhost:{PORT}")
    print(f"  Open in browser:   http://localhost:{PORT}/example.html")
    print("")
    print("  Press Ctrl+C to stop")
    print("")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServer stopped.")

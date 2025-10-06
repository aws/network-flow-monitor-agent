#!/usr/bin/env python3

import http.client
import http.server
import json
import socketserver
import threading
import socket

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def start_http_server(ip='localhost', port=8080):
    """Start a simple HTTP server on the specified port."""
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Hello from test server!')

        def log_message(self, format, *args):
            pass  # Suppress logging

    server = socketserver.TCPServer((ip, port), Handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server

def send_http_request(ip='localhost', port=8080):
    """Send a single HTTP request and return success status."""
    print('Sending test HTTP request...', end='')
    try:
        conn = http.client.HTTPConnection(ip, port)
        conn.request('GET', '/')
        response = conn.getresponse()
        if response.status == 200:
            print('succeeded')
            return True
        else:
            print(f'failed: {response.status}')
            return False
    except Exception as e:
        print(f'failed: {e}')
        return False
    finally:
        conn.close()

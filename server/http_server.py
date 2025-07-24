# server_custom.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for: {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Hello from localhost HTTP server!</h1>")

HOST = 'localhost'
PORT = 8080

httpd = HTTPServer((HOST, PORT), MyHandler)
print(f"Custom HTTP server running on {HOST}:{PORT}")
httpd.serve_forever()

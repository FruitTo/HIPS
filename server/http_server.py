# server_custom.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for: {self.path}")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Hello from enp2s0 HTTP server!</h1>")

# เปลี่ยนจาก 'localhost' เป็น IP จริงของ interface
HOST = '192.168.1.121'
PORT = 8080

httpd = HTTPServer((HOST, PORT), MyHandler)
print(f"Custom HTTP server running on {HOST}:{PORT}")
httpd.serve_forever()

# http_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Hello from local HTTP server!')
        print(f"[HTTP] Served GET request for {self.path}")

def run(server_class=HTTPServer, handler_class=SimpleHandler, port=8000):
    address = ('127.0.0.1', port)
    httpd = server_class(address, handler_class)
    print(f"Starting HTTP server on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped by user.")
    httpd.server_close()

if __name__ == '__main__':
    run()

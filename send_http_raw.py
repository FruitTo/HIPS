# send_http_raw.py
import socket

def send_http_get(host='127.0.0.1', port=8000, path='/', method='GET'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: SnortTest/1.0\r\n"
        f"Accept: */*\r\n"
        "\r\n"
    )
    sock.send(request.encode())
    print("Sent raw HTTP request:")
    print(request)
    response = sock.recv(1024).decode(errors='ignore')
    print("Received response:")
    print(response.splitlines()[0])
    sock.close()

if __name__ == '__main__':
    send_http_get()

#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include <iostream>
#include <string>
#include <thread>
#include <map>
#include <sstream>
#include <vector>
#include <regex>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

class TestServer {
private:
    int server_fd;
    int port;
    bool running;

    std::string buildResponse(int status, const std::string& content_type, const std::string& body) {
        std::ostringstream response;
        response << "HTTP/1.1 " << status;
        
        switch(status) {
            case 200: response << " OK"; break;
            case 400: response << " Bad Request"; break;
            case 404: response << " Not Found"; break;
            case 500: response << " Internal Server Error"; break;
        }
        
        response << "\r\n";
        response << "Content-Type: " << content_type << "\r\n";
        response << "Content-Length: " << body.length() << "\r\n";
        response << "Connection: close\r\n";
        response << "\r\n";
        response << body;
        
        return response.str();
    }

    void handleRequest(int client_socket) {
        char buffer[8192] = {0};
        read(client_socket, buffer, 8192);
        
        std::string request(buffer);
        std::cout << "=== Received Request ===\n" << request << std::endl;
        
        // Parse request line
        std::istringstream request_stream(request);
        std::string method, path, version;
        request_stream >> method >> path >> version;
        
        std::string response_body;
        std::string content_type = "text/html";
        int status_code = 200;
        
        // Route handling
        if (path == "/") {
            response_body = "<h1>Test Server</h1><p>Server is running on port " + std::to_string(port) + "</p>";
        }
        else if (path == "/test") {
            response_body = "<h1>Test Endpoint</h1><p>Method: " + method + "</p>";
        }
        else if (path == "/json") {
            content_type = "application/json";
            response_body = "{\"message\":\"Hello JSON\",\"method\":\"" + method + "\"}";
        }
        else if (path == "/xml") {
            content_type = "application/xml";
            response_body = "<?xml version=\"1.0\"?><response><message>Hello XML</message></response>";
        }
        else if (path == "/login") {
            response_body = "<form method='POST'><input name='user' placeholder='Username'/><input name='pass' type='password' placeholder='Password'/><button type='submit'>Login</button></form>";
        }
        else if (path == "/upload") {
            response_body = "<form method='POST' enctype='multipart/form-data'><input type='file' name='file'/><button type='submit'>Upload</button></form>";
        }
        else if (path == "/error") {
            status_code = 500;
            response_body = "<h1>Internal Server Error</h1><p>Test error page</p>";
        }
        else {
            status_code = 404;
            response_body = "<h1>404 Not Found</h1><p>Path: " + path + "</p>";
        }
        
        std::string response = buildResponse(status_code, content_type, response_body);
        send(client_socket, response.c_str(), response.length(), 0);
        close(client_socket);
    }

public:
    TestServer(int port = 8080) : port(port), running(false) {}
    
    bool start() {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == 0) {
            std::cerr << "Socket creation failed" << std::endl;
            return false;
        }
        
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            std::cerr << "Bind failed" << std::endl;
            return false;
        }
        
        if (listen(server_fd, 3) < 0) {
            std::cerr << "Listen failed" << std::endl;
            return false;
        }
        
        running = true;
        std::cout << "Test server started on port " << port << std::endl;
        
        while (running) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_socket < 0) continue;
            
            std::thread(&TestServer::handleRequest, this, client_socket).detach();
        }
        
        return true;
    }
    
    void stop() {
        running = false;
        close(server_fd);
    }
};

// Usage function
void runTestServer() {
    TestServer server(8080);
    server.start();
}

#endif
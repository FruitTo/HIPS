#!/bin/bash

# HTTP Testing Commands for Packet Filtering
# Target: http://localhost:8080

BASE_URL="http://localhost:8080"

echo "=== HTTP_METHOD Testing ==="
# GET method
curl -X GET "$BASE_URL/test"

# POST method
curl -X POST "$BASE_URL/test" -d "data=test"

# PUT method
curl -X PUT "$BASE_URL/test" -d "update=true"

# DELETE method
curl -X DELETE "$BASE_URL/test"

# HEAD method
curl -X HEAD "$BASE_URL/test"

# OPTIONS method
curl -X OPTIONS "$BASE_URL/test"

# PATCH method
curl -X PATCH "$BASE_URL/test" -d "patch=data"

echo -e "\n=== HTTP_URI และ HTTP_RAW_URI Testing ==="
# Normal URI
curl "$BASE_URL/normal/path"

# URI with query parameters
curl "$BASE_URL/search?q=test&category=all"

# URI with encoded characters (raw vs decoded)
curl "$BASE_URL/search?q=test%20data&file=test%2Etxt"

# URI with special characters
curl "$BASE_URL/path/with%20spaces/and%26symbols"

# Long URI
curl "$BASE_URL/very/long/path/with/many/segments/test/data/file.php?param1=value1&param2=value2&param3=value3"

# Suspicious URI patterns
curl "$BASE_URL/admin/config.php?cmd=ls"
curl "$BASE_URL/../../etc/passwd"
curl "$BASE_URL/test.php?id=1%27%20OR%20%271%27=%271"

echo -e "\n=== HTTP_CLIENT_BODY Testing ==="
# Form data
curl -X POST "$BASE_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=administrator"

# JSON data
curl -X POST "$BASE_URL/api/data" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","action":"delete","target":"/etc/passwd"}'

# XML data
curl -X POST "$BASE_URL/soap" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><soap:Envelope><soap:Body><request>test</request></soap:Body></soap:Envelope>'

# Multipart form data
curl -X POST "$BASE_URL/upload" \
  -F "file=@/etc/hosts" \
  -F "description=test file"

# Large body data
curl -X POST "$BASE_URL/test" \
  -H "Content-Type: text/plain" \
  -d "$(printf 'A%.0s' {1..1000})"

# Suspicious content in body
curl -X POST "$BASE_URL/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "data=<script>alert('XSS')</script>&cmd=rm%20-rf%20/"

echo -e "\n=== HTTP_HEADER และ HTTP_RAW_HEADER Testing ==="
# Standard browser headers
curl "$BASE_URL/test" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate" \
  -H "Connection: keep-alive"

# Custom headers with IP forwarding
curl "$BASE_URL/test" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "X-Real-IP: 10.0.0.50" \
  -H "X-Custom-Header: suspicious-value"

# Authorization header
curl "$BASE_URL/admin" \
  -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="

# Bearer token
curl "$BASE_URL/api" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Suspicious headers
curl "$BASE_URL/test" \
  -H "X-Command: rm -rf /" \
  -H "User-Agent: sqlmap/1.0" \
  -H "Referer: http://evil-site.com/" \
  -H "X-Injection: ' OR 1=1--"

# Multiple custom headers
curl "$BASE_URL/test" \
  -H "Host: localhost:8080" \
  -H "Cache-Control: no-cache" \
  -H "Pragma: no-cache" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Origin: http://localhost:8080"

echo -e "\n=== HTTP_COOKIE และ HTTP_RAW_COOKIE Testing ==="
# Normal cookies
curl "$BASE_URL/test" \
  -H "Cookie: sessionid=abc123; user=admin"

# Multiple cookies
curl "$BASE_URL/test" \
  -H "Cookie: PHPSESSID=1234567890abcdef; lang=en; theme=dark"

# Suspicious cookies
curl "$BASE_URL/test" \
  -H "Cookie: admin=true; role=administrator; debug=1"

# Encoded cookies
curl "$BASE_URL/test" \
  -H "Cookie: data=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# Large cookie
curl "$BASE_URL/test" \
  -H "Cookie: data=$(printf 'X%.0s' {1..500})"

# Session cookies
curl "$BASE_URL/test" \
  -H "Cookie: JSESSIONID=A1B2C3D4E5F6; path=/; secure; httponly"

echo -e "\n=== HTTP_TRUE_IP Testing (Client IP) ==="
# Different IP forwarding headers
curl "$BASE_URL/test" \
  -H "X-Forwarded-For: 203.0.113.195"

curl "$BASE_URL/test" \
  -H "X-Real-IP: 198.51.100.178"

curl "$BASE_URL/test" \
  -H "X-Client-IP: 192.0.2.146"

curl "$BASE_URL/test" \
  -H "X-Forwarded-For: 10.0.0.1, 192.168.1.100, 203.0.113.195"

echo -e "\n=== Complete HTTP Flow Testing ==="
# Complete request with all components
curl -X POST "$BASE_URL/api/login" \
  -H "User-Agent: TestBot/1.0" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "Authorization: Bearer token123" \
  -H "Cookie: sessionid=test123; tracking=enabled" \
  -H "Referer: http://localhost:8080/login" \
  -d '{"username":"admin","password":"secret","remember":true}'

# File upload simulation
curl -X POST "$BASE_URL/upload" \
  -H "User-Agent: FileUploader/2.0" \
  -H "X-Forwarded-For: 192.168.1.50" \
  -H "Cookie: upload_session=xyz789" \
  -F "file=@test.txt" \
  -F "category=documents"

echo -e "\n=== Attack Pattern Testing ==="
# SQL Injection attempts
curl "$BASE_URL/search?id=1%27%20OR%20%271%27=%271" \
  -H "User-Agent: sqlmap/1.4.12"

# XSS attempts
curl -X POST "$BASE_URL/comment" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"

# Command injection
curl "$BASE_URL/ping?host=8.8.8.8%3B%20rm%20-rf%20/" \
  -H "User-Agent: exploit/1.0"

# Path traversal
curl "$BASE_URL/file?path=../../../etc/passwd" \
  -H "User-Agent: PathTraversal/1.0"

# Large request (potential DoS)
curl -X POST "$BASE_URL/test" \
  -H "Content-Type: text/plain" \
  -d "$(printf 'A%.0s' {1..10000})"

echo -e "\n=== Status Code Testing ==="
# Different endpoints for different status codes
curl "$BASE_URL/"           # 200 OK
curl "$BASE_URL/notfound"   # 404 Not Found  
curl "$BASE_URL/error"      # 500 Internal Server Error
curl "$BASE_URL/forbidden"  # 403 Forbidden (if implemented)

echo -e "\n=== All HTTP tests completed ==="
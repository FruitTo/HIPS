#ifndef DTO_H
#define DTO_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

// Enums
enum class ClassType
{
   // Priority 1 - Critical/High Severity
   ATTEMPTED_USER = 1,
   UNSUCCESSFUL_USER = 1,
   SUCCESSFUL_USER = 1,
   ATTEMPTED_ADMIN = 1,
   SUCCESSFUL_ADMIN = 1,
   SHELLCODE_DETECT = 1,
   TROJAN_ACTIVITY = 1,
   WEB_APPLICATION_ATTACK = 1,
   INAPPROPRIATE_CONTENT = 1,
   POLICY_VIOLATION = 1,
   MALWARE_CNC = 1,
   CLIENT_SIDE_EXPLOIT = 1,

   // Priority 2 - High
   BAD_UNKNOWN = 2,
   ATTEMPTED_RECON = 2,
   SUCCESSFUL_RECON_LIMITED = 2,
   SUCCESSFUL_RECON_LARGESCALE = 2,
   ATTEMPTED_DOS = 2,
   SUCCESSFUL_DOS = 2,
   DENIAL_OF_SERVICE = 2,
   RPC_PORTMAP_DECODE = 2,
   SUSPICIOUS_FILENAME_DETECT = 2,
   SUSPICIOUS_LOGIN = 2,
   SYSTEM_CALL_DETECT = 2,
   UNUSUAL_CLIENT_PORT_CONNECTION = 2,
   NON_STANDARD_PROTOCOL = 2,
   WEB_APPLICATION_ACTIVITY = 2,
   MISC_ATTACK = 2,
   DEFAULT_LOGIN_ATTEMPT = 2,

   // Priority 3 - Medium
   NOT_SUSPICIOUS = 3,
   UNKNOWN = 3,
   STRING_DETECT = 3,
   NETWORK_SCAN = 3,
   PROTOCOL_COMMAND_DECODE = 3,
   MISC_ACTIVITY = 3,
   ICMP_EVENT = 3,

   // Priority 4 - Low
   TCP_CONNECTION = 4
};

enum class Endianness
{
   LITTLE = 1,
   BIG = 2
};

enum class Width
{
   BITS_8 = 8,
   BITS_16 = 16,
   BITS_32 = 32
};

enum class Buffer
{
   NONE = 0,
   
   // Basic packet buffers
   PKT_DATA,
   RAW_DATA,
   BASE64_DATA,
   FILE_DATA,
   
   // HTTP request/response body
   HTTP_CLIENT_BODY,
   HTTP_RAW_BODY,
   
   // HTTP cookies
   HTTP_COOKIE,
   HTTP_RAW_COOKIE,
   
   // HTTP headers
   HTTP_HEADER,
   HTTP_RAW_HEADER,
   
   // HTTP request line components
   HTTP_METHOD,
   HTTP_URI,
   HTTP_RAW_URI,
   
   // HTTP status line components  
   HTTP_STAT_CODE,
   HTTP_STAT_MSG,
   
   // HTTP client identification
   HTTP_TRUE_IP,
   
   // DCE/RPC buffers
   DCE_IFACE,
   DCE_OPNUM,
   DCE_STUB_DATA,
   
   // SSL/TLS buffers
   SSL_STATE,
   SSL_VERSION,
   
   // SIP buffers
   SIP_HEADER,
   SIP_BODY,
};

enum class Operator {
   GREATER_THAN,
   LESS_THAN,
   EQUAL,
   NOT_EQUAL,
   GREATER_EQUAL,
   LESS_EQUAL,
   RANGE_EXCLUSIVE,
   RANGE_INCLUSIVE
};

enum class ByteTestOperator {
   LESS_THAN,
   GREATER_THAN,
   LESS_EQUAL,
   GREATER_EQUAL,
   EQUAL,
   BITWISE_AND,
   BITWISE_XOR
};

enum class SSLState {
   CLIENT_HELLO,
   SERVER_HELLO,
   CLIENT_KEYX,
   SERVER_KEYX,
   UNKNOWN
};

enum class SSLVersion {
   SSLV2,
   SSLV3,
   TLS1_0,
   TLS1_1,
   TLS1_2
};

#endif
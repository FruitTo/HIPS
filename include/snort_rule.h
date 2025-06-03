#ifndef SNORT_RULE_H
#define SNORT_RULE_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

// Enums
enum class ClassType
{
   // Priority 1 - Critical
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
   FILE_FORMAT = 1,
   MALWARE_CNC = 1,
   CLIENT_SIDE_EXPLOIT = 1,

   // Priority 2 - High
   BAD_UNKNOWN = 2,
   ATTEMPTED_RECON = 2,
   SUCCESSFUL_RECON_LIMITED = 2,
   SUCCESSFUL_RECON_LARGESCALE = 2,
   ATTEMPTED_DOS = 2,
   SUCCESSFUL_DOS = 2,
   RPC_PORTMAP_DECODE = 2,
   SUSPICIOUS_FILENAME_DETECT = 2,
   SUSPICIOUS_LOGIN = 2,
   SYSTEM_CALL_DETECT = 2,
   UNUSUAL_CLIENT_PORT_CONNECTION = 2,
   DENIAL_OF_SERVICE = 2,
   NON_STANDARD_PROTOCOL = 2,
   WEB_APPLICATION_ACTIVITY = 2,
   MISC_ATTACK = 2,
   DEFAULT_LOGIN_ATTEMPT = 2,
   SDF = 2,

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
   PKT_DATA,
   RAW_DATA,
   BASE64_DATA,
   HTTP_CLIENT_BODY,
   HTTP_COOKIE,
   HTTP_HEADER,
   HTTP_METHOD,
   HTTP_PASSWD,
   HTTP_PASSWDCONFIRM,
   HTTP_RAW_HEADER,
   HTTP_RAW_URI,
   HTTP_STAT_CODE,
   HTTP_STAT_MSG,
   HTTP_URI,
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

// Basic Structs
struct NetworkConfig
{
   std::optional<std::string> EXTERNAL_NET;
   std::optional<std::string> FILE_DATA_PORTS;
   std::optional<std::string> FTP_PORTS;
   std::optional<std::string> HOME_NET;
   std::optional<std::string> HTTP_PORTS;
   std::optional<std::string> HTTP_SERVERS;
   std::optional<std::string> ORACLE_PORTS;
   std::optional<std::string> SMTP_SERVERS;
   std::optional<std::string> SQL_SERVERS;
   std::optional<std::string> SSH_PORTS;
   std::optional<std::string> TELNET_SERVERS;
};

struct FlowOption {
   bool to_client = false;
   bool to_server = false;
   bool established = false;
   bool stateless = false;
};

// Content and Pattern Matching
struct Content
{
   Buffer http = Buffer::NONE;
   bool negate = false;
   std::string content;

   bool fast_pattern = false;
   bool fast_pattern_only = false;
   std::optional<uint32_t> fast_pattern_offset;
   std::optional<uint32_t> fast_pattern_length;

   bool nocase = false;

   std::optional<Width> width;
   std::optional<Endianness> endian;

   std::optional<int32_t> offset;
   std::optional<uint32_t> depth;
   std::optional<int32_t> distance;
   std::optional<uint32_t> within;
};

struct PCRE {
   std::string pattern;
   bool negate = false;
   
   bool i = false;
   bool s = false;
   bool m = false;
   bool x = false;
   bool A = false;
   bool E = false;
   bool G = false;
   bool O = false;
   bool R = false;
};

// Size and Position Checks
struct BufferLen {
   Operator operator;
   uint32_t min_value;
   std::optional<uint32_t> max_value;
   bool relative = false;
};

struct Dsize {
   Operator operator;
   uint16_t min_value;
   std::optional<uint16_t> max_value; 
};

struct IsDataAt {
   uint32_t location;
   bool negate = false;
   bool relative = false;
};

// Byte Operations
struct ByteExtract {
   uint8_t count;
   int32_t offset;
   std::string variable_name;
   
   bool relative = false;
   std::optional<uint16_t> multiplier;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   std::optional<uint8_t> align;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

struct ByteTest {
   uint8_t count;
   ByteTestOperator operator;
   bool negate = false;
   std::string compare_value;
   std::string offset;
   
   bool relative = false;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

struct ByteJump {
   uint8_t count;
   std::string offset;
   
   bool relative = false;
   std::optional<uint16_t> multiplier;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   bool align = false;
   bool from_beginning = false;
   bool from_end = false;
   std::optional<std::string> post_offset;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

// Protocol Specific
struct Base64Decode {
   std::optional<uint32_t> bytes;
   std::optional<uint32_t> offset;
   bool relative = false;
};

struct BerData {
   uint8_t type;
};

struct BerSkip {
   uint8_t type;
   bool optional = false;
};

struct SSLStateOption {
   std::vector<SSLState> states;
   bool negate = false;
};

struct SSLVersionOption {
   std::vector<SSLVersion> versions;
   bool negate = false;
};

// Rule Structure
struct PayloadOption
{
   std::vector<Content> content;
   std::optional<BufferLen> bufferlen;
   std::optional<IsDataAt> isdataat;
   std::optional<Dsize> dsize;
   std::optional<PCRE> pcre;
   std::optional<Base64Decode> base64_decode;
   std::optional<std::vector<ByteExtract>> byte_extracts;
   std::optional<std::vector<ByteTest>> byte_tests;
   std::optional<std::vector<ByteJump>> byte_jumps;
   std::optional<std::vector<BerData>> ber_data_list;
   std::optional<std::vector<BerSkip>> ber_skip_list;
   std::optional<SSLStateOption> ssl_state;
   std::optional<SSLVersionOption> ssl_version;
};

struct GeneralOption
{
   std::optional<std::string> msg;
   std::optional<uint16_t> gid;
   uint16_t sid;
   ClassType classtype;
   std::optional<std::vector<std::string>> service;
};

struct RuleOption
{
   GeneralOption general;
   PayloadOption payload;
   FlowOption flow;
};

struct Rule
{
   std::optional<std::string> action;
   std::optional<std::string> protocol;
   std::optional<std::string> src_addr;
   std::optional<std::string> src_port;
   std::optional<std::string> direction;
   std::optional<std::string> dst_addr;
   std::optional<std::string> dst_port;
   RuleOption option;
};

#endif
#ifndef SNORT_RULE_H
#define SNORT_RULE_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>  // ← เพิ่ม

enum class ClassType {
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

struct NetworkConfig {
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

enum class Endianness {
    LITTLE = 1,
    BIG = 2
};

enum class Width {
    BITS_8 = 8,
    BITS_16 = 16,
    BITS_32 = 32
};

struct Content {
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

struct PayloadOption {
    std::vector<Content> content;
};

struct GeneralOption {
    std::optional<std::string> msg;
    std::optional<uint16_t> gid;
    uint16_t sid;
    ClassType classtype;
    std::optional<std::vector<std::string>> service;
};

struct RuleOption {
    GeneralOption general;
    PayloadOption payload;
};

struct Rule {
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
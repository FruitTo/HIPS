#ifndef PACKET_H
#define PACKET_H
#include "./rules/dto.h"
#include "flow.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct NetworkConfig {
   std::string NAME;
   std::string IP;

   std::optional<std::string> HOME_NET;
   std::optional<std::string> EXTERNAL_NET;

   std::vector<std::string> HTTP_PORTS;
   std::vector<std::string> SSH_PORTS;
   std::vector<std::string> FTP_PORTS;
   std::vector<std::string> SIP_PORTS;

   std::vector<std::string> ORACLE_PORTS;
   std::vector<std::string> FILE_DATA_PORTS;

   std::optional<bool> HTTP_SERVERS = false;
   std::optional<bool> SSH_SERVERS = false;
   std::optional<bool> FTP_SERVERS = false;

   std::optional<bool> TELNET_SERVERS = false;
   std::optional<bool> SMTP_SERVERS = false;
   std::optional<bool> SIP_SERVERS = false;
   std::optional<bool> SQL_SERVERS = false;
};

struct TCPFlagsInfo {
  bool fin = false; // F - Finish
  bool syn = false; // S - Synchronize
  bool rst = false; // R - Reset
  bool psh = false; // P - Push
  bool ack = false; // A - Acknowledgment
  bool urg = false; // U - Urgent
  bool ece = false; // E - ECN-Echo
  bool cwr = false; // C - Congestion Window Reduced
};

struct UDPInfo {
  std::string sport;
  std::string dport;
  uint16_t length;
  uint16_t checksum;
  std::vector<uint8_t> payload;
  size_t payload_size;
};

struct TCPInfo {
  TCPFlagsInfo flags;
  std::string sport;
  std::string dport;
  std::string seq;
  std::string ack_seq;
  std::vector<uint8_t> payload;
  size_t payload_size;
};

struct ICMPInfo {
  uint8_t type;
  uint8_t code;
  uint16_t id;
  uint16_t sequence;
  std::vector<uint8_t> payload;
  size_t payload_size;
};

struct HTTPInfo {
  // Request fields
  std::optional<std::string> method;      // HTTP_METHOD
  std::optional<std::string> uri;         // HTTP_URI
  std::optional<std::string> raw_uri;     // HTTP_RAW_URI
  std::optional<std::string> client_body; // HTTP_CLIENT_BODY

  // Response fields
  std::optional<std::string> status_code; // HTTP_STAT_CODE
  std::optional<std::string> status_msg;  // HTTP_STAT_MSG
  std::optional<std::string> raw_body;    // HTTP_RAW_BODY

  // Client identification
  std::optional<std::string> true_ip; // HTTP_TRUE_IP

  // Raw data
  std::string raw_headers; // HTTP_HEADER, HTTP_RAW_HEADER
  std::string raw_cookie;  // HTTP_COOKIE, HTTP_RAW_COOKIE
};

// เพิ่ม struct ใหม่
struct SSLInfo {
  std::optional<SSLState> state;
  std::optional<SSLVersion> version;
  std::vector<uint8_t> payload;
  size_t payload_size = 0;
};

struct SIPInfo {
  std::string headers;
  std::string body;
  std::vector<uint8_t> payload;
  size_t payload_size = 0;
};

struct DCEInfo {
  std::string interface_uuid;
  uint16_t operation_num = 0;
  std::vector<uint8_t> stub_data;
  std::vector<uint8_t> payload;
  size_t payload_size = 0;
};

struct FTPInfo {
  std::optional<std::string> command;
  std::optional<std::string> args;
  std::optional<std::string> response_code;
  std::optional<std::string> response_msg;
  std::optional<std::string> filename;
  std::vector<uint8_t> payload;
  size_t payload_size = 0;
};

struct SMTPInfo {
  std::optional<std::string> command;
  std::optional<std::string> args;
  std::optional<std::string> response_code;
  std::optional<std::string> response_msg;
  std::optional<std::string> from;
  std::optional<std::string> to;
  std::optional<std::string> subject;
  std::string body;
  std::vector<uint8_t> payload;
  size_t payload_size = 0;
};

struct PacketInfo {
  std::chrono::system_clock::time_point timestamp;
  std::string id;
  int ttl;
  bool more_fragments = false; // M
  bool dont_fragment = false;  // D
  bool reserved = false;       // R
  std::string protocol;
  std::string src_addr;
  std::string dst_addr;
  uint8_t ip_proto;                // IP Protocol number (6=TCP, 17=UDP, 1=ICMP)
  uint16_t ip_len;                 // Total IP packet length (IP Header)
  size_t ip_size;                  // Actual size of packet
  uint8_t ip_tos;                  // Type of Service / DSCP
  uint8_t ip_version;              // IP version (4 or 6)
  uint8_t ip_header_len;           // IP header length
  uint16_t frag_offset;            // Fragment offset (13 bits)
  uint16_t checksum;

  std::optional<TCPInfo> tcp;
  std::optional<UDPInfo> udp;
  std::optional<ICMPInfo> icmp;
  std::optional<HTTPInfo> http;
  std::optional<SSLInfo> ssl;
  std::optional<SIPInfo> sip;
  std::optional<DCEInfo> dce;
  std::optional<FTPInfo> ftp;
  std::optional<SMTPInfo> smtp;

  FlowInfo flow;
};

#endif
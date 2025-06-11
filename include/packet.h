#ifndef PACKET_H
#define PACKET_H
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

enum class FlowState {
  ESTABLISHED,     // TCP connection established
  NOT_ESTABLISHED, // TCP handshake ยังไม่เสร็จ
  STATELESS        // ไม่ติดตาม connection state
};

enum class FlowDirection {
  TO_CLIENT,   // ไปยัง client
  TO_SERVER,   // ไปยัง server
  FROM_CLIENT, // มาจาก client
  FROM_SERVER  // มาจาก server
};

enum class StreamMode {
  NO_STREAM,  // ไม่ใช้ stream reassembly
  ONLY_STREAM // ใช้เฉพาะ reassembled stream
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
  std::optional<std::string> method;
  std::optional<std::string> uri;
  std::optional<std::string> raw_uri;
  std::optional<std::string> client_body;

  // Response fields
  std::optional<std::string> status_code;
  std::optional<std::string> status_msg;
  std::optional<std::string> raw_body;

  // Common headers (แยกออกมาเลย)
  std::optional<std::string> host;
  std::optional<std::string> user_agent;
  std::optional<std::string> content_type;
  std::optional<std::string> content_length;
  std::optional<std::string> authorization;
  std::optional<std::string> server;
  std::optional<std::string> powered_by;
  std::optional<std::string> cookie;
  std::optional<std::string> referer;
  std::optional<std::string> origin;
  std::optional<std::string> accept_encoding;

  std::string raw_headers;
  std::string raw_cookie;
};

struct FlowInfo {
  std::optional<FlowState> state;
  std::optional<FlowDirection> direction;
  std::optional<StreamMode> stream_mode;
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

  std::optional<TCPInfo> tcp;
  std::optional<UDPInfo> udp;
  std::optional<ICMPInfo> icmp;
  std::optional<HTTPInfo> http;

  FlowInfo flow;
};

#endif
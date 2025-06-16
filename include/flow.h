#ifndef FLOW_H 
#define FLOW_H
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>

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

enum class FragmentMode { 
  NO_FRAG,
  ONLY_FRAG
};

enum class StreamMode {
  NO_STREAM,  // ไม่ใช้ stream reassembly
  ONLY_STREAM // ใช้เฉพาะ reassembled stream
};

// สำหรับ PacketInfo (per-packet data)
struct FlowInfo {
  std::string flow_key;                     // 5-tuple hash
  std::optional<FlowState> state;           // สำหรับ rule matching
  std::optional<FlowDirection> direction;   // สำหรับ rule matching  
  std::optional<StreamMode> stream_mode;    // สำหรับ rule matching
  std::optional<FragmentMode> frag;         // สำหรับ rule matching
};

// สำหรับ FlowTable (persistent data)
struct FlowEntry {
  std::string flow_key;
  FlowState current_state = FlowState::NOT_ESTABLISHED;
  FlowDirection direction = FlowDirection::TO_SERVER;
  
  std::chrono::system_clock::time_point created_time;
  std::chrono::system_clock::time_point last_seen;
  
  uint64_t packet_count = 0;
  uint64_t byte_count = 0;
  
  // สำหรับ flowbits rules
  std::unordered_map<std::string, bool> flowbits; 
  
  // TCP specific
  uint32_t client_seq = 0;
  uint32_t server_seq = 0;
  bool syn_seen = false;
  bool fin_seen = false;
  bool rst_seen = false;
};

#endif
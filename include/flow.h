#ifndef FLOW_H 
#define FLOW_H
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>

struct PacketInfo;

enum class FlowState {
  ESTABLISHED,
  NOT_ESTABLISHED,
  STATELESS
};

enum class FlowDirection {
  TO_CLIENT,
  TO_SERVER,
};

enum class FragmentMode { 
  NO_FRAG,
  ONLY_FRAG
};

enum class StreamMode {
  NO_STREAM,  
  ONLY_STREAM
};

struct FlowInfo {
  std::string flow_key;
  std::optional<FlowState> state;
  std::optional<FlowDirection> direction; 
  std::optional<StreamMode> stream_mode;
  std::optional<FragmentMode> frag;
};

struct FlowEntry {
  std::string flow_key;
  FlowState current_state = FlowState::NOT_ESTABLISHED;
  std::string client_ip, server_ip;
  uint16_t client_port, server_port;
  std::string protocol;
  
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
  bool shake1 = false;
  bool shake2 = false;
  bool shake3 = false;
};

#endif
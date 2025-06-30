#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include "xxhash.h"
#include "flow.h"
#include "packet.h"
#include "snort_rule.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>

const size_t ARRAY_SIZE = 262144;

inline std::string createFlowKey(PacketInfo *packet) {
  if (!packet)
    return "";

  std::string src = packet->src_addr;
  std::string dst = packet->dst_addr;
  std::string sport = "0", dport = "0";

  try {
    if (packet->tcp.has_value()) {
      sport = packet->tcp->sport;
      dport = packet->tcp->dport;
    } else if (packet->udp.has_value()) {
      sport = packet->udp->sport;
      dport = packet->udp->dport;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error creating flow key: " << e.what() << std::endl;
    return "";
  }

  if (src > dst || (src == dst && sport > dport)) {
    std::swap(src, dst);
    std::swap(sport, dport);
  }

  return src + ":" + sport + "<->" + dst + ":" + dport + ":" + packet->protocol;
}

inline size_t hash1(const std::string &key) {
  return XXH32(key.c_str(), key.length(), 0x12345678) % ARRAY_SIZE;
}

inline size_t hash2(const std::string &key) {
  return XXH32(key.c_str(), key.length(), 0x87654321) % ARRAY_SIZE;
}

inline size_t hash3(const std::string &key) {
  return XXH64(key.c_str(), key.length(), 0xABCDEF01) % ARRAY_SIZE;
}

inline bool bloomContains(const std::string &flow_key,
                          uint16_t bloom_counters[]) {
  return bloom_counters[hash1(flow_key)] > 0 &&
         bloom_counters[hash2(flow_key)] > 0 &&
         bloom_counters[hash3(flow_key)] > 0;
}

inline void bloomAdd(const std::string &flow_key, uint16_t bloom_counters[]) {
  if (bloom_counters[hash1(flow_key)] < UINT16_MAX)
    bloom_counters[hash1(flow_key)]++;
  if (bloom_counters[hash2(flow_key)] < UINT16_MAX)
    bloom_counters[hash2(flow_key)]++;
  if (bloom_counters[hash3(flow_key)] < UINT16_MAX)
    bloom_counters[hash3(flow_key)]++;
}

inline void updateTCPFlow(FlowEntry &flow, PacketInfo *packet) {
  if (packet->tcp->flags.rst) {
    // RST flag - reset connection state
    flow.syn_seen = false;
    flow.shake1 = false;
    flow.shake2 = false;
    flow.shake3 = false;
    flow.rst_seen = true;
    flow.current_state = FlowState::NOT_ESTABLISHED;
    packet->flow.state = FlowState::NOT_ESTABLISHED;
  }
  else if (packet->tcp->flags.syn && !packet->tcp->flags.ack && !flow.shake1) {
    flow.shake1 = true;
    flow.syn_seen = true;
  } 
  else if (packet->tcp->flags.syn && packet->tcp->flags.ack && flow.shake1 && !flow.shake2) {
    flow.shake2 = true;
  } 
  else if (!packet->tcp->flags.syn && packet->tcp->flags.ack && flow.shake1 && flow.shake2 && !flow.shake3) {
    flow.shake3 = true;
    flow.current_state = FlowState::ESTABLISHED;
    packet->flow.state = FlowState::ESTABLISHED;
  }
}

inline void setFlowbit(FlowEntry &flow, const std::string &bit_name,
                       bool value) {
  flow.flowbits[bit_name] = value;
}

inline bool isFlowbitSet(const FlowEntry &flow, const std::string &bit_name) {
  auto it = flow.flowbits.find(bit_name);
  return it != flow.flowbits.end() && it->second;
}

inline void
cleanupExpiredFlows(std::unordered_map<std::string, FlowEntry> &flow_table) {
  auto now = std::chrono::system_clock::now();
  size_t removed = 0;

  for (auto it = flow_table.begin(); it != flow_table.end();) {
    if (now - it->second.last_seen > std::chrono::minutes(5)) {
      it = flow_table.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  if (removed > 0) {
    std::cout << "Cleaned up " << removed << " expired flows" << std::endl;
  }
}

inline void createNewFlow(PacketInfo *packet, const std::string &flow_key,
              const std::string &protocol, const NetworkConfig *conf,
              std::unordered_map<std::string, FlowEntry> &flow_table,
              uint16_t bloom_counters[]) {
  bloomAdd(flow_key, bloom_counters);
  FlowEntry new_flow;

  new_flow.flow_key = flow_key;
  new_flow.created_time = packet->timestamp;
  new_flow.last_seen = packet->timestamp;
  new_flow.packet_count = 1;
  new_flow.protocol = protocol;
  new_flow.flowbits = std::unordered_map<std::string, bool>();

  if (packet->src_addr == *conf->HOME_NET) {
    new_flow.server_ip = packet->src_addr;
    new_flow.client_ip = packet->dst_addr;
  } else {
    new_flow.server_ip = *conf->HOME_NET;
    new_flow.client_ip = packet->src_addr;
  }

  if (protocol == "udp" && packet->udp) {
    new_flow.byte_count = packet->udp->payload_size;
    new_flow.current_state = FlowState::STATELESS;

    if (packet->src_addr == *conf->HOME_NET) {
      new_flow.server_port =
          static_cast<uint16_t>(std::stoi(packet->udp->sport));
      new_flow.client_port =
          static_cast<uint16_t>(std::stoi(packet->udp->dport));
    } else {
      new_flow.client_port =
          static_cast<uint16_t>(std::stoi(packet->udp->sport));
      new_flow.server_port =
          static_cast<uint16_t>(std::stoi(packet->udp->dport));
    }

    packet->flow.state = FlowState::STATELESS;

  } else if (protocol == "icmp" && packet->icmp) {
    new_flow.byte_count = packet->icmp->payload_size;
    new_flow.current_state = FlowState::STATELESS;
    new_flow.client_port = 0;
    new_flow.server_port = 0;

    packet->flow.state = FlowState::STATELESS;

  } else if ((protocol == "tcp" || protocol == "http") && packet->tcp) {
    new_flow.byte_count = packet->tcp->payload_size;
    new_flow.current_state = FlowState::NOT_ESTABLISHED;

    if (packet->src_addr == *conf->HOME_NET) {
      new_flow.server_port =
          static_cast<uint16_t>(std::stoi(packet->tcp->sport));
      new_flow.client_port =
          static_cast<uint16_t>(std::stoi(packet->tcp->dport));
    } else {
      new_flow.client_port =
          static_cast<uint16_t>(std::stoi(packet->tcp->sport));
      new_flow.server_port =
          static_cast<uint16_t>(std::stoi(packet->tcp->dport));
    }

    if (packet->tcp->flags.syn && !packet->tcp->flags.ack) {
      new_flow.shake1 = true;
      new_flow.syn_seen = true;
    }

    packet->flow.state = FlowState::NOT_ESTABLISHED;
  }

  flow_table[flow_key] = new_flow;
}

inline void flowIdentication(PacketInfo *packet, const NetworkConfig *conf,
                 std::unordered_map<std::string, FlowEntry> &flow_table,
                 uint16_t bloom_counters[]) {
  std::string flow_key = createFlowKey(packet);
  if (flow_key.empty())
    return;

  packet->flow.flow_key = flow_key;

  if (bloomContains(flow_key, bloom_counters)) {
    auto flow_map = flow_table.find(flow_key);
    if (flow_map != flow_table.end()) {
      flow_map->second.last_seen = packet->timestamp;
      flow_map->second.packet_count++;
      flow_map->second.byte_count += packet->tcp    ? packet->tcp->payload_size
                                     : packet->udp  ? packet->udp->payload_size
                                     : packet->icmp ? packet->icmp->payload_size
                                                    : 0;

      if (flow_map->second.protocol == "tcp" && packet->tcp) {
        updateTCPFlow(flow_map->second, packet);

        if (packet->tcp->flags.fin || packet->tcp->flags.rst) {
          flow_map->second.current_state = FlowState::NOT_ESTABLISHED;
          if (packet->tcp->flags.fin)
            flow_map->second.fin_seen = true;
          if (packet->tcp->flags.rst)
            flow_map->second.rst_seen = true;
        }

        if (packet->flow.direction == FlowDirection::TO_SERVER) {
          if (flow_map->second.client_seq == 0) {
            flow_map->second.client_seq = std::stoul(packet->tcp->seq);
          }
        } else {
          if (flow_map->second.server_seq == 0) {
            flow_map->second.server_seq = std::stoul(packet->tcp->seq);
          }
        }
      }

      packet->flow.state = flow_map->second.current_state;
    } else {
      createNewFlow(packet, flow_key, packet->protocol, conf, flow_table,
                    bloom_counters);
    }
  } else {
    createNewFlow(packet, flow_key, packet->protocol, conf, flow_table,
                  bloom_counters);
  }
}

#endif
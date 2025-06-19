#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/filter.h"
#include "./include/flow.h"
#include "./include/packet.h"
#include "./include/snort_rule.h"
#include "./include/snort_rule_parser.h"

#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <tins/tins.h>
#include <vector>
#include <xxhash.h>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;

const size_t ARRAY_SIZE = 262144;

// Forward declarations
void sniff(const string &iface, auto &conf);
void flowIdentication(PacketInfo *packet, const NetworkConfig *conf,
                     unordered_map<string, FlowEntry> &flow_table,
                     uint16_t bloom_counters[]);
void createNewFlow(PacketInfo *packet, const string &flow_key,
                   const string &protocol, const NetworkConfig *conf,
                   unordered_map<string, FlowEntry> &flow_table,
                   uint16_t bloom_counters[]);
string createFlowKey(PacketInfo *packet);

// Bloom filter functions
size_t hash1(const string &key);
size_t hash2(const string &key);
size_t hash3(const string &key);
bool bloomContains(const string &flow_key, uint16_t bloom_counters[]);
void bloomAdd(const string &flow_key, uint16_t bloom_counters[]);

// Flow management functions
void updateTCPFlow(FlowEntry &flow, PacketInfo *packet);
void setFlowbit(FlowEntry& flow, const std::string& bit_name, bool value);
bool isFlowbitSet(const FlowEntry& flow, const std::string& bit_name);
void cleanupExpiredFlows(unordered_map<string, FlowEntry> &flow_table);

int main() {
  vector<string> interface = getInterfaceName();
  thread_pool pool(interface.size());
  vector<future<void>> task;

  for (const string &iface : interface) {
    NetworkConfig conf;
    conf.HOME_NET = getIpInterface(iface);
    conf.EXTERNAL_NET = "!" + *conf.HOME_NET;

    cout << "Choose Your services for " << iface << " interface." << endl;
    cout << "HTTP Service ? [y/n]" << endl;
    char yesno;
    cin >> yesno;
    if (yesno == 'y' || yesno == 'Y') {
      conf.HTTP_SERVERS = true;
      yesno = '\0';
    } else {
      conf.HTTP_SERVERS = false;
    }
    cout << "SMTP Service ? [y/n]" << endl;
    cin >> yesno;
    if (yesno == 'y' || yesno == 'Y') {
      conf.SMTP_SERVERS = true;
      yesno = '\0';
    } else {
      conf.SMTP_SERVERS = false;
    }
    cout << "SQL Service ? [y/n]" << endl;
    cin >> yesno;
    if (yesno == 'y' || yesno == 'Y') {
      conf.SQL_SERVERS = true;
      yesno = '\0';
    } else {
      conf.SQL_SERVERS = false;
    }
    cout << "TELNET Service ? [y/n]" << endl;
    cin >> yesno;
    if (yesno == 'y' || yesno == 'Y') {
      conf.TELNET_SERVERS = true;
      yesno = '\0';
    } else {
      conf.TELNET_SERVERS = false;
    }
    cout << "SIP Service ? [y/n]" << endl;
    cin >> yesno;
    if (yesno == 'y' || yesno == 'Y') {
      conf.SIP_SERVERS = true;
      yesno = '\0';
    } else {
      conf.SIP_SERVERS = false;
    }
    task.push_back(pool.submit_task([iface, conf]() { sniff(iface, conf); }));
  }
  
  // Wait for all tasks to complete
  for (auto &t : task) {
    t.wait();
  }
  
  return 0;
}

void sniff(const string &iface, auto &conf) {
  unordered_map<string, FlowEntry> flow_table;
  uint16_t bloom_counters[ARRAY_SIZE] = {0};
  uint64_t total_packets = 0;
  uint64_t total_flows = 0;
  auto last_cleanup = chrono::system_clock::now();
  
  // Log
  string currentDay = currentDate();
  string currentPath = getPath();
  filesystem::create_directories(currentPath);
  auto writer = make_unique<PacketWriter>(currentPath + iface + "-" +
                                              currentDay + ".pcap",
                                          DataLinkType<EthernetII>());

  // Config
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(iface, config);
  sniffer.sniff_loop([&](Packet &pkt) {
        total_packets++;
        
        // Check Flow Time Expire
        auto now = chrono::system_clock::now();
        if (now - last_cleanup > chrono::minutes(1)) {
          cleanupExpiredFlows(flow_table);
          last_cleanup = now;
        }
        
        // Write logs
        string date = currentDate();
        string path = getPath();
        if (currentDay != date) {
          currentDay = date;
          currentPath = path;
          filesystem::create_directories(currentPath);
          writer = make_unique<PacketWriter>(currentPath + iface + "-" +
                                                 currentDay + ".pcap",
                                             DataLinkType<EthernetII>());
        }
        writer->write(pkt);

        // Filter
        PDU *pdu = pkt.pdu();
        if (pdu->find_pdu<IP>()) {
          IP &ip = pdu->rfind_pdu<IP>();
          PacketInfo packet;
          packet.protocol = "ip";
          IPFilter(&packet, ip);
          if (packet.src_addr == *conf.HOME_NET &&
              packet.dst_addr != *conf.HOME_NET) {
            packet.flow.direction = FlowDirection::TO_CLIENT;
          } else {
            packet.flow.direction = FlowDirection::TO_SERVER;
          }
          
          if (pdu->find_pdu<TCP>()) {
            TCP &tcp = pdu->rfind_pdu<TCP>();
            packet.protocol = "tcp";
            packet.tcp.emplace();
            TCPFilter(&packet, tcp);
            
            if (packet.tcp->payload_size > 0) {
              packet.flow.stream_mode = StreamMode::ONLY_STREAM;
            } else {
              packet.flow.stream_mode = StreamMode::NO_STREAM;
            }
            
            if (tcp.sport() == 80 || tcp.dport() == 80 || 
                tcp.sport() == 8080 || tcp.dport() == 8080 ||
                tcp.sport() == 443 || tcp.dport() == 443) {
              packet.protocol = "http";
              packet.http.emplace();
              HTTPFilter(&packet, tcp);
            }
          } else if (pdu->find_pdu<UDP>()) {
            UDP &udp = pdu->rfind_pdu<UDP>();
            packet.protocol = "udp";
            packet.udp.emplace();
            UDPFilter(&packet, udp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
          } else if (pdu->find_pdu<ICMP>()) {
            ICMP &icmp = pdu->rfind_pdu<ICMP>();
            packet.protocol = "icmp";
            packet.icmp.emplace();
            ICMPFilter(&packet, icmp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
          }
          
          // Flow
          size_t flows_before = flow_table.size();
          flowIdentication(&packet, &conf, flow_table, bloom_counters);
          if (flow_table.size() > flows_before) {
            total_flows++;
          }
        }
        return true;
      });
}

string createFlowKey(PacketInfo *packet) {
  if (!packet) return "";
  
  string src = packet->src_addr;
  string dst = packet->dst_addr;
  string sport = "0", dport = "0";

  try {
    if (packet->tcp.has_value()) {
      sport = packet->tcp->sport;
      dport = packet->tcp->dport;
    } else if (packet->udp.has_value()) {
      sport = packet->udp->sport;
      dport = packet->udp->dport;
    }
  } catch (const std::exception& e) {
    cerr << "Error creating flow key: " << e.what() << endl;
    return "";
  }

  if (src > dst || (src == dst && sport > dport)) {
    swap(src, dst);
    swap(sport, dport);
  }

  return src + ":" + sport + "<->" + dst + ":" + dport + ":" + packet->protocol;
}

size_t hash1(const string &key) {
  return XXH32(key.c_str(), key.length(), 0x12345678) % ARRAY_SIZE;
}

size_t hash2(const string &key) {
  return XXH32(key.c_str(), key.length(), 0x87654321) % ARRAY_SIZE;
}

size_t hash3(const string &key) {
  return XXH64(key.c_str(), key.length(), 0xABCDEF01) % ARRAY_SIZE;
}

bool bloomContains(const string &flow_key, uint16_t bloom_counters[]) {
  return bloom_counters[hash1(flow_key)] > 0 &&
         bloom_counters[hash2(flow_key)] > 0 &&
         bloom_counters[hash3(flow_key)] > 0;
}

void bloomAdd(const string &flow_key, uint16_t bloom_counters[]) {
  if (bloom_counters[hash1(flow_key)] < UINT16_MAX)
    bloom_counters[hash1(flow_key)]++;
  if (bloom_counters[hash2(flow_key)] < UINT16_MAX)
    bloom_counters[hash2(flow_key)]++;
  if (bloom_counters[hash3(flow_key)] < UINT16_MAX)
    bloom_counters[hash3(flow_key)]++;
}

void updateTCPFlow(FlowEntry &flow, PacketInfo *packet) {
  if (packet->tcp->flags.syn && !packet->tcp->flags.ack && !flow.shake1) {
    flow.shake1 = true;
    flow.syn_seen = true;
  }
  else if (packet->tcp->flags.syn && packet->tcp->flags.ack && flow.shake1 &&
           !flow.shake2) {
    flow.shake2 = true;
  }
  else if (!packet->tcp->flags.syn && packet->tcp->flags.ack && flow.shake1 &&
           flow.shake2 && !flow.shake3) {
    flow.shake3 = true;
    flow.current_state = FlowState::ESTABLISHED;
    packet->flow.state = FlowState::ESTABLISHED;
  }
}

void setFlowbit(FlowEntry& flow, const std::string& bit_name, bool value) {
    flow.flowbits[bit_name] = value;
}

bool isFlowbitSet(const FlowEntry& flow, const std::string& bit_name) {
    auto it = flow.flowbits.find(bit_name);
    return it != flow.flowbits.end() && it->second;
}

void cleanupExpiredFlows(unordered_map<string, FlowEntry> &flow_table) {
    auto now = chrono::system_clock::now();
    size_t removed = 0;
    
    for (auto it = flow_table.begin(); it != flow_table.end();) {
        // Remove flows older than 5 minutes
        if (now - it->second.last_seen > chrono::minutes(5)) {
            it = flow_table.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0) {
        cout << "Cleaned up " << removed << " expired flows" << endl;
    }
}

void flowIdentication(PacketInfo *packet, const NetworkConfig *conf,
                     unordered_map<string, FlowEntry> &flow_table,
                     uint16_t bloom_counters[]) {
  string flow_key = createFlowKey(packet);
  if (flow_key.empty()) return;
  
  packet->flow.flow_key = flow_key;

  if (bloomContains(flow_key, bloom_counters)) {
    auto flow_map = flow_table.find(flow_key);
    if (flow_map != flow_table.end()) {
      flow_map->second.last_seen = packet->timestamp;
      flow_map->second.packet_count++;
      flow_map->second.byte_count += packet->tcp   ? packet->tcp->payload_size
                                     : packet->udp ? packet->udp->payload_size
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
            flow_map->second.client_seq = stoul(packet->tcp->seq);
          }
        } else {
          if (flow_map->second.server_seq == 0) {
            flow_map->second.server_seq = stoul(packet->tcp->seq);
          }
        }
      }

      packet->flow.state = flow_map->second.current_state;
    } else {
      createNewFlow(packet, flow_key, packet->protocol, conf, flow_table, bloom_counters);
    }
  } else {
    createNewFlow(packet, flow_key, packet->protocol, conf, flow_table, bloom_counters);
  }
}

void createNewFlow(PacketInfo *packet, const string &flow_key,
                   const string &protocol, const NetworkConfig *conf,
                   unordered_map<string, FlowEntry> &flow_table,
                   uint16_t bloom_counters[]) {
  bloomAdd(flow_key, bloom_counters);
  FlowEntry new_flow;
  
  new_flow.flow_key = flow_key;
  new_flow.created_time = packet->timestamp;
  new_flow.last_seen = packet->timestamp;
  new_flow.packet_count = 1;
  new_flow.protocol = protocol;
  new_flow.flowbits = unordered_map<string, bool>();
  
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
      new_flow.server_port = static_cast<uint16_t>(stoi(packet->udp->sport));
      new_flow.client_port = static_cast<uint16_t>(stoi(packet->udp->dport));
    } else {
      new_flow.client_port = static_cast<uint16_t>(stoi(packet->udp->sport));
      new_flow.server_port = static_cast<uint16_t>(stoi(packet->udp->dport));
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
      new_flow.server_port = static_cast<uint16_t>(stoi(packet->tcp->sport));
      new_flow.client_port = static_cast<uint16_t>(stoi(packet->tcp->dport));
    } else {
      new_flow.client_port = static_cast<uint16_t>(stoi(packet->tcp->sport));
      new_flow.server_port = static_cast<uint16_t>(stoi(packet->tcp->dport));
    }

    if (packet->tcp->flags.syn && !packet->tcp->flags.ack) {
      new_flow.shake1 = true;
      new_flow.syn_seen = true;
    }
    
    packet->flow.state = FlowState::NOT_ESTABLISHED;
  }

  flow_table[flow_key] = new_flow;
}
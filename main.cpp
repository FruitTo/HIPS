#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/filter.h"
#include "./include/flow_manager.h"
#include "./include/packet.h"
#include "./include/snort_rule.h"
#include "./include/snort_rule_parser.h"
#include "./include/header_detection.h"
#include "./include/tins/tins.h"

#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;

// Pre Declaratrion.
void sniff(const string &iface, auto &conf);

// Global Object MAP -> VECTOR -> Rule-Object
auto rules = SnortRuleParser::parseRulesFromFile("./rule/snort3-community.rules");

int main() {
  vector<string> interfaceName = getInterfaceName();
  thread_pool pool(interfaceName.size());
  vector<future<void>> task;

  // Runing separate interface.
  for (const string &iface : interfaceName) {
    // Config of the current interface.
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
  auto writer = make_unique<PacketWriter>(currentPath + iface + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());

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
          writer = make_unique<PacketWriter>(currentPath + iface + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());
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
            
            // HTTP Detection
            if (tcp.sport() == 80 || tcp.dport() == 80 || 
                tcp.sport() == 8080 || tcp.dport() == 8080 ||
                tcp.sport() == 443 || tcp.dport() == 443) {
              packet.protocol = "http";
              packet.http.emplace();
              HTTPFilter(&packet, tcp);
            }
            
            // SSL/TLS Detection
            if (tcp.sport() == 443 || tcp.dport() == 443) {
              packet.ssl.emplace();
              SSLFilter(&packet, tcp);
            }
            
            // FTP Detection
            if (tcp.sport() == 21 || tcp.dport() == 21 || 
                tcp.sport() == 2021 || tcp.dport() == 2021) {
              packet.protocol = "ftp";
              packet.ftp.emplace();
              FTPFilter(&packet, tcp);
            }
            
            // SMTP Detection
            if (tcp.sport() == 25 || tcp.dport() == 25 ||
                tcp.sport() == 587 || tcp.dport() == 587 ||
                tcp.sport() == 465 || tcp.dport() == 465) {
              packet.protocol = "smtp";
              packet.smtp.emplace();
              SMTPFilter(&packet, tcp);
            }
            
            // DCE/RPC Detection
            if (tcp.sport() == 135 || tcp.dport() == 135) {
              packet.dce.emplace();
              DCEFilter(&packet, tcp);
            }
            
          } else if (pdu->find_pdu<UDP>()) {
            UDP &udp = pdu->rfind_pdu<UDP>();
            packet.protocol = "udp";
            packet.udp.emplace();
            UDPFilter(&packet, udp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
            
            // SIP Detection
            if (udp.sport() == 5060 || udp.dport() == 5060) {
              packet.protocol = "sip";
              packet.sip.emplace();
              SIPFilter(&packet, udp);
            }
            
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

          // Detection
          if(headerDetection(packet, rules, conf)){
            cout << "SRC:" << packet.src_addr << '\t' << endl;
          }
        }
        return true;
      });
}
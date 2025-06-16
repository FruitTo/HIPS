#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/filter.h"
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

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;

void sniff(const string &iface, auto &conf) {
  // Config
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(iface, config);

  // Logs
  string currentDay = currentDate();
  string currentPath = getPath();
  filesystem::create_directories(currentPath);
  // Auto remove when it out of scope.
  auto writer = make_unique<PacketWriter>(currentPath + iface + "-" +
                                              currentDay + ".pcap",
                                          DataLinkType<EthernetII>());

  cout << *conf.HOME_NET << endl;
  sniffer.sniff_loop([&writer, iface, &currentDay, &currentPath](Packet &pkt) {
    // Write logs.
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
      if (pdu->find_pdu<TCP>()) {
        TCP &tcp = pdu->rfind_pdu<TCP>();
        packet.protocol = "tcp";
        packet.tcp.emplace();
        TCPFilter(&packet, tcp);
        if (tcp.sport() == 80 || tcp.dport() == 80 || tcp.sport() == 8080 ||
            tcp.dport() == 8080) {
          packet.protocol = "http";
          packet.http.emplace();
          HTTPFilter(&packet, tcp);
        }
      } else if (pdu->find_pdu<UDP>()) {
        UDP &udp = pdu->rfind_pdu<UDP>();
        packet.protocol = "udp";
        packet.udp.emplace();
        UDPFilter(&packet, udp);
      } else if (pdu->find_pdu<ICMP>()) {
        ICMP &icmp = pdu->rfind_pdu<ICMP>();
        packet.protocol = "icmp";
        packet.icmp.emplace();
        ICMPFilter(&packet, icmp);
      }

      // if(packet.tcp && packet.tcp->payload_size > 0){
      //     cout << " TCP Payload:" << packet.tcp->payload_size << " bytes" <<
      //     endl;
      // }
      // if(packet.udp && packet.udp->payload_size > 0){
      //     cout << " UDP Payload:" << packet.udp->payload_size << " bytes" <<
      //     endl;
      // }
      // if(packet.icmp && packet.icmp->payload_size > 0){
      //     cout << " ICMP Payload:" << packet.icmp->payload_size << " bytes"
      //     << endl;
      // }
    }
    return true;
  });
}

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
    task.push_back(pool.submit_task([iface, conf]() { sniff(iface, conf); }));
  }
  return 0;
}
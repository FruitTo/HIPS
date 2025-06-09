#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/snort_rule_parser.h"
#include "./include/snort_rule.h"
#include "./include/date.h"
#include "./include/packet.h"

#include <string>
#include <future>
#include <iostream>
#include <tins/tins.h>
#include <vector>
#include <filesystem>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;

void sniff(const string &iface, auto &conf)
{
    // Config
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(iface, config);

    // Logs
    string currentDay = currentDate();
    string currentPath = getPath();
    filesystem::create_directories(currentPath);
    // Auto remove when it out of scope.
    auto writer = make_unique<PacketWriter>(currentPath + iface + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());

    cout << *conf.HOME_NET << endl;
    sniffer.sniff_loop([&writer, iface, &currentDay, &currentPath](Packet &pkt){
        // Write logs.
        string date = currentDate();
        string path = getPath();
        if(currentDay != date){
            currentDay = date;
            currentPath = path;
            filesystem::create_directories(currentPath);
            writer = make_unique<PacketWriter>
            (
                currentPath + iface + "-" + currentDay + ".pcap",
                DataLinkType<EthernetII>()
            );
        }
        writer->write(pkt);

        // Filter
        PDU *pdu = pkt.pdu();
        if (pdu->find_pdu<IP>()) {
            IP &ip = pdu->rfind_pdu<IP>();
            PacketInfo packet;
            packet.protocol = "ip";
            packet.id = ip.id();
            packet.ttl = (int)ip.ttl();
            packet.src_addr = ip.src_addr().to_string();
            packet.dst_addr = ip.dst_addr().to_string();
            if(ip.flags() & IP::DONT_FRAGMENT){
                packet.dont_fragment = true;
            }
            if(ip.flags() & IP::MORE_FRAGMENTS){
                packet.more_fragments = true;
            }
            if(ip.flags() & 0x8000){
                packet.reserved = true;
            }

            if (pdu->find_pdu<TCP>()) {
                TCP &tcp = pdu->rfind_pdu<TCP>();
                packet.protocol = "tcp";
                packet.tcp.emplace();
                packet.tcp->sport = tcp.sport();
                packet.tcp->dport = tcp.dport();
                packet.tcp->seq = tcp.seq();
                packet.tcp->ack_seq = tcp.ack_seq();
                packet.tcp->flags.fin = tcp.get_flag(TCP::Flags::FIN);
                packet.tcp->flags.syn = tcp.get_flag(TCP::Flags::SYN);
                packet.tcp->flags.rst = tcp.get_flag(TCP::Flags::RST);
                packet.tcp->flags.psh = tcp.get_flag(TCP::Flags::PSH);
                packet.tcp->flags.ack = tcp.get_flag(TCP::Flags::ACK);
                packet.tcp->flags.urg = tcp.get_flag(TCP::Flags::URG);
                packet.tcp->flags.ece = tcp.get_flag(TCP::Flags::ECE);
                packet.tcp->flags.cwr = tcp.get_flag(TCP::Flags::CWR);

                if(tcp.sport() == 80 || tcp.dport() == 80 || 
                    tcp.sport() == 8080 || tcp.dport() == 8080) {
                    packet.protocol = "http";
                }
            } else if (pdu->find_pdu<UDP>()) {
                UDP &udp = pdu->rfind_pdu<UDP>();
                packet.protocol = "udp";
                if(udp.sport() == 53 || udp.dport() == 53) {
                    packet.protocol = "dns";
                }
            } else if (pdu->find_pdu<ICMP>()) {
                    packet.protocol = "icmp";
            }
            cout << "[" << iface << "] ";
            cout << "Protocol: " << packet.protocol << " SRC: " << packet.src_addr << " DST: " << packet.dst_addr << endl;
        } 
        return true; 
    });
}

int main()
{
    vector<string> interface = getInterfaceName();
    thread_pool pool(interface.size());

    vector<future<void>> task;
    for (const string &iface : interface)
    {
        NetworkConfig conf;
        conf.HOME_NET = getIpInterface(iface);
        cout << *conf.HOME_NET << endl;
        conf.EXTERNAL_NET = "!" + *conf.HOME_NET;
        cout << "Choose Your services for " << iface << " interface." << endl;
        cout << "HTTP Service ? y/n" << endl;
        char yesno;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y'){
            conf.HTTP_SERVERS = true;
            yesno = '\0';
        } else {
            conf.HTTP_SERVERS = false;
        }
        cout << "SMTP Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y'){
            conf.SMTP_SERVERS = true;
            yesno = '\0';
        } else {
            conf.SMTP_SERVERS = false;
        }
        cout << "SQL Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y'){
            conf.SQL_SERVERS = true;
            yesno = '\0';
        } else {
            conf.SQL_SERVERS = false;
        }
        cout << "TELNET Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y'){
            conf.TELNET_SERVERS = true;
            yesno = '\0';
        } else {
            conf.TELNET_SERVERS = false;
        }
        task.push_back(pool.submit_task([iface, conf](){ sniff(iface, conf); }));
    }
    return 0;
}
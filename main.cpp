#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/snort_rule_parser.h"
#include "./include/snort_rule.h"
#include "./include/date.h"

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

void sniff(const string &iface,auto &conf)
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

    sniffer.sniff_loop([&writer, iface, &currentDay, &currentPath](Packet &pkt)
                       {
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
        IP &ip = pdu->rfind_pdu<IP>();
        TCP &tcp = pdu->rfind_pdu<TCP>();
        string protocol;
        if (pdu->find_pdu<IP>()) {
            protocol = "ip";
            Rule packet;
            packet.protocol = protocol;
            if (pdu->find_pdu<TCP>()) {
                protocol = "tcp";
                if(tcp.sport() == 80 || tcp.dport() == 80 || tcp.sport() == 8080 || tcp.dport() == 8080){
                    protocol = "http";
                }
            } else if (pdu->find_pdu<UDP>()) {
                protocol = "udp";
            } else if (pdu->find_pdu<ICMP>()) {
                protocol = "icmp";
            }  
        } 

        // Flow
        cout << "[" << iface << "] ";
        cout << "Protocol: " << protocol << " SRC: " << ip.src_addr() << " DST: " << ip.dst_addr() << endl;
        return true; });
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
        if (yesno == 'y' || yesno == 'Y')
        {
            conf.HTTP_SERVERS = true;
            yesno = '\0';
        }
        else
        {
            conf.HTTP_SERVERS = false;
        }
        cout << "SMTP Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y')
        {
            conf.SMTP_SERVERS = true;
            yesno = '\0';
        }
        else
        {
            conf.SMTP_SERVERS = false;
        }
        cout << "SQL Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y')
        {
            conf.SQL_SERVERS = true;
            yesno = '\0';
        }
        else
        {
            conf.SQL_SERVERS = false;
        }
        cout << "TELNET Service ? y/n" << endl;
        cin >> yesno;
        if (yesno == 'y' || yesno == 'Y')
        {
            conf.TELNET_SERVERS = true;
            yesno = '\0';
        }
        else
        {
            conf.TELNET_SERVERS = false;
        }
        task.push_back(pool.submit_task([iface,conf]()
                                        { sniff(iface,conf); }));
    }

    return 0;
}
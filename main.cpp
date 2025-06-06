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

void sniff(const string &iface)
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(iface, config);

    string currentDay = currentDate();
    string currentPath = getPath();

    filesystem::create_directories(currentPath);
    // Auto remove when it out of scope.
    auto writer = make_unique<PacketWriter>( currentPath + iface + "-" + currentDay + ".pcap", DataLinkType<EthernetII>()); 

    sniffer.sniff_loop([&writer,iface,&currentDay,&currentPath](Packet &pkt)
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

        // Flow
        cout << "[" << iface << "] ";
        cout << "SRC: " << ip.src_addr() << " DST: " << ip.dst_addr() << endl;
        return true; 
    });
}

int main()
{
    vector<string> interface = getInterface();
    thread_pool pool(interface.size());

    vector<future<void>> task;
    for (const string &iface : interface)
    {
        task.push_back(pool.submit_task([iface](){ sniff(iface); }));
    }

    return 0;
}
#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/snort_rule.h"
#include <string>
#include <future>
#include <iostream>
#include <tins/tins.h>
#include <vector>
#include <json/json.h>
#include <sstream>
#include <chrono>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;

void sniff(const string &iface,Json::Value rules)
{
    cout << rules[0]["header"].asString() << endl;
    cout << rules.size() << endl;

    // Filter
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(iface, config);

    sniffer.sniff_loop([iface](Packet &pkt){
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
    Json::Value rules = readRule();

    vector<string> interface = getInterface();
    thread_pool pool(interface.size());

    vector<future<void>> task;
    for(const string &iface: interface){
        task.push_back(pool.submit_task([iface,rules]() {
            sniff(iface,rules);
        }));
    }

    return 0;
}
#include <iostream>
#include <tins/tins.h>
#include <vector>
#include <string>
#include <bitset>

using namespace std;
using namespace Tins;

int main()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniff("enp2s0", config);
    sniff.sniff_loop([](PDU &pdu) -> bool {
        
        if (pdu.find_pdu<IP>()) {
            IP& ip = pdu.rfind_pdu<IP>();
            
            cout << "=== IP Header Information ===" << endl;
            
            cout << "Version: " << (int)ip.version() << endl;

            cout << "IHL (Header Length): " << (int)ip.header_size() << " bytes" << endl;
            cout << "IHL Value: " << (int)(ip.header_size() / 4) << " (4-byte words)" << endl;
            
            cout << "Type of Service (ToS): " << (int)ip.tos() << endl;
            cout << "ToS Binary: " << bitset<8>(ip.tos()) << endl;
            
            cout << "Total Length: " << ip.tot_len() << " bytes" << endl;
            
            cout << "Identification: " << ip.id() << endl;
            cout << "ID Hex: 0x" << hex << ip.id() << dec << endl;
            
            cout << "Flags:" << endl;
            cout << "  Don't Fragment (DF): " << (ip.flags() & IP::DONT_FRAGMENT ? "Set" : "Not Set") << endl;
            cout << "  More Fragments (MF): " << (ip.flags() & IP::MORE_FRAGMENTS ? "Set" : "Not Set") << endl;
            cout << "  Reserved: " << (ip.flags() & 0x8000 ? "Set" : "Not Set") << endl;
            cout << "  Flags Value: " << (int)ip.flags() << endl;
            
            cout << "Fragment Offset: " << ip.fragment_offset() << " (8-byte blocks)" << endl;
            cout << "Fragment Offset Bytes: " << (ip.fragment_offset() * 8) << " bytes" << endl;
            
            cout << "TTL (Time to Live): " << (int)ip.ttl() << endl;
            
            cout << "Protocol: " << (int)ip.protocol() << endl;
            cout << "Protocol Name: ";
            switch(ip.protocol()) {
                case IPPROTO_ICMP: cout << "ICMP (1)"; break;
                case IPPROTO_TCP:  cout << "TCP (6)"; break;
                case IPPROTO_UDP:  cout << "UDP (17)"; break;
                default: cout << "Other (" << (int)ip.protocol() << ")"; break;
            }
            cout << endl;
            
            cout << "Header Checksum: " << ip.checksum() << endl;
            cout << "Checksum Hex: 0x" << hex << ip.checksum() << dec << endl;
            
            cout << "Source IP: " << ip.src_addr() << endl;
            cout << "Source IP Hex: 0x" << hex << ip.src_addr() << dec << endl;
            
            cout << "Destination IP: " << ip.dst_addr() << endl;
            cout << "Destination IP Hex: 0x" << hex << ip.dst_addr() << dec << endl;
            cout << "=================================" << endl;
        }
        return true;
    }); 
    
    return 0;
}
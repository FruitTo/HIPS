#include <iostream>
#include <tins/tins.h>
using namespace Tins;
using namespace std;

bool analyze_tcp_packet(const PDU& pdu) {
    try {
        const IP& ip = pdu.rfind_pdu<IP>();
        const TCP& tcp = pdu.rfind_pdu<TCP>();
        
        cout << "=== TCP Header Analysis ===" << endl;
        
        // 1. Source และ Destination Ports
        cout << "Source Port: " << tcp.sport() << endl;
        cout << "Destination Port: " << tcp.dport() << endl;
        
        // 2. Sequence และ Acknowledgment Numbers
        cout << "Sequence Number: " << tcp.seq() << endl;
        cout << "Acknowledgment Number: " << tcp.ack_seq() << endl;
        
        // 3. Window Size
        cout << "Window Size: " << tcp.window() << endl;
        
        // 4. Checksum
        cout << "Checksum: 0x" << hex << tcp.checksum() << dec << endl;
        
        // 5. Urgent Pointer
        cout << "Urgent Pointer: " << tcp.urg_ptr() << endl;
        
        // 6. Data Offset/Header Length
        cout << "Data Offset: " << tcp.data_offset() << endl;
        
        return true;
    }
    catch (const pdu_not_found&) {
        // ไม่ใช่ TCP packet
        return true;
    }
}
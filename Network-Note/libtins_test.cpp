#include <iostream>
#include <tins/tins.h>
#include <vector>
#include <string>
using namespace std;
using namespace Tins;

int main() {
    vector<NetworkInterface> iface = NetworkInterface::all();
    for(const auto& i : iface){
        cout << "Interface: " << i.name() << endl;
        IPv4Address ip = i.ipv4_address();
        cout << "IP: " << ip.to_string() << endl;
    }

    return 0;
}
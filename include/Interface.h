#ifndef INTERFACE_H
#define INTERFACE_H

#include <iostream>
#include <vector>
#include <string>
#include <tins/tins.h>
#include <sstream>
using namespace std;
using namespace Tins;

vector<string> getInterface(){
    vector<string> interface;
    vector<NetworkInterface> iface = NetworkInterface::all();

    cout << "Your interface :";

    for(const auto& i : iface){
        cout << " " + i.name();
    }
    cout << endl << "Select your interface : ";
    string input;
    string word;
    getline(cin, input);
    istringstream iss(input);
    while(iss >> word){
        interface.push_back(word);
    }
    return interface;
}

#endif
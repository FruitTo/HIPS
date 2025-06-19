#include <iostream>
#include <string>
#include <iomanip>
#include <xxhash.h>

int main() {
    std::string data = "Hello xxHash from Fedora!";
    
    // Test xxHash32
    uint32_t hash32 = XXH32(data.c_str(), data.length(), 0);
    
    std::cout << hash32 << std::endl;
    return 0;
}
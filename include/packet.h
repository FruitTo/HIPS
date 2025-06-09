#ifndef PACKET_H
#define PACKET_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

enum class FlowState {
    ESTABLISHED,        // TCP connection established
    NOT_ESTABLISHED,    // TCP handshake ยังไม่เสร็จ
    STATELESS          // ไม่ติดตาม connection state
};

enum class FlowDirection {
    TO_CLIENT,         // ไปยัง client
    TO_SERVER,         // ไปยัง server  
    FROM_CLIENT,       // มาจาก client
    FROM_SERVER        // มาจาก server
};

enum class StreamMode {
    NO_STREAM,         // ไม่ใช้ stream reassembly
    ONLY_STREAM        // ใช้เฉพาะ reassembled stream
};

struct TCPFlags {
    bool fin = false;    // F - Finish
    bool syn = false;    // S - Synchronize  
    bool rst = false;    // R - Reset
    bool psh = false;    // P - Push
    bool ack = false;    // A - Acknowledgment
    bool urg = false;    // U - Urgent
    bool ece = false;    // E - ECN-Echo
    bool cwr = false;    // C - Congestion Window Reduced
};

struct TCP {
    TCPFlags flags;
    std::string sport;
    std::string dport;
    std::string seq;
    std::string ack_seq;
};

struct FlowInfo {
    std::optional<FlowState> state;
    std::optional<FlowDirection> direction;
    std::optional<StreamMode> stream_mode;
};

struct PacketInfo { 
    std::string id;
    int ttl;
    bool more_fragments = false;        // M
    bool dont_fragment = false;         // D
    bool reserved = false;              // R
    std::string protocol;
    std::string src_addr;
    std::string dst_addr;
    
    std::optional<TCP> tcp;
    
    FlowInfo flow;
};

#endif
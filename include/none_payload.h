#ifndef NONE_PAYLOAD_H
#define NONE_PAYLOAD_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "./dto.h"
#include <variant>

struct TTL
{
    Operator op;
    uint8_t min_value;
    std::optional<uint8_t> max_value;
};

struct ID
{
    Operator op;
    uint16_t min_value;
    std::optional<uint16_t> max_value;
};

struct FragbitsOption
{
    enum class Modifier
    {
        EXACT, // fragbits:M; (exact match)
        PLUS,  // fragbits:+MD; (specified + any others)
        ANY,   // fragbits:*MD; (any of specified)
        NOT    // fragbits:!D; (specified bits not set)
    } modifier = Modifier::EXACT;

    // Fragment bits
    bool more_fragments = false; // M
    bool dont_fragment = false;  // D
    bool reserved = false;       // R
};

struct IPProtoOption
{
    Operator op = Operator::EQUAL;
    std::variant<uint8_t, std::string> protocol;
};

struct TCPFlags
{
    enum class Modifier
    {
        EXACT, // flags:SA; (exact match - เฉพาะ flags ที่ระบุ)
        PLUS,  // flags:+SA; (flags ที่ระบุ + อื่นๆ ได้)
        ANY,   // flags:*SA; (มี flags ใดๆ ที่ระบุ)
        NOT    // flags:!SA; (ไม่มี flags ที่ระบุ)
    } modifier = Modifier::EXACT;

    bool fin = false; // F - Finish
    bool syn = false; // S - Synchronize
    bool rst = false; // R - Reset
    bool psh = false; // P - Push
    bool ack = false; // A - Acknowledgment
    bool urg = false; // U - Urgent
    bool ece = false; // E - ECN-Echo
    bool cwr = false; // C - Congestion Window Reduced

    bool mask_fin = false;
    bool mask_syn = false;
    bool mask_rst = false;
    bool mask_psh = false;
    bool mask_ack = false;
    bool mask_urg = false;
    bool mask_ece = false;
    bool mask_cwr = false;
};

struct FlowOption
{
    // Connection State (mutual exclusive)
    enum class ConnectionState
    {
        ESTABLISHED,     // established
        NOT_ESTABLISHED, // not_established
        STATELESS        // stateless
    };
    std::optional<ConnectionState> connection_state;

    // Direction (mutual exclusive)
    enum class Direction
    {
        TO_CLIENT,   // to_client
        TO_SERVER,   // to_server
        FROM_CLIENT, // from_client
        FROM_SERVER  // from_server
    };
    std::optional<Direction> direction;

    // Stream handling (mutual exclusive)
    enum class StreamMode
    {
        NO_STREAM,  // no_stream
        ONLY_STREAM // only_stream
    };
    std::optional<StreamMode> stream_mode;

    // Fragment handling (mutual exclusive)
    enum class FragmentMode
    {
        NO_FRAG,  // no_frag
        ONLY_FRAG // only_frag
    };
    std::optional<FragmentMode> fragment_mode;
};

struct FlowBit
{
    enum class Operation
    {
        SET,      // flowbits:set,flag;
        UNSET,    // flowbits:unset,flag;
        ISSET,    // flowbits:isset,flag;
        ISNOTSET, // flowbits:isnotset,flag;
        NOALERT   // flowbits:noalert;
    } operation;

    enum class LogicalOperator
    {
        AND, // & operator (required for set/unset, optional for isset/isnotset)
        OR   // | operator (only for isset/isnotset)
    };

    std::vector<std::string> flag_names;
    std::optional<LogicalOperator> logical_op;
};

struct SEQ
{
    Operator op;
    uint32_t min_value;
    std::optional<uint32_t> max_value;
};

struct ACK
{
    Operator op;
    uint32_t min_value;
    std::optional<uint32_t> max_value;
};

struct IType
{
    Operator op;
    uint8_t min_value;
    std::optional<uint8_t> max_value;
};

struct ICode
{
    Operator op;
    uint8_t min_value;
    std::optional<uint8_t> max_value;
};

struct ICMP_ID
{
    Operator op;
    uint16_t min_value;
    std::optional<uint16_t> max_value;
};

struct ICMP_SEQ
{
    Operator op;
    uint16_t min_value;
    std::optional<uint16_t> max_value;
};

struct NonePayloadOption
{
    std::optional<TTL> ttl;
    std::optional<ID> id;
    std::optional<FragbitsOption> fragbits;
    std::optional<IPProtoOption> ip_proto;
    std::optional<TCPFlags> flags;
    std::optional<FlowOption> flow;
    std::optional<std::vector<FlowBit>> flowbits;
    std::optional<SEQ> seq;
    std::optional<ACK> ack;
    std::optional<IType> itype;
    std::optional<ICode> icode;
    std::optional<ICMP_ID> icmp_id;
    std::optional<ICMP_SEQ> icmp_seq;
};

#endif
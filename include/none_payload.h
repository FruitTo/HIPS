#ifndef NONE_PAYLOAD_H
#define NONE_PAYLOAD_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "./dto.h"

struct FlowOption
{
    bool to_client = false;
    bool to_server = false;
    bool established = false;
    bool stateless = false;
};

struct TTL
{
    Operator operator;
    uint16_t min_value;
    std::optional<uint16_t> max_value;
};

struct ID
{
    Operator operator;
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

struct IPProtoOption {
    enum class Operator {
        NOT,            // ip_proto:!tcp;
        GREATER_THAN,   // ip_proto:>50;
        LESS_THAN,      // ip_proto:<10;
        EQUAL           // ip_proto:tcp; (default)
    } op = Operator::EQUAL;
    
    uint8_t protocol_number = 0;    // เก็บแค่ number (0-255)
};

struct NonePayloadOption
{
    std::optional<FlowOption> flow;
    std::optional<TTL> ttl;
    std::optional<ID> id;
    std::optional<FragbitsOption> fragbits;
};

#endif
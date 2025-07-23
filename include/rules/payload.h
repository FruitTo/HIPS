#ifndef PAYLOAD_H
#define PAYLOAD_H
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "./dto.h"


// Content and Pattern Matching
struct Content
{
   Buffer buffer = Buffer::NONE;
   bool negate = false;
   std::string content;

   bool fast_pattern = false;
   bool fast_pattern_only = false;
   std::optional<uint32_t> fast_pattern_offset;
   std::optional<uint32_t> fast_pattern_length;

   bool nocase = false;

   std::optional<Width> width;
   std::optional<Endianness> endian;

   std::optional<int32_t> offset;
   std::optional<uint32_t> depth;
   std::optional<int32_t> distance;
   std::optional<uint32_t> within;
};

struct PCRE {
   std::string pattern;
   bool negate = false;
   
   bool i = false;
   bool s = false;
   bool m = false;
   bool x = false;
   bool A = false;
   bool E = false;
   bool G = false;
   bool O = false;
   bool R = false;
};

// Size and Position Checks
struct BufferLen {
   Operator op;
   uint32_t min_value;
   std::optional<uint32_t> max_value;
   bool relative = false;
};

struct Dsize {
   Operator op;
   uint16_t min_value;
   std::optional<uint16_t> max_value; 
};

struct IsDataAt {
   uint32_t location;
   bool negate = false;
   bool relative = false;
};

// Byte Operations
struct ByteExtract {
   uint8_t count;
   int32_t offset;
   std::string variable_name;
   
   bool relative = false;
   std::optional<uint16_t> multiplier;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   std::optional<uint8_t> align;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

struct ByteTest {
   uint8_t count;
   ByteTestOperator op;
   bool negate = false;
   std::string compare_value;
   std::string offset;
   
   bool relative = false;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

struct ByteJump {
   uint8_t count;
   std::string offset;
   
   bool relative = false;
   std::optional<uint16_t> multiplier;
   std::optional<Endianness> endian;
   bool string_format = false;
   std::optional<std::string> base;
   bool align = false;
   bool from_beginning = false;
   bool from_end = false;
   std::optional<std::string> post_offset;
   bool dce = false;
   std::optional<uint32_t> bitmask;
};

// Protocol Specific
struct Base64Decode {
   std::optional<uint32_t> bytes;
   std::optional<uint32_t> offset;
   bool relative = false;
};

struct BerData {
   uint8_t type;
};

struct BerSkip {
   uint8_t type;
   bool optional = false;
};

struct SSLStateOption {
   std::vector<SSLState> states;
   bool negate = false;
};

struct SSLVersionOption {
   std::vector<SSLVersion> versions;
   bool negate = false;
};


// Rule Structure
struct PayloadOption
{
   std::vector<Content> content;
   std::optional<std::vector<BufferLen>> bufferlen;
   std::optional<std::vector<IsDataAt>> isdataat;
   std::optional<Dsize> dsize;
   std::optional<std::vector<PCRE>> pcre;
   std::optional<Base64Decode> base64_decode;
   std::optional<std::vector<ByteExtract>> byte_extracts;
   std::optional<std::vector<ByteTest>> byte_tests;
   std::optional<std::vector<ByteJump>> byte_jumps;
   std::optional<std::vector<BerData>> ber_data_list;
   std::optional<std::vector<BerSkip>> ber_skip_list;
   std::optional<SSLStateOption> ssl_state;
   std::optional<SSLVersionOption> ssl_version;
};
#endif
#ifndef SNORT_RULE_H
#define SNORT_RULE_H

#include <string>
#include <vector>
#include <regex>
#include <fstream>
#include <sstream>

struct GeneralOptions {
    std::string msg;
    std::string reference;
    std::string sid;
    std::string rev;
    std::string classtype;
    std::string priority;
    std::string metadata;
    std::string gid;
    std::string service;
};

struct PayloadOptions {
    std::vector<std::string> content;
    std::vector<std::string> pcre;
    std::vector<std::string> byte_test;
    std::vector<std::string> byte_jump;
    std::string isdataat;
    std::string dsize;
    std::string offset;
    std::string depth;
    std::string distance;
    std::string within;
    std::string http_uri;
    std::string http_header;
    std::string http_method;
    std::string http_cookie;
    std::string http_stat_code;
    std::string http_stat_msg;
    std::string http_raw_uri;
};

struct NonPayloadOptions {
    std::string flags;
    std::string fragbits;
    std::string fragoffset;
    std::string ttl;
    std::string tos;
    std::string id;
    std::string ipopts;
    std::string seq;
    std::string ack;
    std::string icmp_id;
    std::string icmp_seq;
    std::string itype;
    std::string icode;
    std::string ip_proto;
};

struct PostDetectionOptions {
    std::string flow;
    std::vector<std::string> flowbits;
    std::string detection_filter;
    std::string threshold;
    std::string tag;
};

struct AppLayerOptions {
    std::string sip_method;
    std::string sip_stat_code;
    std::string ssl_state;
    std::string ssl_version;
    std::string dce_iface;
    std::string dce_opnum;
    std::string dce_stub_data;
};

struct RuleBody {
    GeneralOptions general;
    PayloadOptions payload;
    NonPayloadOptions non_payload;
    PostDetectionOptions post_detection;
    AppLayerOptions app_layer;
};

struct Header {
    std::string action;
    std::string protocal;
    std::string src_addr;
    std::string src_port;
    std::string direction;
    std::string dst_addr;
    std::string dst_port
}

struct Rule {
    Header header;
    RuleBody body;
}

#endif
#ifndef FILTER_H
#define FILTER_H
#include "packet.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <tins/tins.h>
#include <vector>

void IPFilter(PacketInfo *packet, Tins::IP &ip) {
  packet->timestamp = std::chrono::system_clock::now();
  packet->id = std::to_string(ip.id());
  packet->ttl = (int)ip.ttl();
  packet->src_addr = ip.src_addr().to_string();
  packet->dst_addr = ip.dst_addr().to_string();

  if (ip.flags() & Tins::IP::DONT_FRAGMENT) {
    packet->dont_fragment = true;
  }
  if (ip.flags() & Tins::IP::MORE_FRAGMENTS) {
    packet->more_fragments = true;
  }
  if (ip.flags() & 0x8000) {
    packet->reserved = true;
  }
}

void TCPFilter(PacketInfo *packet, Tins::TCP &tcp) {
  packet->tcp->sport = std::to_string(tcp.sport());
  packet->tcp->dport = std::to_string(tcp.dport());
  packet->tcp->seq = std::to_string(tcp.seq());
  packet->tcp->ack_seq = std::to_string(tcp.ack_seq());
  packet->tcp->flags.fin = tcp.get_flag(Tins::TCP::Flags::FIN);
  packet->tcp->flags.syn = tcp.get_flag(Tins::TCP::Flags::SYN);
  packet->tcp->flags.rst = tcp.get_flag(Tins::TCP::Flags::RST);
  packet->tcp->flags.psh = tcp.get_flag(Tins::TCP::Flags::PSH);
  packet->tcp->flags.ack = tcp.get_flag(Tins::TCP::Flags::ACK);
  packet->tcp->flags.urg = tcp.get_flag(Tins::TCP::Flags::URG);
  packet->tcp->flags.ece = tcp.get_flag(Tins::TCP::Flags::ECE);
  packet->tcp->flags.cwr = tcp.get_flag(Tins::TCP::Flags::CWR);
  packet->tcp->payload_size = tcp.inner_pdu() ? tcp.inner_pdu()->size() : 0;

  if (tcp.inner_pdu() && packet->tcp->payload_size > 0) {
    auto raw_data = tcp.inner_pdu()->serialize();
    packet->tcp->payload =
        std::vector<uint8_t>(raw_data.begin(), raw_data.end());
  }
}

void UDPFilter(PacketInfo *packet, Tins::UDP &udp) {
  packet->udp->sport = std::to_string(udp.sport());
  packet->udp->dport = std::to_string(udp.dport());
  packet->udp->length = udp.length();
  packet->udp->checksum = udp.checksum();
  packet->udp->payload_size = udp.inner_pdu() ? udp.inner_pdu()->size() : 0;

  if (udp.inner_pdu() && packet->udp->payload_size > 0) {
    auto raw_data = udp.inner_pdu()->serialize();
    packet->udp->payload =
        std::vector<uint8_t>(raw_data.begin(), raw_data.end());
  }
}

void ICMPFilter(PacketInfo *packet, Tins::ICMP &icmp) {
  packet->icmp->type = icmp.type();
  packet->icmp->code = icmp.code();
  packet->icmp->id = icmp.id();
  packet->icmp->sequence = icmp.sequence();
  packet->icmp->payload_size = icmp.inner_pdu() ? icmp.inner_pdu()->size() : 0;

  if (icmp.inner_pdu()) {
    auto raw_data = icmp.inner_pdu()->serialize();
    packet->icmp->payload =
        std::vector<uint8_t>(raw_data.begin(), raw_data.end());
  }
}

void HTTPFilter(PacketInfo *packet, Tins::TCP &tcp) {
  if (tcp.inner_pdu() && tcp.inner_pdu()->size() > 0) {
    std::vector<uint8_t> raw_bytes = tcp.inner_pdu()->serialize();
    std::string http_content(raw_bytes.begin(), raw_bytes.end());
    // Method
    if (http_content.find("GET ") == 0) {
      packet->http->method = "GET";
    } else if (http_content.find("POST ") == 0) {
      packet->http->method = "POST";
    } else if (http_content.find("PUT ") == 0) {
      packet->http->method = "PUT";
    } else if (http_content.find("DELETE ") == 0) {
      packet->http->method = "DELETE";
    } else if (http_content.find("HTTP/") == 0 &&
               http_content.find("200 OK") == 0) {
      if (http_content.find("200 OK") != std::string::npos) {
        packet->http->status_code = "200";
        packet->http->status_msg = "OK";
      } else if (http_content.find("404 Not Found") != std::string::npos) {
        packet->http->status_code = "404";
        packet->http->status_msg = "Not Found";
      } else if (http_content.find("500 Internal Server Error") !=
                 std::string::npos) {
        packet->http->status_code = "500";
        packet->http->status_msg = "Internal Server Error";
      }
    }
    if (packet->http->method.has_value()) {
      std::cout << "HTTP Method: " << *packet->http->method << std::endl;
    }
    if (packet->http->status_code.has_value()) {
      std::cout << "HTTP Status: " << *packet->http->status_code << std::endl;
    }
  }
}

#endif
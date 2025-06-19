#ifndef FILTER_H
#define FILTER_H
#include "packet.h"
#include <chrono>
#include <curl/curl.h>
#include <filesystem>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <tins/tins.h>
#include <vector>

std::string url_encode(const std::string &str) {
  std::ostringstream encoded;
  encoded.fill('0');
  encoded << std::hex;

  for (char c : str) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded << c;
    } else {
      encoded << '%' << std::setw(2) << int((unsigned char)c);
    }
  }
  return encoded.str();
}

std::string url_decode(const std::string &str) {
  std::string decoded;
  for (size_t i = 0; i < str.length(); ++i) {
    if (str[i] == '%' && i + 2 < str.length()) {
      int hex_value;
      std::istringstream hex_stream(str.substr(i + 1, 2));
      hex_stream >> std::hex >> hex_value;
      decoded += static_cast<char>(hex_value);
      i += 2;
    } else if (str[i] == '+') {
      decoded += ' ';
    } else {
      decoded += str[i];
    }
  }
  return decoded;
}

std::string Match(std::string request, std::regex reg) {
  std::smatch match;
  if (std::regex_search(request, match, reg)) {
    std::string url = match[1].str();
    return url;
  }
  return "";
}

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

  if (packet->more_fragments || packet->dont_fragment) {
    packet->flow.frag = FragmentMode::ONLY_FRAG;
  } else {
    packet->flow.frag = FragmentMode::NO_FRAG;
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
    if (http_content.find("GET ") == 0) {
      packet->http->method = "GET";
      std::regex reg("^GET\\s+([^\\s]+)\\s+HTTP");
      std::string extracted_uri = Match(http_content, reg);
      packet->http->raw_uri = extracted_uri;
      packet->http->uri = url_decode(extracted_uri);

      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->client_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }

        if ((headers.find("X-Forwarded-For:") != std::string::npos) ||
            (headers.find("X-Real-IP:") != std::string::npos)) {
          std::regex xff_regex("X-Forwarded-For:\\s*([^\\r\\n,]+)");
          std::smatch match;
          if (std::regex_search(headers, match, xff_regex)) {
            packet->http->true_ip = match[1].str();
          } else {
            std::regex realip_regex("X-Real-IP:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, realip_regex)) {
              packet->http->true_ip = match[1].str();
            }
          }
        }
      }
    } else if (http_content.find("POST ") == 0) {
      packet->http->method = "POST";
      std::regex reg("^POST\\s+([^\\s]+)\\s+HTTP");
      std::string extracted_uri = Match(http_content, reg);
      packet->http->raw_uri = extracted_uri;
      packet->http->uri = url_decode(extracted_uri);
      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->client_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }
        if ((headers.find("X-Forwarded-For:") != std::string::npos) ||
            (headers.find("X-Real-IP:") != std::string::npos)) {
          std::regex xff_regex("X-Forwarded-For:\\s*([^\\r\\n,]+)");
          std::smatch match;
          if (std::regex_search(headers, match, xff_regex)) {
            packet->http->true_ip = match[1].str();
          } else {
            std::regex realip_regex("X-Real-IP:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, realip_regex)) {
              packet->http->true_ip = match[1].str();
            }
          }
        }
      }

    } else if (http_content.find("PUT ") == 0) {
      packet->http->method = "PUT";
      std::regex reg("^PUT\\s+([^\\s]+)\\s+HTTP");
      std::string extracted_uri = Match(http_content, reg);
      packet->http->raw_uri = extracted_uri;
      packet->http->uri = url_decode(extracted_uri);
      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->client_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }

        if ((headers.find("X-Forwarded-For:") != std::string::npos) ||
            (headers.find("X-Real-IP:") != std::string::npos)) {
          std::regex xff_regex("X-Forwarded-For:\\s*([^\\r\\n,]+)");
          std::smatch match;
          if (std::regex_search(headers, match, xff_regex)) {
            packet->http->true_ip = match[1].str();
          } else {
            std::regex realip_regex("X-Real-IP:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, realip_regex)) {
              packet->http->true_ip = match[1].str();
            }
          }
        }
      }
    } else if (http_content.find("DELETE ") == 0) {
      packet->http->method = "DELETE";
      std::regex reg("^DELETE\\s+([^\\s]+)\\s+HTTP");
      std::string extracted_uri = Match(http_content, reg);
      packet->http->raw_uri = extracted_uri;
      packet->http->uri = url_decode(extracted_uri);

      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->client_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }

        if ((headers.find("X-Forwarded-For:") != std::string::npos) ||
            (headers.find("X-Real-IP:") != std::string::npos)) {
          std::regex xff_regex("X-Forwarded-For:\\s*([^\\r\\n,]+)");
          std::smatch match;
          if (std::regex_search(headers, match, xff_regex)) {
            packet->http->true_ip = match[1].str();
          } else {
            std::regex realip_regex("X-Real-IP:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, realip_regex)) {
              packet->http->true_ip = match[1].str();
            }
          }
        }
      }
    } else if (http_content.find("PATCH ") == 0) {
      packet->http->method = "PATCH";
      std::regex reg("^PATCH\\s+([^\\s]+)\\s+HTTP");
      std::string extracted_uri = Match(http_content, reg);
      packet->http->raw_uri = extracted_uri;
      packet->http->uri = url_decode(extracted_uri);
      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->client_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }

        if ((headers.find("X-Forwarded-For:") != std::string::npos) ||
            (headers.find("X-Real-IP:") != std::string::npos)) {
          std::regex xff_regex("X-Forwarded-For:\\s*([^\\r\\n,]+)");
          std::smatch match;
          if (std::regex_search(headers, match, xff_regex)) {
            packet->http->true_ip = match[1].str();
          } else {
            std::regex realip_regex("X-Real-IP:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, realip_regex)) {
              packet->http->true_ip = match[1].str();
            }
          }
        }
      }
    } else if (http_content.find("HTTP/") == 0) {
      std::regex status_regex("^HTTP/1\\.1\\s+(\\d+)\\s+(.+?)\\r");
      std::smatch match;
      if (std::regex_search(http_content, match, status_regex)) {
        packet->http->status_code = match[1].str();
        packet->http->status_msg = match[2].str();
      }

      size_t body_start = http_content.find("\r\n\r\n");
      if (body_start != std::string::npos) {
        std::string headers = http_content.substr(0, body_start);
        packet->http->raw_headers = headers;
        std::string body = http_content.substr(body_start + 4);

        if (!body.empty()) {
          packet->http->raw_body = body;
        }

        if ((headers.find("Cookie:") != std::string::npos) ||
            (headers.find("Set-Cookie:") != std::string::npos)) {
          std::regex cookie_regex("Cookie:\\s*([^\\r\\n]+)");
          std::smatch match;
          if (std::regex_search(headers, match, cookie_regex)) {
            packet->http->raw_cookie = match[1].str();
          } else {
            std::regex setcookie_regex("Set-Cookie:\\s*([^\\r\\n]+)");
            if (std::regex_search(headers, match, setcookie_regex)) {
              packet->http->raw_cookie = match[1].str();
            }
          }
        }
      }
    }
  }
}

#endif
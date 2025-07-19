#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/filter.h"
#include "./include/flow_manager.h"
#include "./include/packet.h"
#include "./include/snort_rule.h"
#include "./include/snort_rule_parser.h"
#include "./include/header_detection.h"
#include "./include/tins/tins.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;
namespace fs = filesystem;

void parsePorts(const string &input, vector<string> &target);
void config(bool mode, const vector<NetworkConfig> &configuredInterfaces);
void sniff(NetworkConfig &conf);
void sniff_file(NetworkConfig &conf);
string join(const vector<string> &list, const string &sep);

auto rules = SnortRuleParser::parseRulesFromFile("./rules/snort3-community.rules");

int main()
{
    // Select Mode
    bool mode = false;

    NetworkConfig device;
    device.NAME = "Ubuntu-12";
    device.IP = "192.168.10.50";
    device.HOME_NET = "192.168.10.50";
    device.EXTERNAL_NET = "!192.168.10.50";
    // device.SSH_SERVERS = true;
    // device.SSH_PORTS.push_back("22");
    device.HTTP_SERVERS = true;
    device.HTTP_PORTS.push_back("80");

    vector<NetworkConfig> configuredInterfaces;
    configuredInterfaces.push_back(device);

    // Config Device
    thread_pool pool(configuredInterfaces.size());
    vector<future<void>> task;

    // Create Config File
    config(mode, configuredInterfaces);

    // Create pipe
    const char *fifo_path = "/tmp/snort_fifo";
    mkfifo(fifo_path, 0666);
    if (mkfifo(fifo_path, 0666) == -1 && errno != EEXIST)
    {
        perror("mkfifo failed");
        return 1;
    }
    else
    {
        cout << "mkfifo pass" << endl;
    }

    pid_t pid = fork();
    if (pid == 0)
    {
        execl("./snort.sh", "./snort.sh",
              "-r", "/tmp/snort_fifo",
              "-A", "alert_fast",
              "-c", "./config/snort.lua",
              nullptr);
        _exit(1);
    }
    else
    {
        open(fifo_path, O_WRONLY);
    }

    // Push Packet Capture Task
    for (NetworkConfig &conf : configuredInterfaces)
    {
        task.push_back(pool.submit_task([&conf]()
                                        { sniff_file(conf); }));
    }

    for (auto &t : task)
    {
        t.wait();
    }

    return 0;
}
void sniff_file(NetworkConfig &conf)
{
    FileSniffer fileSniff("/home/fruitto/Downloads/File/Dataset/Friday-WorkingHours.pcap");
    PacketWriter pcapWriter("/tmp/snort_fifo", DataLinkType<EthernetII>());

    unordered_map<string, FlowEntry> flow_table;
    uint16_t bloom_counters[ARRAY_SIZE] = {0};
    uint64_t total_flows = 0;

    fileSniff.sniff_loop([&](Packet &pkt) {
        // Filter
        PDU *pdu = pkt.pdu();
        if (pdu->find_pdu<IP>()) {
            IP &ip = pdu->rfind_pdu<IP>();
            PacketInfo packet;
            packet.protocol = "ip";
            IPFilter(&packet, ip);
            if (packet.src_addr == *conf.HOME_NET &&
                packet.dst_addr != *conf.HOME_NET) {
                packet.flow.direction = FlowDirection::TO_CLIENT;
            } else {
                packet.flow.direction = FlowDirection::TO_SERVER;
            }

            if (pdu->find_pdu<TCP>()) {
                TCP &tcp = pdu->rfind_pdu<TCP>();
                packet.protocol = "tcp";
                packet.tcp.emplace();
                TCPFilter(&packet, tcp);

                if (packet.tcp->payload_size > 0) {
                    packet.flow.stream_mode = StreamMode::ONLY_STREAM;
                } else {
                    packet.flow.stream_mode = StreamMode::NO_STREAM;
                }

                if (tcp.sport() == 80 || tcp.dport() == 80 || 
                    tcp.sport() == 8080 || tcp.dport() == 8080 ||
                    tcp.sport() == 443 || tcp.dport() == 443)  {
                    packet.protocol = "http";
                    packet.http.emplace();
                    HTTPFilter(&packet, tcp);
                }

                if (tcp.sport() == 443 || tcp.dport() == 443) {
                    packet.ssl.emplace();
                    SSLFilter(&packet, tcp);
                }

                if (tcp.sport() == 21 || tcp.dport() == 21 || 
                    tcp.sport() == 2021 || tcp.dport() == 2021) {
                    packet.protocol = "ftp";
                    packet.ftp.emplace();
                    FTPFilter(&packet, tcp);
                }

                if (tcp.sport() == 25 || tcp.dport() == 25 ||
                    tcp.sport() == 587 || tcp.dport() == 587 ||
                    tcp.sport() == 465 || tcp.dport() == 465) {
                    packet.protocol = "smtp";
                    packet.smtp.emplace();
                    SMTPFilter(&packet, tcp);
                }

                if (tcp.sport() == 135 || tcp.dport() == 135) {
                    packet.dce.emplace();
                    DCEFilter(&packet, tcp);
                }

            } else if (pdu->find_pdu<UDP>()) {
                UDP &udp = pdu->rfind_pdu<UDP>();
                packet.protocol = "udp";
                packet.udp.emplace();
                UDPFilter(&packet, udp);
                packet.flow.stream_mode = StreamMode::NO_STREAM;

                if (udp.sport() == 5060 || udp.dport() == 5060) {
                    packet.protocol = "sip";
                    packet.sip.emplace();
                    SIPFilter(&packet, udp);
                }

            } else if (pdu->find_pdu<ICMP>()) {
                ICMP &icmp = pdu->rfind_pdu<ICMP>();
                packet.protocol = "icmp";
                packet.icmp.emplace();
                ICMPFilter(&packet, icmp);
                packet.flow.stream_mode = StreamMode::NO_STREAM;
            }

            // Flow
            size_t flows_before = flow_table.size();
            flowIdentication(&packet, &conf, flow_table, bloom_counters);
            if (flow_table.size() > flows_before) {
                total_flows++;
            }

            // Header Detection → ส่งเข้า Snort
            if (headerDetection(packet, rules, conf)) {
                pcapWriter.write(pkt);
            }
        }

        return true; // ต้องมีเพื่อไม่ให้หยุด loop
    });
}


void sniff(NetworkConfig &conf)
{
    // Initial Flow Variable
    static std::mutex mtx;
    unordered_map<string, FlowEntry> flow_table;
    uint16_t bloom_counters[ARRAY_SIZE] = {0};
    uint64_t total_packets = 0;
    uint64_t total_flows = 0;
    auto last_cleanup = chrono::system_clock::now();

    PacketWriter pcapWriter("/tmp/snort_fifo", DataLinkType<EthernetII>());

    // Initial Log Variable
    string currentDay = currentDate();
    string currentTime = timeStamp();
    string currentPath = getPath();
    filesystem::create_directories(currentPath);
    auto writer = make_unique<PacketWriter>(currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap", DataLinkType<EthernetII>());

    // Capture Packet (Sniffer)
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(conf.NAME, config);
    sniffer.sniff_loop([&](Packet &pkt)
                       {
        total_packets++;
        
        // Check Flow Time Expire
        auto now = chrono::system_clock::now();
        if (now - last_cleanup > chrono::minutes(1)) {
          cleanupExpiredFlows(flow_table);
          last_cleanup = now;
        }

        // Write logs
        string date = currentDate();
        string path = getPath();
        if (currentDay != date) {
          currentDay = date;
          currentPath = path;
          filesystem::create_directories(currentPath);
          writer = make_unique<PacketWriter>(currentPath + conf.NAME + "-" + currentDay + ".pcap", DataLinkType<EthernetII>());
        }
        writer->write(pkt);
        
        // Filter
        PDU *pdu = pkt.pdu();
        if (pdu->find_pdu<IP>()) {
          IP &ip = pdu->rfind_pdu<IP>();
          PacketInfo packet;
          packet.protocol = "ip";
          IPFilter(&packet, ip);
          if (packet.src_addr == *conf.HOME_NET &&
              packet.dst_addr != *conf.HOME_NET) {
            packet.flow.direction = FlowDirection::TO_CLIENT;
          } else {
            packet.flow.direction = FlowDirection::TO_SERVER;
          }
          if (pdu->find_pdu<TCP>()) {
            TCP &tcp = pdu->rfind_pdu<TCP>();
            packet.protocol = "tcp";
            packet.tcp.emplace();
            TCPFilter(&packet, tcp);
            
            if (packet.tcp->payload_size > 0) {
              packet.flow.stream_mode = StreamMode::ONLY_STREAM;
            } else {
              packet.flow.stream_mode = StreamMode::NO_STREAM;
            }
            
            // HTTP Detection
            if (tcp.sport() == 80 || tcp.dport() == 80 || 
                tcp.sport() == 8080 || tcp.dport() == 8080 ||
                tcp.sport() == 443 || tcp.dport() == 443)  {
              packet.protocol = "http";
              packet.http.emplace();
              HTTPFilter(&packet, tcp);
            }
            
            // SSL/TLS Detection
            if (tcp.sport() == 443 || tcp.dport() == 443) {
              packet.ssl.emplace();
              SSLFilter(&packet, tcp);
            }
            
            // FTP Detection
            if (tcp.sport() == 21 || tcp.dport() == 21 || 
                tcp.sport() == 2021 || tcp.dport() == 2021) {
              packet.protocol = "ftp";
              packet.ftp.emplace();
              FTPFilter(&packet, tcp);
            }
            
            // SMTP Detection
            if (tcp.sport() == 25 || tcp.dport() == 25 ||
                tcp.sport() == 587 || tcp.dport() == 587 ||
                tcp.sport() == 465 || tcp.dport() == 465) {
              packet.protocol = "smtp";
              packet.smtp.emplace();
              SMTPFilter(&packet, tcp);
            }
            
            // DCE/RPC Detection
            if (tcp.sport() == 135 || tcp.dport() == 135) {
              packet.dce.emplace();
              DCEFilter(&packet, tcp);
            }
            
          } else if (pdu->find_pdu<UDP>()) {
            UDP &udp = pdu->rfind_pdu<UDP>();
            packet.protocol = "udp";
            packet.udp.emplace();
            UDPFilter(&packet, udp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
            
            // SIP Detection
            if (udp.sport() == 5060 || udp.dport() == 5060) {
              packet.protocol = "sip";
              packet.sip.emplace();
              SIPFilter(&packet, udp);
            }
            
          } else if (pdu->find_pdu<ICMP>()) {
            ICMP &icmp = pdu->rfind_pdu<ICMP>();
            packet.protocol = "icmp";
            packet.icmp.emplace();
            ICMPFilter(&packet, icmp);
            packet.flow.stream_mode = StreamMode::NO_STREAM;
          }
          
          // Flow
          size_t flows_before = flow_table.size();
          flowIdentication(&packet, &conf, flow_table, bloom_counters);
          if (flow_table.size() > flows_before) {
            total_flows++;
          }

          // Detection
          if(headerDetection(packet, rules, conf)){
            pcapWriter.write(pkt);
          }
        }
        return true; });
}

void parsePorts(const string &input, vector<string> &target)
{
    istringstream iss(input);
    string port;
    while (iss >> port)
        target.push_back(port);
}

string join(const vector<string> &list, const string &sep)
{
    string out;
    for (size_t i = 0; i < list.size(); ++i)
    {
        out += list[i];
        if (i != list.size() - 1)
            out += sep;
    }
    return out;
}

void config(bool mode, const vector<NetworkConfig> &configuredInterfaces)
{
    namespace fs = std::filesystem;
    auto root = fs::current_path();
    auto cfg = root / "config" / "snort.lua";
    auto logs = root / "snort_logs";

    std::ofstream out(cfg);
    if (!out)
        return;

    out << "include 'snort_defaults.lua'\n\n-- auto-generated snort.lua\n\n";

    // เปิด inspector ตามที่ต้องการ
    bool need_http = false;
    for (auto &nc : configuredInterfaces)
        need_http |= nc.HTTP_SERVERS.value_or(false);
    out << "stream = {}\nstream_tcp = {}\nstream_udp = {}\n";
    if (need_http)
        out << "http_inspect = {}\n";
    out << "\nwizard = { curses = {'dce_tcp','dce_udp','dce_smb','sslv2','mms','s7commplus'} }\n\n";

    // รวมค่า HOME_NET และ HTTP_PORTS
    std::set<std::string> home_ips;
    std::set<std::string> http_ports;
    for (const NetworkConfig &nc : configuredInterfaces)
    {
        home_ips.insert("'" + nc.IP + "'");
        if (nc.HTTP_SERVERS.value_or(false))
            http_ports.insert(nc.HTTP_PORTS.begin(), nc.HTTP_PORTS.end());
    }
    if (need_http)
    {
        out << "HTTP_SERVERS = { " << [&]()
        {
            std::string s;
            for (auto &v : home_ips)
            {
                if (!s.empty())
                    s += ", ";
                s += v;
            }
            return s;
        }() << " }\n";
        out << "HTTP_PORTS = '" << [&]()
        {
            std::string s;
            for (auto &v : http_ports)
            {
                if (!s.empty())
                    s += " ";
                s += v;
            }
            return s;
        }() << "'\n\n";
    }

    // HOME_NET และ EXTERNAL_NET
    out << "variables = {\n"
           "  HOME_NET = { ";
    {
        std::string s;
        for (auto &v : home_ips)
        {
            if (!s.empty())
                s += ", ";
            s += v;
        }
        out << s;
    }
    out << " },\n"
           "  EXTERNAL_NET = { ";
    {
        std::string s;
        for (auto &v : home_ips)
        {
            if (!s.empty())
                s += ", ";
            s += "'!" + v.substr(1);
        }
        out << s;
    }
    out << " }\n}\n\n";

    // ใช้ DAQ stdin ผ่าน pcap DAQ
    // out << "snaplen = 65535\n";
    out << "daq_module = 'pcap'\n"
           "daq_mode = '"
        << (mode ? "inline" : "passive") << "'\n\n";

    out << "ips = {\n"
           "  variables = default_variables,\n"
           "  rules     = '"
        << (root / "rules" / "snort3-community.rules").string() << "',\n"
                                                                   "  mode      = '"
        << (mode ? "inline" : "tap") << "',\n"
                                        "  enable_builtin_rules = true\n"
                                        "}\n\n";

    // Loggers
    out << "loggers = {{ name='alert_json', file=true, filename='" << logs.string() << "/snort.alert' }}\n";
    out << "pkt_logger = { file=true, limit=1000 }\n\n";

    // Binder
    out << "binder = {\n"
           "  { when={ proto='tcp' }, use={ type='stream_tcp' } },\n"
           "  { when={ proto='udp' }, use={ type='stream_udp' } },\n";
    if (need_http)
        out << "  { when={ service='http' }, use={ type='http_inspect' } },\n";
    out << "  { use={ type='wizard' } }\n};\n";
    out.close();
}
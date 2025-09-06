#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/packet.h"
#include "./include/flow.h"
#include "./include/tins/tins.h"
#include "./include/ids_api.h"

#include <fstream>
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
#include <thread>
#include <map>
#include <netinet/in.h> 

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;
namespace fs = filesystem;
using SteadyClock = chrono::steady_clock; 

void sniff(NetworkConfig &conf);
void parsePorts(const string &input, vector<string> &target);
string join(const vector<string> &list, const string &sep);
void config(bool mode, const vector<NetworkConfig> &configuredInterfaces);

int main() {
  // ONNX
  // IDSContext ctx = ids_init("./artifacts");

  vector<string> interfaceName = getInterfaceName();
  vector<NetworkConfig> configuredInterfaces;
  thread_pool pool(interfaceName.size());
  vector<future<void>> task;

  // Select Mode.
  bool mode;
  char modeInput;
  cout << "IPS Mode ? [y/n]" << endl;
  cin >> modeInput;
  mode = (modeInput == 'y' || modeInput == 'Y');

  // Config Interface
  for (const string &iface : interfaceName) {
    NetworkConfig conf;
    char yesno;
    string input;

    conf.NAME = iface;
    conf.IP = getIpInterface(iface);
    conf.HOME_NET = getIpInterface(iface);
    conf.EXTERNAL_NET = "!" + *conf.HOME_NET;

    cout << "\nConfiguring services for interface: " << iface << "\n";

    auto askService = [&](const string &name, optional<bool> &flag, vector<string> &ports) {
      cout << name << " Service? [y/n]: ";
      cin >> yesno;
      cin.ignore(numeric_limits<streamsize>::max(), '\n');
      bool enabled = (yesno == 'y' || yesno == 'Y');
      flag = enabled;
      if (enabled) {
        cout << "Enter " << name << " port(s) (space separated): ";
        getline(cin, input);
        parsePorts(input, ports);
      }
    };

    askService("HTTP",   conf.HTTP_SERVERS,   conf.HTTP_PORTS);
    askService("SSH",    conf.SSH_SERVERS,    conf.SSH_PORTS);
    askService("FTP",    conf.FTP_SERVERS,    conf.FTP_PORTS);
    askService("Oracle", conf.SQL_SERVERS,    conf.ORACLE_PORTS);
    askService("TELNET", conf.TELNET_SERVERS, conf.FILE_DATA_PORTS);

    configuredInterfaces.push_back(conf);
  }

  // Create Config File
  config(mode, configuredInterfaces);

  // Create Snort Process
  pid_t pid = fork();
  if (pid == 0) {
    vector<char *> argv;

    argv.push_back(strdup("sudo"));
    argv.push_back(strdup("snort"));

    argv.push_back(strdup("--snaplen"));
    argv.push_back(strdup("65535"));

    argv.push_back(strdup("--daq-dir"));
    argv.push_back(strdup("/usr/local/lib/daq"));
    argv.push_back(strdup("--daq"));
    argv.push_back(strdup("afpacket"));
    argv.push_back(strdup("--daq-mode"));
    argv.push_back(strdup("passive"));

    // Interface
    for (const auto &ifn : interfaceName) {
      argv.push_back(strdup("-i"));
      argv.push_back(strdup(ifn.c_str()));
    }

    // Thread
    argv.push_back(strdup("--max-packet-threads"));
    argv.push_back(strdup(to_string(interfaceName.size()).c_str()));

    argv.push_back(strdup("-c"));
    argv.push_back(strdup("./config/snort.lua"));
    argv.push_back(strdup("-A"));
    argv.push_back(strdup("alert_json"));
    argv.push_back(strdup("-l"));
    argv.push_back(strdup("./snort_logs"));
    argv.push_back(nullptr);

    cout << "[Snort command] ";
    for (char *arg : argv) {
      if (arg != nullptr) cout << arg << " ";
    }
    cout << endl;

    execvp("sudo", argv.data());
    perror("execvp failed");
    _exit(1);
  }
  // User for wait snort
  // else if (pid > 0)
  // {
  //   int status;
  //   waitpid(pid, &status, 0);
  // }

  // Sniffer
  for (NetworkConfig &conf : configuredInterfaces) {
    task.push_back(pool.submit_task([&conf]() { sniff(conf); }));
  }

  for (auto &t : task) {
    t.wait();
  }

  return 0;
}

void sniff(NetworkConfig &conf) {
  // Initial Log Variable
  std::string currentDay  = currentDate();
  std::string currentTime = timeStamp();
  std::string currentPath = getPath();
  std::filesystem::create_directories(currentPath);
  auto writer = std::make_unique<PacketWriter>(
      currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap",
      DataLinkType<EthernetII>());

  // Sniffer
  SnifferConfiguration cfg;
  cfg.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, cfg);

  // ONNX
  IDSContext ctx = ids_init("./artifacts");

  // Flow Variable
  std::unordered_map<std::string, FlowState> flow_map;
  using SteadyClock = std::chrono::steady_clock;
  using namespace std::chrono;
  const auto t0 = SteadyClock::now();

  // idle thresholds
  static constexpr double UDP_IDLE_SEC = 1.0;   // close UDP flow after 1s idle
  static constexpr double TCP_IDLE_SEC = 60.0;  // close TCP flow after 60s idle

  sniffer.sniff_loop([&](Packet &pkt) {
    // --- Rotate PCAP daily (ใช้รูปแบบไฟล์เดียวกันทุกครั้ง) ---
    std::string date = currentDate();
    std::string path = getPath();
    if (currentDay != date) {
      currentDay  = date;
      currentPath = path;
      std::filesystem::create_directories(currentPath);
      std::string ts = timeStamp();
      writer = std::make_unique<PacketWriter>(
          currentPath + conf.NAME + "_" + currentDay + "_" + ts + ".pcap",
          DataLinkType<EthernetII>());
    }
    writer->write(pkt);

    // --- Parse L3 (IPv4/IPv6) + L4 ---
    PDU* pdu = pkt.pdu();
    if (!pdu) return true;

    const IP*   ip4 = pdu->find_pdu<IP>();
    const IPv6* ip6 = ip4 ? nullptr : pdu->find_pdu<IPv6>();
    if (!ip4 && !ip6) return true;

    // โปรโตคอล L4
    uint8_t proto = 0; // 6=TCP, 17=UDP, 58=ICMPv6, 1=ICMP
    int frame_len_l3 = 0;
    int ip_hdr_len   = 0;
    std::string src_str, dst_str;

    if (ip4) {
      proto        = ip4->protocol();
      frame_len_l3 = static_cast<int>(ip4->size());
      ip_hdr_len   = static_cast<int>(ip4->header_size());
      src_str      = ip4->src_addr().to_string();
      dst_str      = ip4->dst_addr().to_string();
    } else { // IPv6
      proto        = ip6->next_header();
      frame_len_l3 = static_cast<int>(ip6->size());
      ip_hdr_len   = static_cast<int>(ip6->header_size());
      src_str      = ip6->src_addr().to_string();
      dst_str      = ip6->dst_addr().to_string();
    }

    uint16_t sport = 0, dport = 0;
    const TCP* tcp = pdu->find_pdu<TCP>();
    const UDP* udp = (!tcp) ? pdu->find_pdu<UDP>() : nullptr;
    const bool is_tcp = (tcp != nullptr);

    if (tcp) { sport = tcp->sport(); dport = tcp->dport(); }
    else if (udp) { sport = udp->sport(); dport = udp->dport(); }

    // ใช้ ICMP/ICMPv6 สำหรับคำนวณ L4 header
    const ICMP*   icmp4 = (!tcp && !udp) ? pdu->find_pdu<ICMP>()   : nullptr;
    const ICMPv6* icmp6 = (!tcp && !udp && !icmp4) ? pdu->find_pdu<ICMPv6>() : nullptr;

    const std::string key =
        std::to_string(proto) + "|" + src_str + ":" + std::to_string(sport) +
        "->" + dst_str + ":" + std::to_string(dport);

    FlowState& flow = flow_map[key];
    if (!flow.started) {
      flow_init(flow);
    }

    // ทิศทาง FWD: ให้ "แพ็กเก็ตที่ออกจากเครื่องนี้" เป็น FWD
    const bool is_fwd = (src_str == conf.IP);

    const auto  now_tp = SteadyClock::now();
    const double ts_sec = duration_cast<nanoseconds>(now_tp - t0).count() / 1e9;

    // L4 header size
    uint8_t tcp_flags_byte = 0;
    int     tcp_window     = 0;
    int     l4_hdr_len     = 0;

    if (tcp) {
      // ใช้ API ของ libtins แทนแมสก์ดิบ
      tcp_flags_byte = tcp->flags();
      tcp_window     = tcp->window();
      l4_hdr_len     = static_cast<int>(tcp->header_size());
    } else if (udp) {
      l4_hdr_len = static_cast<int>(udp->header_size()); // 8 bytes
    } else if (icmp4) {
      l4_hdr_len = static_cast<int>(icmp4->header_size()); // ~8
    } else if (icmp6) {
      l4_hdr_len = static_cast<int>(icmp6->header_size()); // ~8
    } else {
      l4_hdr_len = 0;
    }

    int payload_len = frame_len_l3 - (ip_hdr_len + l4_hdr_len);
    if (payload_len < 0) payload_len = 0;

    flow_add_packet(
        flow,
        is_fwd,
        ts_sec,
        static_cast<int32_t>(frame_len_l3),
        static_cast<int32_t>(ip_hdr_len),
        static_cast<int32_t>(l4_hdr_len),
        is_tcp,
        tcp_flags_byte,
        static_cast<int32_t>(tcp_window),
        static_cast<int32_t>(payload_len)
    );

    flow.last_ts = ts_sec;
    if (flow.first_ts == 0.0) flow.first_ts = ts_sec;

    // TCP Feature
    const bool fin = tcp && tcp->get_flag(TCP::FIN);
    const bool rst = tcp && tcp->get_flag(TCP::RST);
    if (is_tcp && (fin || rst)) {
      Features feat{};
      flow_finalize(flow, feat, 1.0);

      std::vector<float> input_vec;
      features_to_float_vector(feat, input_vec);

      IDSResult result2 = ids_predict_from_ordered(ctx, input_vec);
      std::cout << "[TCP Flow End] "
            << "attack=" << result2.is_attack
            << " p_attack=" << result2.p_attack
            << " class_id=" << result2.class_id
            << " class=" << result2.class_name
            << " class_prob=" << result2.class_prob
            << std::endl;

      flow_map.erase(key);
      return true;
    }

    // UDP Feature
    static uint64_t tick = 0;
    if ((++tick & 0x3FF) == 0) { // ทุก ~1024 แพ็กเก็ต
      std::vector<std::string> to_close; to_close.reserve(128);
      for (auto &kv : flow_map) {
        const std::string& k = kv.first;
        FlowState& s = kv.second;

        const bool is_udp_flow = (k.rfind("17|", 0) == 0);
        const bool is_tcp_flow = (k.rfind("6|", 0)  == 0);

        const double idle = ts_sec - s.last_ts;
        if ((is_udp_flow && idle >= UDP_IDLE_SEC) ||
            (is_tcp_flow && idle >= TCP_IDLE_SEC)) {
          to_close.push_back(k);
        }
      }
      for (const auto& k2 : to_close) {
        auto it = flow_map.find(k2);
        if (it != flow_map.end()) {
          Features feat{};
          const bool is_udp_flow = (k2.rfind("17|", 0) == 0);
          const double idle_thr = is_udp_flow ? UDP_IDLE_SEC : TCP_IDLE_SEC;

          flow_finalize(it->second, feat, idle_thr);

          std::vector<float> input_vec;
          features_to_float_vector(feat, input_vec);

          IDSResult result2 = ids_predict_from_ordered(ctx, input_vec);
          std::cout << "[UDP Flow Idle Close] "
          << "attack=" << result2.is_attack
          << " p_attack=" << result2.p_attack
          << " class_id=" << result2.class_id
          << " class=" << result2.class_name
          << " class_prob=" << result2.class_prob
          << std::endl;

          flow_map.erase(it);
        }
      }
    }

    return true;
  });
}

void parsePorts(const string &input, vector<string> &target) {
  istringstream iss(input);
  string port;
  while (iss >> port) target.push_back(port);
}

string join(const vector<string> &list, const string &sep) {
  string out;
  for (size_t i = 0; i < list.size(); ++i) {
    out += list[i];
    if (i != list.size() - 1) out += sep;
  }
  return out;
}

void config(bool mode, const vector<NetworkConfig> &configuredInterfaces) {
  namespace fs = filesystem;
  auto root = fs::current_path();
  auto cfg  = root / "config" / "snort.lua";
  auto logs = root / "snort_logs";
  fs::create_directories(logs);

  ofstream out(cfg);
  if (!out) {
    cerr << "Failed to open " << cfg << " for writing.\n";
    return;
  }

  set<string> home_ips;

  set<string> http_ports;
  bool need_http = false;

  set<string> file_ports;
  bool need_telnet = false;

  set<string> ftp_ports;
  bool need_ftp = false;

  set<string> oracle_ports;
  bool need_sql = false;

  set<string> ssh_ports;
  bool need_ssh = false;

  // Check need protocol
  for (const auto &nc : configuredInterfaces) {
    home_ips.insert("'" + nc.IP + "'");
    if (nc.HTTP_SERVERS.value_or(false)) {
      need_http = true;
      http_ports.insert(nc.HTTP_PORTS.begin(), nc.HTTP_PORTS.end());
    }

    if (nc.TELNET_SERVERS.value_or(false)) {
      need_telnet = true;
      file_ports.insert(nc.FILE_DATA_PORTS.begin(), nc.FILE_DATA_PORTS.end());
    }

    if (nc.FTP_SERVERS.value_or(false)) {
      need_ftp = true;
      ftp_ports.insert(nc.FTP_PORTS.begin(), nc.FTP_PORTS.end());
    }

    if (nc.SQL_SERVERS.value_or(false)) {
      need_sql = true;
      oracle_ports.insert(nc.ORACLE_PORTS.begin(), nc.ORACLE_PORTS.end());
    }

    if (nc.SSH_SERVERS.value_or(false)) {
      need_ssh = true;
      ssh_ports.insert(nc.SSH_PORTS.begin(), nc.SSH_PORTS.end());
    }
  }

  // HTTP
  if (need_http && !http_ports.empty()) {
    // out << "http_inspect = {\n"
    //        "  request_depth = -1,\n"
    //        "  response_depth = -1,\n"
    //        "  unzip = true,\n"
    //        "  normalize_utf = true\n"
    //        "}\n\n";

    ostringstream ip_list;
    bool first = true;
    for (const auto &ip : home_ips) {
      if (!first) ip_list << ", ";
      ip_list << ip;
      first = false;
    }
    out << "HTTP_SERVERS = { " << ip_list.str() << " }\n";

    ostringstream port_list;
    first = true;
    for (const auto &port : http_ports) {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "HTTP_PORTS = '" << port_list.str() << "'\n";
    out << "FILE_DATA_PORTS = HTTP_PORTS .. " " '143 110'\n";

  } else {
    out << "FILE_DATA_PORTS = '143 110'\n";
  }

  // Telnet
  if (need_telnet && !file_ports.empty()) {
    ostringstream port_list;
    bool first = true;
    for (const auto &port : file_ports) {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "FILE_DATA_PORTS = '" << port_list.str() << "'\n";
  }

  // FTP
  if (need_ftp && !ftp_ports.empty()) {
    ostringstream port_list;
    bool first = true;
    for (const auto &port : ftp_ports) {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "FTP_PORTS = '" << port_list.str() << "'\n";
  }

  // SQL
  if (need_sql && !oracle_ports.empty()) {
    ostringstream port_list;
    bool first = true;
    for (const auto &port : oracle_ports) {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "ORACLE_PORTS = '" << port_list.str() << "'\n";
  }

  // SSH
  if (need_ssh && !ssh_ports.empty()) {
    ostringstream port_list;
    bool first = true;
    for (const auto &port : ssh_ports) {
      if (!first) port_list << " ";
      port_list << port;
      first = false;
    }
    out << "SSH_PORTS = '" << port_list.str() << "'\n";
  }

  // HOME_NET
  if (home_ips.size() > 1) {
    out << "HOME_NET = { ";
    bool first = true;
    for (auto &ip : home_ips) {
      if (!first) out << ", ";
      out << ip;
      first = false;
    }
    out << " }\n";
  } else {
    if (!home_ips.empty()) {
      out << "HOME_NET = " << *home_ips.begin() << "\n";
    } else {
      out << "HOME_NET = 'any'\n";
    }
  }

  // EXTERNAL_NET
  out << "EXTERNAL_NET = 'any'\n\n";
  // if (home_ips.size() > 1)
  // {
  //   out << "EXTERNAL_NET = { ";
  //   bool first = true;
  //   for (auto &ip : home_ips)
  //   {
  //     string raw_ip = ip.substr(1, ip.size() - 2);
  //     if (!first)
  //       out << ", ";
  //     out << "'!" << raw_ip << "'";
  //     first = false;
  //   }
  //   out << " }\n\n";
  // }
  // else
  // {
  //   if (!home_ips.empty())
  //   {
  //     string raw_ip = (*home_ips.begin()).substr(1, (*home_ips.begin()).size() - 2);
  //     out << "EXTERNAL_NET = '!" << raw_ip << "'\n\n";
  //   }
  //   else
  //   {
  //     out << "EXTERNAL_NET = 'any'\n\n";
  //   }
  // }

  out << "include 'snort_defaults.lua'\n";

  out << "stream = { }\n"
         "stream_ip = { }\n"
         "stream_icmp = { }\n"
         "stream_tcp = { }\n"
         "stream_udp = { }\n"
         "stream_user = { }\n"
         "stream_file = { }\n\n"

         "arp_spoof = { }\n"
         "back_orifice = { }\n"
         "dns = { }\n"
         "imap = { }\n"
         "netflow = { }\n"
         "normalizer = { }\n"
         "pop = { }\n"
         "rpc_decode = { }\n"
         "sip = { }\n"
         "ssh = { }\n"
         "ssl = { }\n"
         "telnet = { }\n\n"

         "cip = { }\n"
         "dnp3 = { }\n"
         "iec104 = { }\n"
         "mms = { }\n"
         "modbus = { }\n"
         "s7commplus = { }\n\n"

         "dce_smb = { }\n"
         "dce_tcp = { }\n"
         "dce_udp = { }\n"
         "dce_http_proxy = { }\n"
         "dce_http_server = { }\n\n"

         "gtp_inspect = default_gtp\n"
         "port_scan = default_med_port_scan\n"
         "smtp = default_smtp\n\n"

         "ftp_server = default_ftp_server\n"
         "ftp_client = { }\n"
         "ftp_data = { }\n\n"

         "http_inspect = { }\n"
         "http2_inspect = { }\n\n"

         "js_norm = default_js_norm\n\n"

         "wizard = default_wizard\n\n"

         "binder = {\n"
         "    { when = { proto = 'udp', ports = '53', role='server' },  use = { type = 'dns' } },\n"
         "    { when = { proto = 'tcp', ports = '53', role='server' },  use = { type = 'dns' } },\n"
         "    { when = { proto = 'tcp', ports = '111', role='server' }, use = { type = 'rpc_decode' } },\n"
         "    { when = { proto = 'tcp', ports = '502', role='server' }, use = { type = 'modbus' } },\n"
         "    { when = { proto = 'tcp', ports = '2123 2152 3386', role='server' }, use = { type = 'gtp_inspect' } },\n"
         "    { when = { proto = 'tcp', ports = '2404', role='server' }, use = { type = 'iec104' } },\n"
         "    { when = { proto = 'udp', ports = '2222', role = 'server' }, use = { type = 'cip' } },\n"
         "    { when = { proto = 'tcp', ports = '44818', role = 'server' }, use = { type = 'cip' } },\n\n"
         "    { when = { proto = 'tcp', service = 'dcerpc' },  use = { type = 'dce_tcp' } },\n"
         "    { when = { proto = 'udp', service = 'dcerpc' },  use = { type = 'dce_udp' } },\n"
         "    { when = { proto = 'udp', service = 'netflow' }, use = { type = 'netflow' } },\n\n";

  if (need_http && !http_ports.empty()) {
    vector<string> ports_vec(http_ports.begin(), http_ports.end());
    string ports_list = join(ports_vec, " "); // เช่น "8000 8080"
    out << "    { when = { proto = 'tcp', ports = \"" << ports_list
        << "\", role = 'server' }, use = { type = 'http_inspect' } },\n";
  }

  out << "    { when = { service = 'netbios-ssn' },      use = { type = 'dce_smb' } },\n"
         "    { when = { service = 'dce_http_server' },  use = { type = 'dce_http_server' } },\n"
         "    { when = { service = 'dce_http_proxy' },   use = { type = 'dce_http_proxy' } },\n\n"
         "    { when = { service = 'cip' },              use = { type = 'cip' } },\n"
         "    { when = { service = 'dnp3' },             use = { type = 'dnp3' } },\n"
         "    { when = { service = 'dns' },              use = { type = 'dns' } },\n"
         "    { when = { service = 'ftp' },              use = { type = 'ftp_server' } },\n"
         "    { when = { service = 'ftp-data' },         use = { type = 'ftp_data' } },\n"
         "    { when = { service = 'gtp' },              use = { type = 'gtp_inspect' } },\n"
         "    { when = { service = 'imap' },             use = { type = 'imap' } },\n"
         "    { when = { service = 'http' },             use = { type = 'http_inspect' } },\n"
         "    { when = { service = 'http2' },            use = { type = 'http2_inspect' } },\n"
         "    { when = { service = 'iec104' },           use = { type = 'iec104' } },\n"
         "    { when = { service = 'mms' },              use = { type = 'mms' } },\n"
         "    { when = { service = 'modbus' },           use = { type = 'modbus' } },\n"
         "    { when = { service = 'pop3' },             use = { type = 'pop' } },\n"
         "    { when = { service = 'ssh' },              use = { type = 'ssh' } },\n"
         "    { when = { service = 'sip' },              use = { type = 'sip' } },\n"
         "    { when = { service = 'smtp' },             use = { type = 'smtp' } },\n"
         "    { when = { service = 'ssl' },              use = { type = 'ssl' } },\n"
         "    { when = { service = 'sunrpc' },           use = { type = 'rpc_decode' } },\n"
         "    { when = { service = 's7commplus' },       use = { type = 's7commplus' } },\n"
         "    { when = { service = 'telnet' },           use = { type = 'telnet' } },\n\n"
         "    { use = { type = 'wizard' } }\n"
         "}\n\n"

         "references = default_references\n"
         "classifications = default_classifications\n";

  // DAQ
  out << "daq_module = 'afpacket'\n";
  out << "daq_mode = '" << (mode ? "inline" : "passive") << "'\n";

  // IPS block
  out << "ips = {\n";
  out << "  rules = [[\n";
  out << "    include " << (root / "rules" / "default.rules").string() << "\n";
  if (need_http)   { out << "    include " << (root / "rules" / "http.rules").string()   << "\n"; }
  if (need_telnet) { out << "    include " << (root / "rules" / "telnet.rules").string() << "\n"; }
  if (need_sql)    { out << "    include " << (root / "rules" / "sql.rules").string()    << "\n"; }
  if (need_ssh)    { out << "    include " << (root / "rules" / "ssh.rules").string()    << "\n"; }
  if (need_ftp)    { out << "    include " << (root / "rules" / "ftp.rules").string()    << "\n"; }
  out << "  ]],\n";
  out << "  mode = '" << (mode ? "inline" : "tap") << "',\n"
         "  enable_builtin_rules = false,\n"
         "  variables = default_variables,\n"
         "}\n\n";

  // Logging
  out << "alert_json = {\n"
         "    fields = 'timestamp seconds proto pkt_gen pkt_len dir src_ap dst_ap rule action msg class service',\n"
         "    file = true,\n"
         "    limit = 100,\n"
         "}\n\n";

  out << "pkt_logger = { file=true, limit=1000 }\n\n";

  out << "if ( tweaks ~= nil ) then\n"
         "    include(tweaks .. '.lua')\n"
         "end\n";

  out.close();
}
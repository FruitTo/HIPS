#include "./include/BS_thread_pool.hpp"
#include "./include/Interface.h"
#include "./include/date.h"
#include "./include/packet.h"
#include "./include/flow.h"
#include "./include/tins/tins.h"

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

using namespace std;
using namespace Tins;
using namespace BS;
using namespace chrono;
namespace fs = filesystem;
using SteadyClock = std::chrono::steady_clock; 

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
  string currentDay  = currentDate();
  string currentTime = timeStamp();
  string currentPath = getPath();
  filesystem::create_directories(currentPath);
  auto writer = std::make_unique<PacketWriter>(
      currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap",
      DataLinkType<EthernetII>());

  // Capture Packet (Sniffer)
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, config);

  std::unordered_map<string, Flow> flow_map;

  sniffer.sniff_loop([&](Packet &pkt) {
    // roll pcap file per day
    string date = currentDate();
    string path = getPath();
    if (currentDay != date) {
      currentDay  = date;
      currentPath = path;
      filesystem::create_directories(currentPath);
      writer = std::make_unique<PacketWriter>(
          currentPath + conf.NAME + "-" + currentDay + ".pcap",
          DataLinkType<EthernetII>());
    }
    writer->write(pkt);

    // ===== Parse with libtins =====
    PDU* pdu = pkt.pdu();
    if (!pdu) return true;

    // รองรับ IPv4 (คุณจะขยายเป็น IPv6 ได้ภายหลัง)
    const IP* ip = pdu->find_pdu<IP>();
    if (!ip) return true; // ข้ามเฟรมที่ไม่ใช่ IPv4

    const auto now = SteadyClock::now(); // timestamp ณ ตอนรับแพ็กเก็ต

    // flow key (ปรับได้ตามจริง เช่น รวมโปรโตคอล/พอร์ต)
    const string src_str = ip->src_addr().to_string();
    const string dst_str = ip->dst_addr().to_string();
    const string key     = src_str + ";" + dst_str + ";";

    Flow& flow = flow_map[key];

    // ทิศทาง: src != server ⇒ FWD, src == server ⇒ BWD
    const bool fwd = (src_str != conf.IP);

    // ----- ค่าที่ใช้ทำฟีเจอร์ความยาว/เฮดเดอร์ -----
    // L3 frame length (ให้สอดคล้องกับตอนเทรน): ip->size() = IP header + (L4 header + payload)
    const int frame_len_l3 = static_cast<int>(ip->size());
    const int ip_hdr_len   = static_cast<int>(ip->header_size());

    bool is_tcp  = false;
    bool is_udp  = false;
    bool is_icmp = false;

    bool syn=false, urg=false, psh=false;
    int  win=0;
    int  l4_hdr_len = 0;

    // ----- ตรวจ TCP -----
    if (const TCP* tcp = pdu->find_pdu<TCP>()) {
      is_tcp = true;
      // flags
      const uint8_t flags = tcp->flags();
      syn = (flags & TCP::SYN) != 0;
      urg = (flags & TCP::URG) != 0;
      psh = (flags & TCP::PSH) != 0;
      // window
      win = tcp->window();
      // TCP header length
      l4_hdr_len = static_cast<int>(tcp->header_size());

      // อัปเดต TCP-เฉพาะ
      flow.on_tcp_flags(syn, urg);
      if (fwd) flow.set_init_win_bytes_fwd(win);
      else     flow.set_init_win_bytes_bwd(win);
    }
    // ----- ตรวจ UDP -----
    else if (const UDP* udp = pdu->find_pdu<UDP>()) {
      is_udp = true;
      l4_hdr_len = static_cast<int>(udp->header_size()); // ปกติ 8
    }
    // ----- ตรวจ ICMP -----
    else if (const ICMP* icmp = pdu->find_pdu<ICMP>()) {
      is_icmp = true;
      l4_hdr_len = static_cast<int>(icmp->header_size()); // โดยทั่วไปราว 8
    } else {
      // โปรโตคอลอื่น: ใส่ l4_hdr_len = 0
      l4_hdr_len = 0;
    }

    // payload length (เฉพาะถ้าคุณนิยาม "segment = payload" ตอนเทรน)
    int payload_len = frame_len_l3 - (ip_hdr_len + l4_hdr_len);
    if (payload_len < 0) payload_len = -1; // unknown/ไม่ใช้

    // ----- เติมแพ็กเก็ตลง Flow -----
    const int hdr_total = ip_hdr_len + l4_hdr_len;

    if (fwd) {
      // PSH มีเฉพาะ TCP
      flow.add_fwd_packet(now, frame_len_l3, hdr_total, psh);
      // เฉพาะถ้าคุณนิยาม segment=payload และเป็น FWD เท่านั้น
      if (is_tcp && payload_len >= 0) flow.on_fwd_payload(payload_len);
    } else {
      flow.add_bwd_packet(now, frame_len_l3, hdr_total);
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
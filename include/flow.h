#ifndef FLOW_H
#define FLOW_H

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <climits>

using SteadyClock = std::chrono::steady_clock;

// ===== Common helpers =====
inline double duration_sec(SteadyClock::time_point first_ts, SteadyClock::time_point last_ts) {
    if (first_ts.time_since_epoch().count() == 0) return 0.0;
    auto d = last_ts - first_ts;
    return std::chrono::duration<double>(d).count();
}

inline double max_length(const std::vector<int>& v) {
    if (v.empty()) return 0.0;
    return static_cast<double>(*std::max_element(v.begin(), v.end()));
}

inline float mean_length(const std::vector<int>& v) {
    if (v.empty()) return 0.0f;
    double sum = 0; for (int x : v) sum += x;
    return static_cast<float>(sum / v.size());
}

inline float std_length(const std::vector<int>& v) {
    if (v.size() <= 1) return 0.0f;
    float m = mean_length(v);
    double var = 0; for (int x : v) { double d = x - m; var += d*d; }
    var /= v.size(); // population std
    return static_cast<float>(std::sqrt(var));
}

struct Stats {
    double sum = 0;
    double mean = 0;
    double stddev = 0;
    double min = 0;
    double max = 0;
};

inline Stats calc_stats(const std::vector<double>& iats) {
    Stats s;
    if (iats.empty()) return s;
    s.sum = std::accumulate(iats.begin(), iats.end(), 0.0);
    s.mean = s.sum / iats.size();
    s.min = *std::min_element(iats.begin(), iats.end());
    s.max = *std::max_element(iats.begin(), iats.end());
    double variance = 0.0;
    for (double v : iats) variance += (v - s.mean) * (v - s.mean);
    s.stddev = std::sqrt(variance / iats.size());
    return s;
}

// ===== Active/Idle helpers (จาก Flow IAT รวมทุกทิศ) =====
struct PeriodStats {
    float  mean = 0.0f;
    float  std  = 0.0f;
    double mx   = 0.0;
    double mn   = 0.0;
};

inline void calc_period_stats(const std::vector<double>& iats, double idle_threshold,
                              PeriodStats& active, PeriodStats& idle) {
    std::vector<double> active_periods, idle_periods;
    double acc = 0.0;
    bool in_active = true;
    bool any = false;

    for (double dt : iats) {
        bool is_active_gap = (dt <= idle_threshold);
        if (!any) { in_active = is_active_gap; any = true; }
        if (is_active_gap == in_active) acc += dt;
        else {
            if (acc > 0.0) {
                (in_active ? active_periods : idle_periods).push_back(acc);
            }
            in_active = is_active_gap;
            acc = dt;
        }
    }
    if (acc > 0.0) (in_active ? active_periods : idle_periods).push_back(acc);

    auto summarize = [](const std::vector<double>& v, PeriodStats& out) {
        if (v.empty()) { out = {}; return; }
        double s = std::accumulate(v.begin(), v.end(), 0.0);
        double m = s / v.size();
        double var = 0.0;
        for (double x : v) var += (x - m) * (x - m);
        var /= v.size();
        out.mean = static_cast<float>(m);
        out.std  = static_cast<float>(std::sqrt(var));
        out.mx   = *std::max_element(v.begin(), v.end());
        out.mn   = *std::min_element(v.begin(), v.end());
    };

    summarize(active_periods, active);
    summarize(idle_periods, idle);
}

// ===== Feature container (0–56) =====
struct Features
{
  int64_t flow_duration = 0;

  int32_t total_fwd_pkts = 0; // 1
  int32_t total_bwd_pkts = 0; // 2

  double fwd_len_total = 0.0; // 3
  double bwd_len_total = 0.0; // 4

  double fwd_len_max = 0.0;   // 5
  float  fwd_len_mean = 0.0f; // 6
  float  fwd_len_std  = 0.0f; // 7

  double bwd_len_max = 0.0;   // 8
  float  bwd_len_mean = 0.0f; // 9
  float  bwd_len_std  = 0.0f; // 10

  double flow_bytes_per_s = 0.0; // 11
  double flow_pkts_per_s  = 0.0; // 12

  float  flow_iat_mean = 0.0f; // 13
  float  flow_iat_std  = 0.0f; // 14
  double flow_iat_max  = 0.0;  // 15
  double flow_iat_min  = 0.0;  // 16

  double fwd_iat_total = 0.0; // 17
  float  fwd_iat_mean  = 0.0f; // 18
  float  fwd_iat_std   = 0.0f; // 19
  double fwd_iat_max   = 0.0;  // 20
  double fwd_iat_min   = 0.0;  // 21

  double bwd_iat_total = 0.0; // 22
  float  bwd_iat_mean  = 0.0f; // 23
  float  bwd_iat_std   = 0.0f; // 24
  double bwd_iat_max   = 0.0;  // 25
  double bwd_iat_min   = 0.0;  // 26

  int8_t  fwd_psh_flags = 0;         // 27
  int64_t fwd_header_len_total = 0;  // 28
  int64_t bwd_header_len_total = 0;  // 29

  float fwd_pkts_per_s = 0.0f; // 30
  float bwd_pkts_per_s = 0.0f; // 31

  double pkt_len_max  = 0.0;  // 32 (optional: ถ้าเก็บ global per-packet)
  float  pkt_len_mean = 0.0f; // 33
  float  pkt_len_std  = 0.0f; // 34
  float  pkt_len_var  = 0.0f; // 35

  int8_t syn_flag_count = 0; // 36
  int8_t urg_flag_count = 0; // 37

  float avg_pkt_size     = 0.0f; // 38
  float avg_fwd_seg_size = 0.0f; // 39
  float avg_bwd_seg_size = 0.0f; // 40

  int32_t subflow_fwd_pkts  = 0; // 41
  int32_t subflow_fwd_bytes = 0; // 42
  int32_t subflow_bwd_pkts  = 0; // 43
  int32_t subflow_bwd_bytes = 0; // 44

  int32_t init_fwd_win_bytes = 0; // 45
  int32_t init_bwd_win_bytes = 0; // 46

  int32_t fwd_act_data_pkts = 0; // 47
  int32_t fwd_seg_size_min  = 0; // 48

  float  active_mean = 0.0f; // 49
  float  active_std  = 0.0f; // 50
  double active_max  = 0.0;  // 51
  double active_min  = 0.0;  // 52

  float  idle_mean = 0.0f; // 53
  float  idle_std  = 0.0f; // 54
  double idle_max  = 0.0;  // 55
  double idle_min  = 0.0;  // 56
};

// ===== Flow accumulator =====
struct Flow {
  std::string key;

  // Time (for duration + flow IAT)
  SteadyClock::time_point first_ts{};
  SteadyClock::time_point last_ts{};      // last seen (any direction)
  SteadyClock::time_point last_any_ts{};  // for Flow-IAT

  // Per-direction last timestamp
  SteadyClock::time_point last_fwd_ts{};
  SteadyClock::time_point last_bwd_ts{};

  // Forward
  int32_t total_fwd = 0;
  double  total_fwd_length = 0.0;
  std::vector<int> fwd_length;

  // Backward
  int32_t total_bwd = 0;
  double  total_bwd_length = 0.0;
  std::vector<int> bwd_length;

  // Inter-Arrival Time lists
  std::vector<double> iat_list;      // any direction
  std::vector<double> iat_fwd_list;  // forward only
  std::vector<double> iat_bwd_list;  // backward only

  // TCP/Flags/Windows & header metrics
  int8_t syn_flag_count = 0;  // 36
  int8_t urg_flag_count = 0;  // 37
  int8_t fwd_psh_flags  = 0;  // 27

  int64_t fwd_header_len_total = 0;  // 28
  int64_t bwd_header_len_total = 0;  // 29

  int32_t init_fwd_win_bytes = -1; // 45
  int32_t init_bwd_win_bytes = -1; // 46

  int32_t fwd_act_data_pkts = 0;         // 47
  int32_t fwd_seg_size_min  = INT32_MAX; // 48 (payload len หรือ packet len ตามนิยามตอนเทรน)

  // Subflow placeholder (ยังไม่แยก subflow จริง ให้ใช้ค่ารวมเป็น default)
  int32_t subflow_fwd_pkts  = 0; // 41
  int32_t subflow_fwd_bytes = 0; // 42
  int32_t subflow_bwd_pkts  = 0; // 43
  int32_t subflow_bwd_bytes = 0; // 44

  // Active/Idle threshold (seconds) สำหรับ calc_period_stats จาก iat_list
  double idle_threshold = 1.0;

  // --- Event handlers ---
  inline void add_packet_any(SteadyClock::time_point now) {
      if (first_ts.time_since_epoch().count() == 0) {
          first_ts    = now;
          last_any_ts = now;
      } else {
          double dt = std::chrono::duration<double>(now - last_any_ts).count();
          if (dt >= 0.0) iat_list.push_back(dt);
          last_any_ts = now;
      }
      last_ts = now;
  }

  inline void add_fwd_packet(SteadyClock::time_point now, int pkt_len, int hdr_len=0, bool psh=false) {
      add_packet_any(now);
      if (last_fwd_ts.time_since_epoch().count() != 0) {
          double dt = std::chrono::duration<double>(now - last_fwd_ts).count();
          if (dt >= 0.0) iat_fwd_list.push_back(dt);
      }
      last_fwd_ts = now;

      total_fwd += 1;
      total_fwd_length += static_cast<double>(pkt_len);
      fwd_length.push_back(pkt_len);

      fwd_header_len_total += hdr_len;
      if (psh) fwd_psh_flags++;
  }

  inline void add_bwd_packet(SteadyClock::time_point now, int pkt_len, int hdr_len=0) {
      add_packet_any(now);
      if (last_bwd_ts.time_since_epoch().count() != 0) {
          double dt = std::chrono::duration<double>(now - last_bwd_ts).count();
          if (dt >= 0.0) iat_bwd_list.push_back(dt);
      }
      last_bwd_ts = now;

      total_bwd += 1;
      total_bwd_length += static_cast<double>(pkt_len);
      bwd_length.push_back(pkt_len);

      bwd_header_len_total += hdr_len;
  }

  inline void on_tcp_flags(bool syn, bool urg) {
      if (syn) syn_flag_count++;
      if (urg) urg_flag_count++;
  }

  inline void set_init_win_bytes_fwd(int32_t win_bytes) {
      if (init_fwd_win_bytes < 0) init_fwd_win_bytes = std::max(0, win_bytes);
  }
  inline void set_init_win_bytes_bwd(int32_t win_bytes) {
      if (init_bwd_win_bytes < 0) init_bwd_win_bytes = std::max(0, win_bytes);
  }

  // payload_len: ถ้านิยาม segment = payload; ถ้านิยาม segment = packet length ให้ส่ง pkt_len แทนภายนอก
  inline void on_fwd_payload(int payload_len) {
      if (payload_len > 0) fwd_act_data_pkts++;
      if (payload_len >= 0 && payload_len < fwd_seg_size_min) fwd_seg_size_min = payload_len;
  }

  // --- Finalize (เรียกเมื่อปิดโฟลว์เท่านั้น) ---
  inline void finalize(Features& out) const {
      // Duration (usec ตามชุดเทรน)
      double dur_s = duration_sec(first_ts, last_ts);
      out.flow_duration = static_cast<int64_t>(dur_s * 1e6);

      // Basic counts/bytes
      out.total_fwd_pkts = total_fwd;
      out.total_bwd_pkts = total_bwd;
      out.fwd_len_total  = total_fwd_length;
      out.bwd_len_total  = total_bwd_length;

      // Per-second (คำนวณที่นี่เท่านั้น)
      double bytes_total = total_fwd_length + total_bwd_length;
      double pkts_total  = static_cast<double>(total_fwd + total_bwd);
      out.flow_bytes_per_s = (dur_s > 0.0) ? (bytes_total / dur_s) : 0.0;
      out.flow_pkts_per_s  = (dur_s > 0.0) ? (pkts_total  / dur_s) : 0.0;
      out.fwd_pkts_per_s   = (dur_s > 0.0) ? static_cast<float>(total_fwd / dur_s) : 0.0f;
      out.bwd_pkts_per_s   = (dur_s > 0.0) ? static_cast<float>(total_bwd / dur_s) : 0.0f;

      // Length stats
      out.fwd_len_max  = max_length(fwd_length);
      out.fwd_len_mean = mean_length(fwd_length);
      out.fwd_len_std  = std_length(fwd_length);

      out.bwd_len_max  = max_length(bwd_length);
      out.bwd_len_mean = mean_length(bwd_length);
      out.bwd_len_std  = std_length(bwd_length);

      // Flow IAT (13–16)
      {
          Stats s = calc_stats(iat_list);
          out.flow_iat_mean = static_cast<float>(s.mean);
          out.flow_iat_std  = static_cast<float>(s.stddev);
          out.flow_iat_max  = s.max;
          out.flow_iat_min  = s.min;
      }
      // Fwd IAT (17–21)
      {
          Stats s = calc_stats(iat_fwd_list);
          out.fwd_iat_total = s.sum;
          out.fwd_iat_mean  = static_cast<float>(s.mean);
          out.fwd_iat_std   = static_cast<float>(s.stddev);
          out.fwd_iat_max   = s.max;
          out.fwd_iat_min   = s.min;
      }
      // Bwd IAT (22–26)
      {
          Stats s = calc_stats(iat_bwd_list);
          out.bwd_iat_total = s.sum;
          out.bwd_iat_mean  = static_cast<float>(s.mean);
          out.bwd_iat_std   = static_cast<float>(s.stddev);
          out.bwd_iat_max   = s.max;
          out.bwd_iat_min   = s.min;
      }

      // 27–29: PSH + header length totals
      out.fwd_psh_flags        = fwd_psh_flags;
      out.fwd_header_len_total = fwd_header_len_total;
      out.bwd_header_len_total = bwd_header_len_total;

      // 36–37: TCP flags
      out.syn_flag_count = syn_flag_count;
      out.urg_flag_count = urg_flag_count;

      // 38: Avg Packet Size
      {
          int pkts_total_i = total_fwd + total_bwd;
          out.avg_pkt_size = (pkts_total_i > 0)
              ? static_cast<float>((total_fwd_length + total_bwd_length) / pkts_total_i)
              : 0.0f;
      }

      // 39–40: Avg segment size ต่อทิศ (ใช้ mean ของ packet length โดยดีฟอลต์)
      out.avg_fwd_seg_size = out.fwd_len_mean;
      out.avg_bwd_seg_size = out.bwd_len_mean;

      // 41–44: Subflow (ถ้ายังไม่แยก ให้ใช้ค่ารวม)
      out.subflow_fwd_pkts  = (subflow_fwd_pkts  > 0) ? subflow_fwd_pkts  : total_fwd;
      out.subflow_fwd_bytes = (subflow_fwd_bytes > 0) ? subflow_fwd_bytes : static_cast<int32_t>(total_fwd_length);
      out.subflow_bwd_pkts  = (subflow_bwd_pkts  > 0) ? subflow_bwd_pkts  : total_bwd;
      out.subflow_bwd_bytes = (subflow_bwd_bytes > 0) ? subflow_bwd_bytes : static_cast<int32_t>(total_bwd_length);

      // 45–46: Init window bytes
      out.init_fwd_win_bytes = (init_fwd_win_bytes < 0) ? 0 : init_fwd_win_bytes;
      out.init_bwd_win_bytes = (init_bwd_win_bytes < 0) ? 0 : init_bwd_win_bytes;

      // 47: Fwd active data pkts
      out.fwd_act_data_pkts = fwd_act_data_pkts;

      // 48: Fwd seg size min
      out.fwd_seg_size_min = (fwd_seg_size_min == INT32_MAX) ? 0 : fwd_seg_size_min;

      // 49–56: Active/Idle จาก Flow IAT
      {
          PeriodStats A, I;
          calc_period_stats(iat_list, idle_threshold, A, I);
          out.active_mean = A.mean;
          out.active_std  = A.std;
          out.active_max  = A.mx;
          out.active_min  = A.mn;

          out.idle_mean = I.mean;
          out.idle_std  = I.std;
          out.idle_max  = I.mx;
          out.idle_min  = I.mn;
      }
  }
};

#endif // FLOW_H

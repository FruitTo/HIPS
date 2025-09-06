#ifndef FLOW_H
#define FLOW_H

#include <cstdint>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <limits>

// ===== TCP flag bits (global scope) =====
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;
constexpr uint8_t TCP_ECE = 0x40;
constexpr uint8_t TCP_CWR = 0x80;

constexpr double MICRO = 1e6;

// ----- helpers -----
inline int8_t clamp_i8(int64_t v) {
    if (v < 0) return 0;
    if (v > std::numeric_limits<int8_t>::max()) return std::numeric_limits<int8_t>::max();
    return static_cast<int8_t>(v);
}
inline int32_t clamp_i32(int64_t v) {
    if (v < std::numeric_limits<int32_t>::min()) return std::numeric_limits<int32_t>::min();
    if (v > std::numeric_limits<int32_t>::max()) return std::numeric_limits<int32_t>::max();
    return static_cast<int32_t>(v);
}

template <class T>
inline double mean_pop(const std::vector<T>& a) {
    if (a.empty()) return 0.0;
    return std::accumulate(a.begin(), a.end(), 0.0) / static_cast<double>(a.size());
}
template <class T>
inline double var_pop(const std::vector<T>& a, double mean) {
    if (a.empty()) return 0.0;
    double acc = 0.0;
    for (auto v : a) {
        double d = static_cast<double>(v) - mean;
        acc += d * d;
    }
    return acc / static_cast<double>(a.size());
}
template <class T>
inline double std_pop(const std::vector<T>& a, double mean) {
    return std::sqrt(var_pop(a, mean));
}

template <class T>
inline T vec_min(const std::vector<T>& a) {
    if (a.empty()) return T(0);
    return *std::min_element(a.begin(), a.end());
}
template <class T>
inline T vec_max(const std::vector<T>& a) {
    if (a.empty()) return T(0);
    return *std::max_element(a.begin(), a.end());
}

// IAT from ordered timestamps (seconds)
inline std::vector<double> make_iat_seconds(const std::vector<double>& ts) {
    std::vector<double> out;
    if (ts.size() < 2) return out;
    out.reserve(ts.size() - 1);
    for (size_t i = 1; i < ts.size(); ++i) {
        double dt = ts[i] - ts[i - 1];
        if (dt < 0) dt = 0; // guard non-decreasing
        out.push_back(dt);
    }
    return out;
}

// Active/Idle periods from IAT (seconds)
struct PeriodStats { double mean=0, std=0, mn=0, mx=0; };

inline PeriodStats to_us_stats(const std::vector<double>& periods_s) {
    PeriodStats ps;
    if (periods_s.empty()) return ps;
    std::vector<double> us; us.reserve(periods_s.size());
    for (auto s : periods_s) us.push_back(s * MICRO);
    double m = mean_pop(us);
    ps.mean = m;
    ps.std  = std_pop(us, m);
    ps.mn   = vec_min(us);
    ps.mx   = vec_max(us);
    return ps;
}

inline void build_active_idle_stats(
    const std::vector<double>& iat_s,
    double idle_thr_s,
    PeriodStats& active_us, PeriodStats& idle_us
) {
    std::vector<double> active_s;
    std::vector<double> idle_s;
    double acc = 0.0;
    for (auto dt : iat_s) {
        if (dt <= idle_thr_s) {
            acc += dt;
        } else {
            if (acc > 0.0) { active_s.push_back(acc); acc = 0.0; }
            idle_s.push_back(dt);
        }
    }
    if (acc > 0.0) active_s.push_back(acc);
    active_us = to_us_stats(active_s);
    idle_us   = to_us_stats(idle_s);
}

struct Features {
    // 0
    int64_t  flow_duration = 0;                   // µs

    // 1-2
    int32_t  total_fwd_packets = 0;
    int32_t  total_bwd_packets = 0;

    // 3-4
    double   fwd_packets_length_total = 0;        // bytes
    double   bwd_packets_length_total = 0;

    // 5-7
    double   fwd_packet_length_max = 0;
    float    fwd_packet_length_mean = 0;
    float    fwd_packet_length_std = 0;

    // 8-10
    double   bwd_packet_length_max = 0;
    float    bwd_packet_length_mean = 0;
    float    bwd_packet_length_std = 0;

    // 11-12
    double   flow_bytes_per_s = 0;
    double   flow_packets_per_s = 0;

    // 13-16 (µs)
    float    flow_iat_mean = 0;
    float    flow_iat_std  = 0;
    double   flow_iat_max  = 0;
    double   flow_iat_min  = 0;

    // 17-21 (µs)
    double   fwd_iat_total = 0;
    float    fwd_iat_mean  = 0;
    float    fwd_iat_std   = 0;
    double   fwd_iat_max   = 0;
    double   fwd_iat_min   = 0;

    // 22-26 (µs)
    double   bwd_iat_total = 0;
    float    bwd_iat_mean  = 0;
    float    bwd_iat_std   = 0;
    double   bwd_iat_max   = 0;
    double   bwd_iat_min   = 0;

    // 27-29
    int8_t   fwd_psh_flags = 0;
    int64_t  fwd_header_length = 0;               // bytes
    int64_t  bwd_header_length = 0;

    // 30-31
    float    fwd_packets_per_s = 0;
    float    bwd_packets_per_s = 0;

    // 32-35 (all directions)
    double   packet_length_max = 0;
    float    packet_length_mean = 0;
    float    packet_length_std  = 0;
    float    packet_length_variance = 0;

    // 36-37 (two-way)
    int8_t   syn_flag_count = 0;
    int8_t   urg_flag_count = 0;

    // 38-40
    float    avg_packet_size = 0;
    float    avg_fwd_segment_size = 0;
    float    avg_bwd_segment_size = 0;

    // 41-44 (subflow fallback = totals)
    int32_t  subflow_fwd_packets = 0;
    int32_t  subflow_fwd_bytes   = 0;
    int32_t  subflow_bwd_packets = 0;
    int32_t  subflow_bwd_bytes   = 0;

    // 45-46 (TCP only; else 0)
    int32_t  init_fwd_win_bytes = 0;
    int32_t  init_bwd_win_bytes = 0;

    // 47-48
    int32_t  fwd_act_data_pkts = 0;               // payload > 0
    int32_t  fwd_seg_size_min  = 0;               // min FWD packet length (bytes)

    // 49-52 Active periods (µs)
    float    active_mean = 0;
    float    active_std  = 0;
    double   active_max  = 0;
    double   active_min  = 0;

    // 53-56 Idle periods (µs)
    float    idle_mean = 0;
    float    idle_std  = 0;
    double   idle_max  = 0;
    double   idle_min  = 0;
};

// ================== Functional Flow state & functions ==================

// เดิมเป็น private fields ของ class
struct FlowState {
    // --- Timestamps (seconds) ---
    // ของเดิม
    double first_ts = 0.0;
    double last_ts  = 0.0;

    // เพิ่ม alias ฟิลด์ให้ตรงกับโค้ดใน main.cpp
    // หมายเหตุ: โค้ดปัจจุบันจะอัปเดตทั้งคู่ (เช่น first_ts และ first_ts_sec)
    // จึงตั้งค่าเริ่มต้นให้เท่ากัน และปล่อยให้โค้ดอัปเดตไปตามการใช้งาน
    double first_ts_sec  = 0.0;  // ใช้แทน first_ts ในบางจุดของ main.cpp
    double last_seen_sec = 0.0;  // ใช้แทน last_ts ในบางจุดของ main.cpp

    // --- L4 protocol (เพิ่มให้ตรงกับ main.cpp) ---
    // ควรเก็บค่าตาม IPPROTO_* (เช่น TCP=6, UDP=17)
    int l4_proto = 0;

    // --- Flow lifecycle ---
    bool started = false;

    // --- Packet/byte counters ---
    int64_t cnt_fwd   = 0;
    int64_t cnt_bwd   = 0;
    int64_t bytes_fwd = 0;
    int64_t bytes_bwd = 0;

    // --- Header length sums ---
    int64_t fwd_hdr_len_sum = 0;
    int64_t bwd_hdr_len_sum = 0;

    // --- TCP window sizes (initial seen) ---
    int32_t init_fwd_win_bytes = 0;
    int32_t init_bwd_win_bytes = 0;

    // --- Active data pkts (forward) ---
    int64_t fwd_act_data_pkts = 0;

    // --- TCP flags counters ---
    int64_t psh_fwd   = 0;
    int64_t syn_flags = 0;
    int64_t urg_flags = 0;

    // --- Segmentation / MSS-like stat ---
    int     min_fwd_seg = -1;

    // --- Per-direction payload lengths ---
    std::vector<int32_t> fwd_len;
    std::vector<int32_t> bwd_len;

    // --- All-packet features ---
    std::vector<int32_t> pkt_len_all;
    std::vector<double>  times_all;
    std::vector<double>  times_fwd;
    std::vector<double>  times_bwd;
};

inline void flow_init(FlowState& s) { s = FlowState{}; }

inline void flow_add_packet(
    FlowState& s,
    bool     is_fwd,
    double   ts_sec,
    int32_t  pkt_len,
    int32_t  ip_hdr_len,
    int32_t  l4_hdr_len,
    bool     is_tcp,
    uint8_t  tcp_flags,
    int32_t  tcp_window_bytes,
    int32_t  payload_len
) {
    if (!s.started) {
        s.first_ts = ts_sec;
        s.started = true;
    }
    if (ts_sec < s.last_ts) ts_sec = s.last_ts; // enforce non-decreasing
    s.last_ts = ts_sec;

    // Common accumulators
    s.times_all.push_back(ts_sec);
    s.pkt_len_all.push_back(std::max(0, pkt_len));

    // Header sum (bytes)
    int64_t hdr_sum = static_cast<int64_t>(std::max(0, ip_hdr_len)) +
                      static_cast<int64_t>(std::max(0, l4_hdr_len));

    // Flags (two-way)
    if (is_tcp) {
        if (tcp_flags & TCP_SYN) ++s.syn_flags;
        if (tcp_flags & TCP_URG) ++s.urg_flags;
    }

    if (is_fwd) {
        ++s.cnt_fwd;
        s.bytes_fwd += std::max(0, pkt_len);
        s.fwd_len.push_back(std::max(0, pkt_len));
        s.fwd_hdr_len_sum += hdr_sum;
        s.times_fwd.push_back(ts_sec);

        if (is_tcp && (tcp_flags & TCP_PSH)) ++s.psh_fwd;

        if (is_tcp && s.init_fwd_win_bytes == 0 && tcp_window_bytes > 0)
            s.init_fwd_win_bytes = tcp_window_bytes;

        if (payload_len > 0) ++s.fwd_act_data_pkts;

        if (s.min_fwd_seg < 0 || pkt_len < s.min_fwd_seg)
            s.min_fwd_seg = std::max(0, pkt_len);
    } else {
        ++s.cnt_bwd;
        s.bytes_bwd += std::max(0, pkt_len);
        s.bwd_len.push_back(std::max(0, pkt_len));
        s.bwd_hdr_len_sum += hdr_sum;
        s.times_bwd.push_back(ts_sec);

        if (is_tcp && s.init_bwd_win_bytes == 0 && tcp_window_bytes > 0)
            s.init_bwd_win_bytes = tcp_window_bytes;
    }
}

inline void flow_finalize(const FlowState& s, Features& out, double idle_threshold_sec = 1.0) {
    // -------- duration --------
    double duration_s = s.started ? (s.last_ts - s.first_ts) : 0.0;
    if (duration_s < 0) duration_s = 0.0;
    out.flow_duration = static_cast<int64_t>(duration_s * MICRO); // µs

    // -------- simple counters --------
    out.total_fwd_packets = static_cast<int32_t>(s.cnt_fwd);
    out.total_bwd_packets = static_cast<int32_t>(s.cnt_bwd);

    out.fwd_packets_length_total = static_cast<double>(s.bytes_fwd);
    out.bwd_packets_length_total = static_cast<double>(s.bytes_bwd);

    // FWD stats
    double fwd_mean = mean_pop(s.fwd_len);
    double fwd_std  = std_pop(s.fwd_len, fwd_mean);
    out.fwd_packet_length_max  = static_cast<double>(vec_max(s.fwd_len));
    out.fwd_packet_length_mean = static_cast<float>(fwd_mean);
    out.fwd_packet_length_std  = static_cast<float>(fwd_std);

    // BWD stats
    double bwd_mean = mean_pop(s.bwd_len);
    double bwd_std  = std_pop(s.bwd_len, bwd_mean);
    out.bwd_packet_length_max  = static_cast<double>(vec_max(s.bwd_len));
    out.bwd_packet_length_mean = static_cast<float>(bwd_mean);
    out.bwd_packet_length_std  = static_cast<float>(bwd_std);

    // Rates
    double total_bytes = static_cast<double>(s.bytes_fwd + s.bytes_bwd);
    double total_pkts  = static_cast<double>(s.cnt_fwd + s.cnt_bwd);
    out.flow_bytes_per_s   = (duration_s > 0.0) ? (total_bytes / duration_s) : 0.0;
    out.flow_packets_per_s = (duration_s > 0.0) ? (total_pkts  / duration_s) : 0.0;

    out.fwd_packets_per_s = static_cast<float>((duration_s > 0.0)
                                ? (static_cast<double>(s.cnt_fwd) / duration_s) : 0.0);
    out.bwd_packets_per_s = static_cast<float>((duration_s > 0.0)
                                ? (static_cast<double>(s.cnt_bwd) / duration_s) : 0.0);

    // -------- IAT (convert to µs) --------
    auto iat_all = make_iat_seconds(s.times_all);
    auto iat_fwd = make_iat_seconds(s.times_fwd);
    auto iat_bwd = make_iat_seconds(s.times_bwd);

    // Flow IAT
    if (!iat_all.empty()) {
        std::vector<double> us; us.reserve(iat_all.size());
        for (auto sec : iat_all) us.push_back(sec * MICRO);
        double m = mean_pop(us);
        out.flow_iat_mean = static_cast<float>(m);
        out.flow_iat_std  = static_cast<float>(std_pop(us, m));
        out.flow_iat_max  = vec_max(us);
        out.flow_iat_min  = vec_min(us);
    } else {
        out.flow_iat_mean = 0; out.flow_iat_std = 0;
        out.flow_iat_max = 0;  out.flow_iat_min = 0;
    }

    // FWD IAT
    if (!iat_fwd.empty()) {
        std::vector<double> us; us.reserve(iat_fwd.size());
        for (auto sec : iat_fwd) us.push_back(sec * MICRO);
        double m = mean_pop(us);
        out.fwd_iat_total = std::accumulate(us.begin(), us.end(), 0.0);
        out.fwd_iat_mean  = static_cast<float>(m);
        out.fwd_iat_std   = static_cast<float>(std_pop(us, m));
        out.fwd_iat_max   = vec_max(us);
        out.fwd_iat_min   = vec_min(us);
    } else {
        out.fwd_iat_total = 0; out.fwd_iat_mean = 0; out.fwd_iat_std = 0;
        out.fwd_iat_max = 0;   out.fwd_iat_min = 0;
    }

    // BWD IAT
    if (!iat_bwd.empty()) {
        std::vector<double> us; us.reserve(iat_bwd.size());
        for (auto sec : iat_bwd) us.push_back(sec * MICRO);
        double m = mean_pop(us);
        out.bwd_iat_total = std::accumulate(us.begin(), us.end(), 0.0);
        out.bwd_iat_mean  = static_cast<float>(m);
        out.bwd_iat_std   = static_cast<float>(std_pop(us, m));
        out.bwd_iat_max   = vec_max(us);
        out.bwd_iat_min   = vec_min(us);
    } else {
        out.bwd_iat_total = 0; out.bwd_iat_mean = 0; out.bwd_iat_std = 0;
        out.bwd_iat_max = 0;   out.bwd_iat_min = 0;
    }

    // -------- headers & flags --------
    out.fwd_psh_flags     = clamp_i8(s.psh_fwd);
    out.fwd_header_length = s.fwd_hdr_len_sum;
    out.bwd_header_length = s.bwd_hdr_len_sum;

    out.syn_flag_count = clamp_i8(s.syn_flags);
    out.urg_flag_count = clamp_i8(s.urg_flags);

    // -------- Packet length (all directions) #32–35 --------
    double all_mean = mean_pop(s.pkt_len_all);
    double all_std  = std_pop(s.pkt_len_all, all_mean);
    out.packet_length_max      = static_cast<double>(vec_max(s.pkt_len_all));
    out.packet_length_mean     = static_cast<float>(all_mean);
    out.packet_length_std      = static_cast<float>(all_std);
    out.packet_length_variance = static_cast<float>(all_std * all_std);

    // -------- averages --------
    out.avg_packet_size      = static_cast<float>((total_pkts > 0.0) ? (total_bytes / total_pkts) : 0.0);
    out.avg_fwd_segment_size = static_cast<float>(fwd_mean);
    out.avg_bwd_segment_size = static_cast<float>(bwd_mean);

    // -------- subflow fallback (totals) --------
    out.subflow_fwd_packets = static_cast<int32_t>(s.cnt_fwd);
    out.subflow_fwd_bytes   = clamp_i32(s.bytes_fwd);
    out.subflow_bwd_packets = static_cast<int32_t>(s.cnt_bwd);
    out.subflow_bwd_bytes   = clamp_i32(s.bytes_bwd);

    // -------- TCP init win --------
    out.init_fwd_win_bytes = s.init_fwd_win_bytes;
    out.init_bwd_win_bytes = s.init_bwd_win_bytes;

    // -------- active data pkts (FWD) --------
    out.fwd_act_data_pkts = static_cast<int32_t>(s.fwd_act_data_pkts);

    // -------- Fwd Seg Size Min (#48) --------
    out.fwd_seg_size_min = (s.min_fwd_seg < 0) ? 0 : static_cast<int32_t>(s.min_fwd_seg);

    // -------- Active/Idle periods (µs) --------
    PeriodStats A, I;
    build_active_idle_stats(iat_all, idle_threshold_sec, A, I);
    out.active_mean = static_cast<float>(A.mean);
    out.active_std  = static_cast<float>(A.std);
    out.active_max  = A.mx;
    out.active_min  = A.mn;

    out.idle_mean = static_cast<float>(I.mean);
    out.idle_std  = static_cast<float>(I.std);
    out.idle_max  = I.mx;
    out.idle_min  = I.mn;
}

inline void flow_reset(FlowState& s) { flow_init(s); }

// Pack to float32 vector in order 0..56 (for ONNX input)
inline void features_to_float_vector(const Features& f, std::vector<float>& out) {
    out.clear(); out.reserve(57);
    out.push_back(static_cast<float>(f.flow_duration));                // 0 (µs)
    out.push_back(static_cast<float>(f.total_fwd_packets));            // 1
    out.push_back(static_cast<float>(f.total_bwd_packets));            // 2
    out.push_back(static_cast<float>(f.fwd_packets_length_total));     // 3
    out.push_back(static_cast<float>(f.bwd_packets_length_total));     // 4
    out.push_back(static_cast<float>(f.fwd_packet_length_max));        // 5
    out.push_back(static_cast<float>(f.fwd_packet_length_mean));       // 6
    out.push_back(static_cast<float>(f.fwd_packet_length_std));        // 7
    out.push_back(static_cast<float>(f.bwd_packet_length_max));        // 8
    out.push_back(static_cast<float>(f.bwd_packet_length_mean));       // 9
    out.push_back(static_cast<float>(f.bwd_packet_length_std));        // 10
    out.push_back(static_cast<float>(f.flow_bytes_per_s));             // 11
    out.push_back(static_cast<float>(f.flow_packets_per_s));           // 12
    out.push_back(static_cast<float>(f.flow_iat_mean));                // 13 (µs)
    out.push_back(static_cast<float>(f.flow_iat_std));                 // 14 (µs)
    out.push_back(static_cast<float>(f.flow_iat_max));                 // 15 (µs)
    out.push_back(static_cast<float>(f.flow_iat_min));                 // 16 (µs)
    out.push_back(static_cast<float>(f.fwd_iat_total));                // 17 (µs)
    out.push_back(static_cast<float>(f.fwd_iat_mean));                 // 18 (µs)
    out.push_back(static_cast<float>(f.fwd_iat_std));                  // 19 (µs)
    out.push_back(static_cast<float>(f.fwd_iat_max));                  // 20 (µs)
    out.push_back(static_cast<float>(f.fwd_iat_min));                  // 21 (µs)
    out.push_back(static_cast<float>(f.bwd_iat_total));                // 22 (µs)
    out.push_back(static_cast<float>(f.bwd_iat_mean));                 // 23 (µs)
    out.push_back(static_cast<float>(f.bwd_iat_std));                  // 24 (µs)
    out.push_back(static_cast<float>(f.bwd_iat_max));                  // 25 (µs)
    out.push_back(static_cast<float>(f.bwd_iat_min));                  // 26 (µs)
    out.push_back(static_cast<float>(f.fwd_psh_flags));                // 27
    out.push_back(static_cast<float>(f.fwd_header_length));            // 28
    out.push_back(static_cast<float>(f.bwd_header_length));            // 29
    out.push_back(static_cast<float>(f.fwd_packets_per_s));            // 30
    out.push_back(static_cast<float>(f.bwd_packets_per_s));            // 31
    out.push_back(static_cast<float>(f.packet_length_max));            // 32
    out.push_back(static_cast<float>(f.packet_length_mean));           // 33
    out.push_back(static_cast<float>(f.packet_length_std));            // 34
    out.push_back(static_cast<float>(f.packet_length_variance));       // 35
    out.push_back(static_cast<float>(f.syn_flag_count));               // 36
    out.push_back(static_cast<float>(f.urg_flag_count));               // 37
    out.push_back(static_cast<float>(f.avg_packet_size));              // 38
    out.push_back(static_cast<float>(f.avg_fwd_segment_size));         // 39
    out.push_back(static_cast<float>(f.avg_bwd_segment_size));         // 40
    out.push_back(static_cast<float>(f.subflow_fwd_packets));          // 41
    out.push_back(static_cast<float>(f.subflow_fwd_bytes));            // 42
    out.push_back(static_cast<float>(f.subflow_bwd_packets));          // 43
    out.push_back(static_cast<float>(f.subflow_bwd_bytes));            // 44
    out.push_back(static_cast<float>(f.init_fwd_win_bytes));           // 45
    out.push_back(static_cast<float>(f.init_bwd_win_bytes));           // 46
    out.push_back(static_cast<float>(f.fwd_act_data_pkts));            // 47
    out.push_back(static_cast<float>(f.fwd_seg_size_min));             // 48
    out.push_back(static_cast<float>(f.active_mean));                  // 49 (µs)
    out.push_back(static_cast<float>(f.active_std));                   // 50 (µs)
    out.push_back(static_cast<float>(f.active_max));                   // 51 (µs)
    out.push_back(static_cast<float>(f.active_min));                   // 52 (µs)
    out.push_back(static_cast<float>(f.idle_mean));                    // 53 (µs)
    out.push_back(static_cast<float>(f.idle_std));                     // 54 (µs)
    out.push_back(static_cast<float>(f.idle_max));                     // 55 (µs)
    out.push_back(static_cast<float>(f.idle_min));                     // 56 (µs)
}

#endif // FLOW_H

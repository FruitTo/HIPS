
#include <bits/stdc++.h>
#include "ids_runner.cpp"   // <-- make sure ids_fn.cpp is in the same directory

using namespace std;

static inline string lower(string s){
    transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

// Helper: set feature if its (lowercased) name contains any of the given needles
static void set_if_name_contains(unordered_map<string,float>& fmap,
                                 const vector<string>& feature_order,
                                 const vector<string>& needles,
                                 float value){
    for(const auto& fname: feature_order){
        string lf = lower(fname);
        bool ok=false; for(const auto& nd: needles){ if(lf.find(nd)!=string::npos){ ok=true; break; } }
        if(ok){ fmap[fname] = value; }
    }
}

int main(int argc, char** argv){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    string artifacts = (argc>=2? argv[1] : string("./artifacts"));
    int n_packets = (argc>=3? stoi(argv[2]) : 10);

    IDSContext ctx = ids_init(artifacts);

    // Simulated flow state
    int tot_fwd_pkts=0, tot_bwd_pkts=0;
    int totlen_fwd=0, totlen_bwd=0; // bytes
    double now_ms = 0.0;
    double last_ms = 0.0;

    std::mt19937 rng(123);
    std::uniform_int_distribution<int> len_fwd(60, 900);
    std::uniform_int_distribution<int> len_bwd(60, 700);

    cout << "Simulating " << n_packets << " packets...\n";

    for(int i=1;i<=n_packets;++i){
        bool dir_fwd = (i%2==1); // alternate fwd/bwd for demo
        int len = dir_fwd? len_fwd(rng) : len_bwd(rng);
        if(dir_fwd){ tot_fwd_pkts++; totlen_fwd += len; }
        else       { tot_bwd_pkts++; totlen_bwd += len; }

        // time update
        double iat = 3.0 + (i%5); // ms between packets (toy model)
        now_ms += iat;            // advance clock
        double flow_dur = now_ms; // start at 0

        // simple stats
        double fwd_mean = (tot_fwd_pkts>0)? (double)totlen_fwd / (double)tot_fwd_pkts : NAN;
        double bwd_mean = (tot_bwd_pkts>0)? (double)totlen_bwd / (double)tot_bwd_pkts : NAN;
        double flow_iat_mean = (i>0)? now_ms / (double)i : NAN;

        unordered_map<string,float> fmap;

        // Attempt to set common CIC-IDS style fields if present in meta names
        set_if_name_contains(fmap, ctx.feature_order, {"flow duration"}, (float)flow_dur);
        set_if_name_contains(fmap, ctx.feature_order, {"tot fwd pkts", "total fwd pkts", "totfwd"}, (float)tot_fwd_pkts);
        set_if_name_contains(fmap, ctx.feature_order, {"tot bwd pkts", "total bwd pkts", "totbwd"}, (float)tot_bwd_pkts);
        set_if_name_contains(fmap, ctx.feature_order, {"totlen fwd", "total len fwd"}, (float)totlen_fwd);
        set_if_name_contains(fmap, ctx.feature_order, {"totlen bwd", "total len bwd"}, (float)totlen_bwd);
        set_if_name_contains(fmap, ctx.feature_order, {"fwd pkt len mean", "fwd packet length mean"}, (float)fwd_mean);
        set_if_name_contains(fmap, ctx.feature_order, {"bwd pkt len mean", "bwd packet length mean"}, (float)bwd_mean);
        set_if_name_contains(fmap, ctx.feature_order, {"flow iat mean"}, (float)flow_iat_mean);
        set_if_name_contains(fmap, ctx.feature_order, {"fwd iat mean"}, (float)(dir_fwd? iat : NAN));
        set_if_name_contains(fmap, ctx.feature_order, {"bwd iat mean"}, (float)(!dir_fwd? iat : NAN));

        IDSResult r = ids_predict(ctx, fmap);
        cout << "pkt:" << i
             << (dir_fwd? " FWD":" BWD")
             << " len=" << len
             << "  -> " << (r.is_attack? "ATTACK":"BENIGN")
             << "  p_attack=" << fixed << setprecision(4) << r.p_attack
             << "  class_id=" << r.class_id
             << "  class_name=" << r.class_name
             << "  class_prob=" << r.class_prob
             << "\n";

        last_ms = now_ms;
    }

    return 0;
}

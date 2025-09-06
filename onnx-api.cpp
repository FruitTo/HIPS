#include <nlohmann/json.hpp>
#include <unordered_map>
#include <string>
#include <vector>
#include <limits>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <array>
#include "ids_api.h"   // มีทั้ง IDSResult + IDSContext

using json = nlohmann::json;

namespace {  // ===== helpers ภายในไฟล์ =====

std::string norm_key(std::string s){
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    s.erase(std::remove_if(s.begin(), s.end(),
                           [](unsigned char c){ return !std::isalnum(c); }), s.end());
    return s;
}

json load_json(const std::string& path){
    std::ifstream f(path);
    if(!f) throw std::runtime_error("cannot open: " + path);
    return json::parse(f, nullptr, true, true);
}

void cache_names(Ort::Session& s,
                 size_t in_cnt, size_t out_cnt,
                 std::vector<Ort::AllocatedStringPtr>& in_hold,
                 std::vector<const char*>& in_names,
                 std::vector<Ort::AllocatedStringPtr>& out_hold,
                 std::vector<const char*>& out_names){
    Ort::AllocatorWithDefaultOptions alloc;
    in_hold.reserve(in_cnt); in_names.reserve(in_cnt);
    out_hold.reserve(out_cnt); out_names.reserve(out_cnt);
    for(size_t i=0;i<in_cnt;++i){
        in_hold.emplace_back(s.GetInputNameAllocated(i, alloc));
        in_names.push_back(in_hold.back().get());
    }
    for(size_t i=0;i<out_cnt;++i){
        out_hold.emplace_back(s.GetOutputNameAllocated(i, alloc));
        out_names.push_back(out_hold.back().get());
    }
}

const float* pick_prob_tensor(const std::vector<Ort::Value>& outs, size_t& len_out){
    for(const auto& v: outs){
        if(!v.IsTensor()) continue;
        auto ti = v.GetTensorTypeAndShapeInfo();
        if(ti.GetElementType()!=ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) continue;
        size_t total = ti.GetElementCount();
        if(total >= 2){ len_out = total; return v.GetTensorData<float>(); }
    }
    len_out = 0; return nullptr;
}

} // namespace

// ===== API นิยามจริง =====

IDSContext ids_init(const std::string& artifacts_dir,
                    const std::string& bin_name,
                    const std::string& mul_name,
                    const std::string& meta_name,
                    const std::string& thr_name){
    IDSContext ctx;

    const std::string bin_path  = artifacts_dir + "/" + bin_name;
    const std::string mul_path  = artifacts_dir + "/" + mul_name;
    const std::string meta_path = artifacts_dir + "/" + meta_name;
    const std::string thr_path  = artifacts_dir + "/" + thr_name;

    // Meta
    {
        json meta = load_json(meta_path);
        if(!meta.contains("feature_order") || !meta["feature_order"].is_array())
            throw std::runtime_error("meta.json missing feature_order[]");
        ctx.feature_order = meta["feature_order"].get<std::vector<std::string>>();
        ctx.n_features = static_cast<int64_t>(ctx.feature_order.size());
        ctx.feat_index.reserve(ctx.feature_order.size());
        for(size_t i=0;i<ctx.feature_order.size();++i){
            ctx.feat_index[norm_key(ctx.feature_order[i])] = static_cast<int>(i);
        }
        if(meta.contains("class_map") && meta["class_map"].is_object()){
            for(auto it=meta["class_map"].begin(); it!=meta["class_map"].end(); ++it){
                ctx.class_map[std::stoi(it.key())] = it.value().get<std::string>();
            }
        }
    }
    // Threshold
    {
        json j = load_json(thr_path);
        if(!j.contains("BIN_THRESHOLD"))
            throw std::runtime_error("threshold.json missing BIN_THRESHOLD");
        ctx.bin_threshold = j["BIN_THRESHOLD"].get<float>();
    }

    // Session options
    ctx.so.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    ctx.so.SetIntraOpNumThreads(1);
    ctx.so.SetInterOpNumThreads(1);

    // Sessions
    ctx.bin = Ort::Session(ctx.env, bin_path.c_str(), ctx.so);
    ctx.mul = Ort::Session(ctx.env, mul_path.c_str(), ctx.so);

    // IO counts & names
    ctx.bin_in_cnt = ctx.bin.GetInputCount();
    ctx.bin_out_cnt = ctx.bin.GetOutputCount();
    ctx.mul_in_cnt = ctx.mul.GetInputCount();
    ctx.mul_out_cnt = ctx.mul.GetOutputCount();
    ctx.single_input_bin = (ctx.bin_in_cnt==1);
    ctx.single_input_mul = (ctx.mul_in_cnt==1);

    cache_names(ctx.bin, ctx.bin_in_cnt, ctx.bin_out_cnt,
                ctx.bin_in_hold, ctx.bin_in_names,
                ctx.bin_out_hold, ctx.bin_out_names);
    cache_names(ctx.mul, ctx.mul_in_cnt, ctx.mul_out_cnt,
                ctx.mul_in_hold, ctx.mul_in_names,
                ctx.mul_out_hold, ctx.mul_out_names);

    return ctx;
}

namespace {

float ids_run_binary(const IDSContext& ctx, const std::vector<float>& x){
    std::vector<Ort::Value> inputs; inputs.reserve(ctx.bin_in_cnt);

    if(ctx.single_input_bin){
        std::array<int64_t,2> dims{1, ctx.n_features};
        inputs.emplace_back(Ort::Value::CreateTensor<float>(ctx.mem_info,
                                const_cast<float*>(x.data()), x.size(),
                                dims.data(), dims.size()));
    }else{
        float zero_buf = 0.0f;
        for(size_t i=0;i<ctx.bin_in_cnt;++i){
            const char* inname = ctx.bin_in_names[i];
            auto it = ctx.feat_index.find(norm_key(inname));
            const float* ptr = &zero_buf;
            if(it!=ctx.feat_index.end())
                ptr = &x[static_cast<size_t>(it->second)];
            std::array<int64_t, 2> dims{1, 1};
            inputs.emplace_back(Ort::Value::CreateTensor<float>(ctx.mem_info,
                const_cast<float *>(ptr), 1, dims.data(), dims.size()));
        }
    }

    auto outs = ctx.bin.Run(Ort::RunOptions{nullptr},
                            ctx.bin_in_names.data(), inputs.data(), inputs.size(),
                            ctx.bin_out_names.data(), ctx.bin_out_names.size());

    size_t nprob=0; const float* p = pick_prob_tensor(outs, nprob);
    if(!p) throw std::runtime_error("binary.onnx: no float probability tensor in outputs");
    if(nprob==2) return p[1];
    return p[nprob-1];
}

void ids_run_multiclass(const IDSContext& ctx, const std::vector<float>& x,
                        int& argmax, float& best, float& normprob){
    std::vector<Ort::Value> inputs; inputs.reserve(ctx.mul_in_cnt);

    if(ctx.single_input_mul){
        std::array<int64_t,2> dims{1, ctx.n_features};
        inputs.emplace_back(Ort::Value::CreateTensor<float>(ctx.mem_info,
                                const_cast<float*>(x.data()), x.size(),
                                dims.data(), dims.size()));
    }else{
        float zero_buf = 0.0f;
        for(size_t i=0;i<ctx.mul_in_cnt;++i){
            const char* inname = ctx.mul_in_names[i];
            auto it = ctx.feat_index.find(norm_key(inname));
            const float* ptr = &zero_buf;
            if(it!=ctx.feat_index.end())
                ptr = &x[static_cast<size_t>(it->second)];
            std::array<int64_t, 2> dims{1, 1};
            inputs.emplace_back(Ort::Value::CreateTensor<float>(ctx.mem_info,
                const_cast<float *>(ptr), 1, dims.data(), dims.size()));
        }
    }

    auto outs = ctx.mul.Run(Ort::RunOptions{nullptr},
                            ctx.mul_in_names.data(), inputs.data(), inputs.size(),
                            ctx.mul_out_names.data(), ctx.mul_out_names.size());

    size_t nprob=0; const float* p = pick_prob_tensor(outs, nprob);
    if(!p) throw std::runtime_error("multiclass.onnx: no float probability tensor in outputs");

    argmax = 0; best = p[0];
    float sum = p[0];
    for(size_t i=1;i<nprob;++i){
        sum += p[i];
        if(p[i]>best){ best=p[i]; argmax=(int)i; }
    }
    normprob = (sum>0.0f)? (best/sum) : 0.0f;
}

} // namespace

IDSResult ids_predict_from_ordered(const IDSContext& ctx, const std::vector<float>& x){
    if((int64_t)x.size()!=ctx.n_features)
        throw std::runtime_error("ids_predict_from_ordered: feature size mismatch");

    IDSResult r{};
    float p_attack = ids_run_binary(ctx, x);
    r.p_attack = p_attack; r.bin_prob = p_attack;

    if(p_attack < ctx.bin_threshold){
        r.is_attack = false; r.class_id = 0; r.class_prob = 1.0f - p_attack;
        auto it = ctx.class_map.find(0);
        r.class_name = (it!=ctx.class_map.end()? it->second : "Benign");
        return r;
    }

    int arg; float best, normprob;
    ids_run_multiclass(ctx, x, arg, best, normprob);
    r.is_attack = true; r.class_id = arg + 1; r.class_prob = normprob;
    auto it = ctx.class_map.find(r.class_id);
    r.class_name = (it!=ctx.class_map.end()? it->second : "Attack");
    return r;
}

IDSResult ids_predict(const IDSContext& ctx,
                      const std::unordered_map<std::string,float>& fmap){
    std::vector<float> x((size_t)ctx.n_features, std::numeric_limits<float>::quiet_NaN());
    for(const auto& kv: fmap){
        auto it = ctx.feat_index.find(norm_key(kv.first));
        if(it!=ctx.feat_index.end())
            x[(size_t)it->second] = kv.second;
    }
    return ids_predict_from_ordered(ctx, x);
}

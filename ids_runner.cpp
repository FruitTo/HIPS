// ids_runner.cpp - corrected and hardened for ONNX Runtime C++
// - Add IDSResult::bin_prob as alias to p_attack for backward compatibility
// - Fix multiclass off-by-one (+1) because multiclass.onnx was trained on attack-only classes
// - Prefer const GetTensorData<T>() over mutable where we don't modify buffers
// - Avoid initializer_list assignment on vector<AllocatedStringPtr> (use .clear(), emplace_back)
// - Keep AllocatedStringPtr holders alive across Run() to avoid dangling pointers
// - Robustly locate probability tensor even if output names differ (ZipMap disabled)
// Build:
//   export ORT=/opt/onnxruntime-1.22.1
//   g++ -std=c++17 inference.cpp -I"$ORT/include" -L"$ORT/lib" -lonnxruntime \
//      -Wl,-rpath,"$ORT/lib" -O2 -o inference
//
// Notes:
//   - Ort::AllocatedStringPtr is a unique_ptr owning names allocated by ORT; keep it alive
//     and don't copy vectors with initializer_list (unique_ptr is non-copyable).
//     Refs: cppreference unique_ptr non-copyable; ORT AllocatedStringPtr docs. 
//     (See citations in the chat message.)

#include <onnxruntime/onnxruntime_cxx_api.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <array>

using json = nlohmann::json;

struct IDSResult {
    bool        is_attack{false};
    float       p_attack{0.0f};   // probability of "attack" from binary model (index 1)
    float       bin_prob{0.0f};   // alias for backward compatibility with existing code
    int         class_id{0};      // 0..7 (0 = Benign)
    float       class_prob{0.0f}; // probability of chosen attack subclass (from multiclass)
    std::string class_name{"Benign"};
};

static std::string norm_key(std::string s){
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    s.erase(std::remove_if(s.begin(), s.end(),
            [](unsigned char c){ return !(std::isalnum(c) || c=='_'); }), s.end());
    return s;
}

class IDSRunner {
public:
    IDSRunner(const std::string& artifacts_dir = "./artifacts",
              const std::string& bin_name = "binary.onnx",
              const std::string& mul_name = "multiclass.onnx",
              const std::string& meta_name = "meta.json",
              const std::string& thr_name  = "threshold.json")
    : env_(ORT_LOGGING_LEVEL_WARNING, "ids"),
      so_(),
      bin_(nullptr),
      mul_(nullptr) {

        so_.SetGraphOptimizationLevel(ORT_ENABLE_EXTENDED);

        const std::string bin_path  = artifacts_dir + "/" + bin_name;
        const std::string mul_path  = artifacts_dir + "/" + mul_name;
        const std::string meta_path = artifacts_dir + "/" + meta_name;
        const std::string thr_path  = artifacts_dir + "/" + thr_name;

        // Load meta
        {
            std::ifstream f(meta_path);
            if (!f) throw std::runtime_error("cannot open meta: " + meta_path);
            json meta = json::parse(f, nullptr, true, true);
            if (!meta.contains("feature_order") || !meta["feature_order"].is_array())
                throw std::runtime_error("meta.json missing feature_order[]");
            feature_order_ = meta["feature_order"].get<std::vector<std::string>>();
            n_features_ = static_cast<int64_t>(feature_order_.size());
            feat_index_.reserve(feature_order_.size());
            for (size_t i = 0; i < feature_order_.size(); ++i){
                feat_index_[ norm_key(feature_order_[i]) ] = static_cast<int>(i);
            }
            if (meta.contains("class_map") && meta["class_map"].is_object()){
                for (auto it = meta["class_map"].begin(); it != meta["class_map"].end(); ++it){
                    class_map_[ std::stoi(it.key()) ] = it.value().get<std::string>();
                }
            }
        }
        // Load threshold
        {
            std::ifstream f(thr_path);
            if (!f) throw std::runtime_error("cannot open threshold: " + thr_path);
            json j = json::parse(f, nullptr, true, true);
            if (!j.contains("BIN_THRESHOLD"))
                throw std::runtime_error("threshold.json missing BIN_THRESHOLD");
            bin_threshold_ = j["BIN_THRESHOLD"].get<float>();
        }

        // Create sessions
        bin_ = Ort::Session(env_, bin_path.c_str(), so_);
        mul_ = Ort::Session(env_, mul_path.c_str(), so_);

        // Cache I/O counts
        bin_in_cnt_ = bin_.GetInputCount();
        bin_out_cnt_ = bin_.GetOutputCount();
        mul_in_cnt_ = mul_.GetInputCount();
        mul_out_cnt_ = mul_.GetOutputCount();

        single_input_bin_ = (bin_in_cnt_ == 1);
        single_input_mul_ = (mul_in_cnt_ == 1);
    }

    // Map {name->value} -> ordered vector by meta["feature_order"] then predict
    IDSResult Predict(const std::unordered_map<std::string,float>& fmap){
        std::vector<float> x(static_cast<size_t>(n_features_), 0.0f);
        for (const auto& kv: fmap){
            auto it = feat_index_.find( norm_key(kv.first) );
            if (it != feat_index_.end()){
                x[ static_cast<size_t>(it->second) ] = kv.second;
            }
        }
        return PredictFromOrdered(x);
    }

    // Already-ordered feature vector (size == D)
    IDSResult PredictFromOrdered(const std::vector<float>& x_ordered){
        if (static_cast<int64_t>(x_ordered.size()) != n_features_)
            throw std::runtime_error("PredictFromOrdered: size mismatch: got " +
                std::to_string(x_ordered.size()) + ", expected " + std::to_string(n_features_));

        // --- Binary pass ---
        float p_attack = run_binary(x_ordered);
        IDSResult r;
        r.p_attack = p_attack;
        r.bin_prob = p_attack; // keep compatibility with existing code

        if (p_attack < bin_threshold_){
            r.is_attack = false;
            r.class_id = 0;
            auto it = class_map_.find(0);
            r.class_name = (it!=class_map_.end() ? it->second : "Benign");
            r.class_prob = 1.0f - p_attack;
            return r;
        }

        // --- Multiclass pass (attack-only; output 0..6 => +1) ---
        int    arg;
        float  best, normprob;
        run_multiclass(x_ordered, arg, best, normprob);
        r.is_attack = true;
        r.class_id = arg + 1;              // critical fix (+1)
        r.class_prob = normprob;
        auto it = class_map_.find(r.class_id);
        r.class_name = (it!=class_map_.end() ? it->second : "Attack");
        return r;
    }

private:
    // --- Helpers for names ---
    static std::vector<const char*> get_input_names(Ort::Session& s,
                                              Ort::AllocatorWithDefaultOptions& alloc,
                                              size_t count,
                                              std::vector<Ort::AllocatedStringPtr>& holders){
        std::vector<const char*> names;
        names.reserve(count);
        holders.reserve(count);
        for (size_t i=0; i<count; ++i){
            holders.emplace_back( s.GetInputNameAllocated(i, alloc) );
            names.push_back( holders.back().get() );
        }
        return names;
    }
    static std::vector<const char*> get_output_names(Ort::Session& s,
                                                     Ort::AllocatorWithDefaultOptions& alloc,
                                                     size_t count,
                                                     std::vector<Ort::AllocatedStringPtr>& holders){
        std::vector<const char*> names;
        names.reserve(count);
        holders.reserve(count);
        for (size_t i=0; i<count; ++i){
            holders.emplace_back( s.GetOutputNameAllocated(i, alloc) );
            names.push_back( holders.back().get() );
        }
        return names;
    }

    // Pick the first float tensor (length >= 2) as probability buffer
    static const float* pick_prob_tensor(const std::vector<Ort::Value>& outs, size_t& len_out){
        for (const auto& v: outs){
            if (!v.IsTensor()) continue;
            auto ti = v.GetTensorTypeAndShapeInfo();
            if (ti.GetElementType() != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) continue;
            auto shape = ti.GetShape();
            size_t total = 1;
            for (auto d: shape){ total *= static_cast<size_t>(d < 0 ? 1 : d); }
            if (total >= 2){
                len_out = total;
                return v.GetTensorData<float>(); // const
            }
        }
        len_out = 0;
        return nullptr;
    }

    float run_binary(const std::vector<float>& x){
        Ort::AllocatorWithDefaultOptions alloc;
        std::vector<Ort::AllocatedStringPtr> in_hold, out_hold;
        std::vector<const char*> in_names, out_names;

        if (single_input_bin_){
            in_hold.clear();
            in_hold.emplace_back( bin_.GetInputNameAllocated(0, alloc) ); // keep alive
            in_names = { in_hold.back().get() };
        } else {
            in_names = get_input_names(bin_, alloc, bin_in_cnt_, in_hold);
        }
        out_names = get_output_names(bin_, alloc, bin_out_cnt_, out_hold);

        std::vector<Ort::Value> inputs;
        inputs.reserve(bin_in_cnt_);
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

        if (single_input_bin_){
            std::array<int64_t,2> dims{1, n_features_};
            inputs.emplace_back( Ort::Value::CreateTensor<float>(mem,
                                    const_cast<float*>(x.data()),
                                    x.size(), dims.data(), dims.size()) );
        } else {
            float zero_buf = 0.0f;
            for (size_t i=0; i<bin_in_cnt_; ++i){
                std::string inname = in_hold[i].get();
                auto it = feat_index_.find( norm_key(inname) );
                const float* ptr = &zero_buf;
                if (it != feat_index_.end()){
                    ptr = &x[ static_cast<size_t>(it->second) ];
                }
                std::array<int64_t,2> dims{1,1};
                inputs.emplace_back( Ort::Value::CreateTensor<float>(mem,
                                        const_cast<float*>(ptr), 1, dims.data(), dims.size()) );
            }
        }

        auto outs = bin_.Run(Ort::RunOptions{nullptr},
                             in_names.data(), inputs.data(), inputs.size(),
                             out_names.data(), out_names.size());

        size_t nprob = 0;
        const float* p = pick_prob_tensor(outs, nprob);
        if (!p) throw std::runtime_error("binary.onnx: no float probability tensor in outputs");
        if (nprob == 2) return p[1];            // [p0, p1] -> attack prob at index 1
        return p[nprob-1];                      // fallback
    }

    void run_multiclass(const std::vector<float>& x, int& argmax, float& best, float& normprob){
        Ort::AllocatorWithDefaultOptions alloc;
        std::vector<Ort::AllocatedStringPtr> in_hold, out_hold;
        std::vector<const char*> in_names, out_names;

        if (single_input_mul_){
            in_hold.clear();
            in_hold.emplace_back( mul_.GetInputNameAllocated(0, alloc) );
            in_names = { in_hold.back().get() };
        } else {
            in_names = get_input_names(mul_, alloc, mul_in_cnt_, in_hold);
        }
        out_names = get_output_names(mul_, alloc, mul_out_cnt_, out_hold);

        std::vector<Ort::Value> inputs;
        inputs.reserve(mul_in_cnt_);
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

        if (single_input_mul_){
            std::array<int64_t,2> dims{1, n_features_};
            inputs.emplace_back( Ort::Value::CreateTensor<float>(mem,
                                    const_cast<float*>(x.data()),
                                    x.size(), dims.data(), dims.size()) );
        } else {
            float zero_buf = 0.0f;
            for (size_t i=0; i<mul_in_cnt_; ++i){
                std::string inname = in_hold[i].get();
                auto it = feat_index_.find( norm_key(inname) );
                const float* ptr = &zero_buf;
                if (it != feat_index_.end()){
                    ptr = &x[ static_cast<size_t>(it->second) ];
                }
                std::array<int64_t,2> dims{1,1};
                inputs.emplace_back( Ort::Value::CreateTensor<float>(mem,
                                        const_cast<float*>(ptr), 1, dims.data(), dims.size()) );
            }
        }

        auto outs = mul_.Run(Ort::RunOptions{nullptr},
                             in_names.data(), inputs.data(), inputs.size(),
                             out_names.data(), out_names.size());

        size_t nprob = 0;
        const float* p = pick_prob_tensor(outs, nprob);
        if (!p) throw std::runtime_error("multiclass.onnx: no float probability tensor in outputs");

        argmax = 0; best = p[0];
        float sum = p[0];
        for (size_t i=1; i<nprob; ++i){
            sum += p[i];
            if (p[i] > best){ best = p[i]; argmax = static_cast<int>(i); }
        }
        normprob = (sum > 0.0f) ? (best / sum) : 0.0f;
    }

private:
    // Model + metadata
    std::vector<std::string> feature_order_;
    std::unordered_map<std::string,int> feat_index_;   // normalized name -> index
    std::unordered_map<int,std::string> class_map_;
    int64_t n_features_{0};
    float   bin_threshold_{0.5f};

    // ORT objects
    Ort::Env           env_;
    Ort::SessionOptions so_;
    Ort::Session       bin_;
    Ort::Session       mul_;

    // I/O cache
    size_t bin_in_cnt_{0},  bin_out_cnt_{0};
    size_t mul_in_cnt_{0},  mul_out_cnt_{0};
    bool   single_input_bin_{true};
    bool   single_input_mul_{true};
};

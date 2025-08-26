// ids_runner.cpp (re-fetch names at run-time, robust to empty/garbled names)
#include <onnxruntime/onnxruntime_cxx_api.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <filesystem>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <cmath>
#include <array>

using json = nlohmann::json;
namespace fs = std::filesystem;

static std::string norm_key(std::string s){
    std::string out; out.reserve(s.size());
    for(char c: s) if (std::isalnum(static_cast<unsigned char>(c)))
        out.push_back(std::tolower(static_cast<unsigned char>(c)));
    return out;
}
static json jsonLoad(const fs::path& p){
    std::ifstream f(p);
    if (!f) throw std::runtime_error("cannot open "+p.string());
    return json::parse(f, nullptr, true, true);
}

struct IDSResult {
    bool        is_attack{false};
    float       bin_prob{0.f};
    int         class_id{-1};
    std::string class_name;
    float       class_prob{0.f};
};

class IDSRunner {
public:
    explicit IDSRunner(const fs::path& artifacts_dir)
    : env_(ORT_LOGGING_LEVEL_WARNING, "ids")
    {
        // meta / threshold
        auto meta = jsonLoad(artifacts_dir / "meta.json");
        thr_ = jsonLoad(artifacts_dir / "threshold.json").value("BIN_THRESHOLD", 0.5f);

        if (!meta.contains("feature_order") || !meta["feature_order"].is_array())
            throw std::runtime_error("meta.json missing feature_order");
        n_features_ = static_cast<int64_t>(meta["feature_order"].size());

        for (int i=0;i<n_features_;++i) {
            feat_index_[ norm_key(meta["feature_order"][i].get<std::string>()) ] = i;
        }
        if (meta.contains("class_map") && meta["class_map"].is_object()) {
            for (auto it = meta["class_map"].begin(); it != meta["class_map"].end(); ++it) {
                class_map_[ std::stoi(it.key()) ] = it.value().get<std::string>();
            }
        }

        // SessionOptions
        Ort::SessionOptions so;
        so.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
        so.SetIntraOpNumThreads(1);

        // Sessions
        bin_.reset(new Ort::Session(env_, (artifacts_dir/"binary.onnx").string().c_str(), so));
        mul_.reset(new Ort::Session(env_, (artifacts_dir/"multiclass.onnx").string().c_str(), so));

        // cache I/O counts + shapes (แต่ "ชื่อ" จะดึงสดทุกครั้ง)
        Ort::AllocatorWithDefaultOptions alloc;
        bin_in_cnt_  = bin_->GetInputCount();
        bin_out_cnt_ = bin_->GetOutputCount();
        if (bin_in_cnt_==0 || bin_out_cnt_==0) throw std::runtime_error("binary.onnx I/O invalid");

        if (bin_in_cnt_ == 1) {
            single_input_   = true;
            bin_vec_shape_  = sanitize_single_vector(get_input_shape(*bin_, 0), n_features_);
        } else {
            single_input_ = false;
            bin_in_shapes_.resize(bin_in_cnt_);
            for (size_t i=0;i<bin_in_cnt_;++i)
                bin_in_shapes_[i] = sanitize_scalar_input(get_input_shape(*bin_, i));
        }

        mul_in_cnt_  = mul_->GetInputCount();
        mul_out_cnt_ = mul_->GetOutputCount();
        if (mul_in_cnt_==0 || mul_out_cnt_==0) throw std::runtime_error("multiclass.onnx I/O invalid");

        if (mul_in_cnt_ == 1) {
            mul_single_input_ = true;
            mul_vec_shape_    = sanitize_single_vector(get_input_shape(*mul_,0), n_features_);
        } else {
            mul_single_input_ = false;
            mul_in_shapes_.resize(mul_in_cnt_);
            for (size_t i=0;i<mul_in_cnt_;++i)
                mul_in_shapes_[i] = sanitize_scalar_input(get_input_shape(*mul_, i));
        }
    }

    IDSResult Predict(const std::unordered_map<std::string, float>& feat_map) const {
        IDSResult r;

        // Build dense features in training order
        std::vector<float> feats(static_cast<size_t>(n_features_), 0.0f);
        for (auto& kv: feat_map) {
            auto it = feat_index_.find( norm_key(kv.first) );
            if (it != feat_index_.end()) feats[ it->second ] = kv.second;
        }

        Ort::AllocatorWithDefaultOptions alloc;
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

        // ------ Run binary ------
        std::vector<const char*> in_names;
        std::vector<Ort::Value>  inputs;

        // ชื่ออินพุต/เอาต์พุต: ดึงสด และเก็บ holder ไว้ให้มีอายุจนจบ Run()
        std::vector<Ort::AllocatedStringPtr> name_holders;
        name_holders.reserve(bin_in_cnt_ + 1);

        if (single_input_) {
            auto nm = bin_->GetInputNameAllocated(0, alloc);
            in_names = { nm.get() };
            name_holders.emplace_back(std::move(nm));

            inputs.emplace_back( Ort::Value::CreateTensor<float>(
                mem, feats.data(), feats.size(),
                bin_vec_shape_.data(), bin_vec_shape_.size() ));
        } else {
            in_names.resize(bin_in_cnt_);
            inputs.reserve(bin_in_cnt_);
            for (size_t i=0;i<bin_in_cnt_;++i){
                auto nm = bin_->GetInputNameAllocated(i, alloc);
                const char* cname = nm.get();
                name_holders.emplace_back(std::move(nm));
                in_names[i] = cname;

                // map feature index (by name → index, fallback by position)
                int fidx = map_feature_index(cname, int(i));
                const float* ptr = (fidx>=0 && fidx<n_features_) ? &feats[static_cast<size_t>(fidx)] : &zero_;

                inputs.emplace_back( Ort::Value::CreateTensor<float>(
                    mem, const_cast<float*>(ptr), 1,
                    bin_in_shapes_[i].data(), bin_in_shapes_[i].size() ));
            }
        }

        // output name (สด)
        auto out_nm = bin_->GetOutputNameAllocated(0, alloc);
        std::array<const char*,1> bin_out_names = { out_nm.get() };
        name_holders.emplace_back(std::move(out_nm));

        auto outs = bin_->Run(Ort::RunOptions{nullptr},
                              in_names.data(), inputs.data(), in_names.size(),
                              bin_out_names.data(), bin_out_names.size());

        auto& bout  = outs.front();
        auto  binfo = bout.GetTensorTypeAndShapeInfo();
        auto  bcnt  = binfo.GetElementCount();
        float* bptr = bout.GetTensorMutableData<float>();

        float p = 0.f;
        if (bcnt==1) {
            float v = bptr[0];
            p = (v<0.f || v>1.f)? (1.f/(1.f+std::exp(-v))) : v;
        } else if (bcnt==2) {
            float a=bptr[0], b=bptr[1], m=std::max(a,b);
            p = std::exp(b-m) / (std::exp(a-m)+std::exp(b-m));
        } else {
            float m=bptr[0]; for (size_t i=1;i<bcnt;++i) m=std::max(m,bptr[i]);
            double sum=0, best=0;
            for (size_t i=0;i<bcnt;++i) { double e=std::exp(double(bptr[i]-m)); sum+=e; if(e>best) best=e; }
            p = float(best/sum);
        }
        r.bin_prob = p;
        r.is_attack = (p >= thr_);

        // ------ Run multiclass if needed ------
        if (r.is_attack) {
            std::vector<const char*> n2;
            std::vector<Ort::Value>  i2;
            std::vector<Ort::AllocatedStringPtr> holders2;
            holders2.reserve(mul_in_cnt_ + 1);

            if (mul_single_input_) {
                auto nm = mul_->GetInputNameAllocated(0, alloc);
                n2 = { nm.get() };
                holders2.emplace_back(std::move(nm));

                i2.emplace_back( Ort::Value::CreateTensor<float>(
                    mem, feats.data(), feats.size(),
                    mul_vec_shape_.data(), mul_vec_shape_.size() ));
            } else {
                n2.resize(mul_in_cnt_); i2.reserve(mul_in_cnt_);
                for (size_t i=0;i<mul_in_cnt_;++i){
                    auto nm = mul_->GetInputNameAllocated(i, alloc);
                    const char* cname = nm.get();
                    holders2.emplace_back(std::move(nm));
                    n2[i] = cname;

                    int fidx = map_feature_index(cname, int(i));
                    const float* ptr = (fidx>=0 && fidx<n_features_) ? &feats[static_cast<size_t>(fidx)] : &zero_;
                    i2.emplace_back( Ort::Value::CreateTensor<float>(
                        mem, const_cast<float*>(ptr), 1,
                        mul_in_shapes_[i].data(), mul_in_shapes_[i].size() ));
                }
            }

            auto out2 = mul_->GetOutputNameAllocated(0, alloc);
            std::array<const char*,1> mul_out_names = { out2.get() };
            holders2.emplace_back(std::move(out2));

            auto o2 = mul_->Run(Ort::RunOptions{nullptr},
                                n2.data(), i2.data(), n2.size(),
                                mul_out_names.data(), mul_out_names.size());

            auto& mval = o2.front();
            auto  minfo= mval.GetTensorTypeAndShapeInfo();
            auto  mcnt = minfo.GetElementCount();
            float* md  = mval.GetTensorMutableData<float>();

            float m=md[0]; for (size_t i=1;i<mcnt;++i) m = std::max(m, md[i]);
            double sum=0.0, best=0.0; size_t arg=0;
            for (size_t i=0;i<mcnt;++i) {
                double e = std::exp(double(md[i]-m));
                sum += e;
                if (e > best) { best = e; arg = i; }
            }
            r.class_id   = int(arg);
            r.class_prob = float(best / sum);
            auto it = class_map_.find(r.class_id);
            if (it != class_map_.end()) r.class_name = it->second;
        }

        return r;
    }

private:
    // helpers
    static std::vector<int64_t> get_input_shape(Ort::Session& s, size_t i){
        Ort::TypeInfo ti = s.GetInputTypeInfo(i);
        return ti.GetTensorTypeAndShapeInfo().GetShape();
    }
    static std::vector<int64_t> sanitize_single_vector(std::vector<int64_t> d, int64_t n){
        if (d.size()==1){ d[0] = (d[0]<0)? n: n; }
        else if (d.size()==2){ d[0]=1; d[1]=(d[1]<0)? n: n; }
        else d = {1,n};
        return d;
    }
    static std::vector<int64_t> sanitize_scalar_input(std::vector<int64_t> d){
        if (d.empty()) return {1};
        for (auto& x: d) if (x<0) x=1;
        size_t prod=1; for (auto x: d) prod*=size_t(x);
        if (prod!=1) d={1,1};
        return d;
    }
    int map_feature_index(const char* cname, int fallback_index) const {
        if (!cname) return (fallback_index < n_features_ ? fallback_index : -1);
        std::string key = norm_key(std::string(cname));
        if (key.empty()) return (fallback_index < n_features_ ? fallback_index : -1);
        auto it = feat_index_.find(key);
        if (it != feat_index_.end()) return it->second;

        // ลองแทน '_' เป็น ' ' แล้ว normalize ใหม่
        std::string guess = std::string(cname);
        std::replace(guess.begin(), guess.end(), '_', ' ');
        auto it2 = feat_index_.find( norm_key(guess) );
        if (it2 != feat_index_.end()) return it2->second;

        // fallback: ตามลำดับ index
        return (fallback_index < n_features_) ? fallback_index : -1;
    }

private:
    // ORT
    Ort::Env env_;
    std::unique_ptr<Ort::Session> bin_, mul_;

    // meta
    int64_t n_features_{0};
    float   thr_{0.5f};
    std::unordered_map<std::string,int> feat_index_;
    std::unordered_map<int,std::string>  class_map_;
    inline static const float zero_{0.0f};

    // binary I/O cache (shapes only)
    size_t  bin_in_cnt_{0}, bin_out_cnt_{0};
    bool    single_input_{true};
    std::vector<int64_t> bin_vec_shape_;
    std::vector<std::vector<int64_t>> bin_in_shapes_;

    // multiclass I/O cache (shapes only)
    size_t  mul_in_cnt_{0}, mul_out_cnt_{0};
    bool    mul_single_input_{true};
    std::vector<int64_t> mul_vec_shape_;
    std::vector<std::vector<int64_t>> mul_in_shapes_;
};
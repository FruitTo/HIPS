// onnx-test.cpp
#include <onnxruntime/onnxruntime_cxx_api.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <unordered_map>

using json = nlohmann::json;
namespace fs = std::filesystem;

static inline void chk(const char* tag){ std::cerr << "[CHK] " << tag << "\n"; }

// ---------- JSON helpers ----------
static json jsonLoadLimited(const fs::path& p, std::uintmax_t max_bytes = 8 * 1024 * 1024) {
    if (!fs::exists(p)) throw std::runtime_error("jsonLoad: file not found: " + p.string());
    auto sz = fs::file_size(p);
    if (sz > max_bytes) throw std::runtime_error("jsonLoad: file too large: " + p.string());
    std::ifstream f(p);
    if (!f) throw std::runtime_error("jsonLoad: cannot open: " + p.string() + " (cwd=" + fs::current_path().string() + ")");
    return json::parse(f, nullptr, true, true);
}

static void print_json_summary(const json& j, const std::string& title) {
    std::cout << title << " summary:\n";
    if (!j.is_object()) { std::cout << "  (not an object)\n"; return; }
    for (auto it = j.begin(); it != j.end(); ++it) {
        const auto& k = it.key();
        const auto& v = it.value();
        std::cout << "  - " << k << ": ";
        if (v.is_array())       std::cout << "array[len=" << v.size() << "]\n";
        else if (v.is_object()) std::cout << "object{keys=" << v.size() << "}\n";
        else if (v.is_string()) std::cout << "string[len=" << v.get_ref<const std::string&>().size() << "]\n";
        else if (v.is_boolean())std::cout << "bool\n";
        else if (v.is_number()) std::cout << "number\n";
        else                    std::cout << "value\n";
    }
}

// ---------- string normalize ----------
static std::string norm_key(std::string s){
    std::string out; out.reserve(s.size());
    for(char c: s){
        if (std::isalnum(static_cast<unsigned char>(c))) out.push_back(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// ---------- ORT shape helpers (keep TypeInfo alive!) ----------
static std::vector<int64_t> get_input_shape(Ort::Session& s, size_t index){
    Ort::TypeInfo ti = s.GetInputTypeInfo(index);                       // keep alive
    auto tsi = ti.GetTensorTypeAndShapeInfo();                          // now safe
    return tsi.GetShape();
}
static std::vector<int64_t> get_output_shape(Ort::Session& s, size_t index){
    Ort::TypeInfo ti = s.GetOutputTypeInfo(index);                      // keep alive
    auto tsi = ti.GetTensorTypeAndShapeInfo();
    return tsi.GetShape();
}

static std::vector<int64_t> sanitize_single_vector(std::vector<int64_t> dims, int64_t n_features){
    if (dims.empty()) throw std::runtime_error("empty input dims");
    if (dims.size()==1){
        dims[0] = (dims[0] < 0) ? n_features : n_features;
    } else if (dims.size()==2){
        if (dims[0] < 0) dims[0] = 1;
        if (dims[1] < 0) dims[1] = n_features;
        dims[0] = 1; dims[1] = n_features;
    } else {
        dims.assign({1, n_features});
    }
    int64_t feat = (dims.size()==1)? dims[0] : dims[1];
    if (feat != n_features) throw std::runtime_error("single-vector dims mismatch");
    return dims;
}

static std::vector<int64_t> sanitize_scalar_input(std::vector<int64_t> dims){
    // ต่อ-ฟีเจอร์: ต้องเป็นสเกลาร์ต่อ batch (product == 1)
    if (dims.empty()) return {1};
    for (auto& d: dims) if (d < 0) d = 1;
    size_t prod=1; for (auto d: dims) prod *= static_cast<size_t>(d);
    if (prod != 1) dims.assign({1,1});
    return dims;
}

static void print_shape(const char* tag, const std::vector<int64_t>& s){
    std::cout << tag << " = [";
    for(size_t i=0;i<s.size();++i) std::cout << s[i] << (i+1<s.size()? ", ":"");
    std::cout << "]\n";
}

// ---------- path helper ----------
static fs::path detect_artifacts_dir() {
#if defined(__linux__)
    fs::path exe = fs::read_symlink("/proc/self/exe");
    fs::path base = exe.empty() ? fs::current_path() : exe.parent_path();
#else
    fs::path base = fs::current_path();
#endif
    if (fs::exists(base / "artifacts" / "meta.json")) return base / "artifacts";
    if (fs::exists(fs::current_path() / "artifacts" / "meta.json")) return fs::current_path() / "artifacts";
    return "artifacts";
}

int main() try {
    std::cout << "CWD: " << fs::current_path() << "\n";

    // --- paths & JSON ---
    const fs::path artifacts = detect_artifacts_dir();
    const fs::path binary = artifacts / "binary.onnx";
    const fs::path multi  = artifacts / "multiclass.onnx";

    chk("load json");
    json meta = jsonLoadLimited(artifacts / "meta.json");
    json thr  = jsonLoadLimited(artifacts / "threshold.json");

    if (!meta.contains("feature_order") || !meta["feature_order"].is_array())
        throw std::runtime_error("meta.json missing 'feature_order' array");

    const int64_t n_features = static_cast<int64_t>(meta["feature_order"].size());
    const float BIN_THRESHOLD = thr.value("BIN_THRESHOLD", 0.5f);

    std::cout << "n_features = " << n_features << "\n";
    std::cout << "BIN_THRESHOLD = " << BIN_THRESHOLD << "\n";
    print_json_summary(meta, "meta");
    print_json_summary(thr,  "threshold");

    // แม็ปชื่อฟีเจอร์ -> index
    std::unordered_map<std::string, int> feat_index;
    feat_index.reserve(static_cast<size_t>(n_features));
    for (int i=0;i<n_features;++i){
        const std::string name = meta["feature_order"][i].get<std::string>();
        feat_index[norm_key(name)] = i;
    }

    // เวกเตอร์ฟีเจอร์ตัวอย่าง (ใส่ค่าจริงทีหลัง)
    std::vector<float> features(static_cast<size_t>(n_features), 0.0f);

    // --- ORT boot & sessions ---
    chk("env + so");
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "ids"};
    Ort::SessionOptions so;
    so.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
    so.SetIntraOpNumThreads(1);

    chk("create sessions");
    Ort::Session bin_sess{env, binary.string().c_str(), so};
    Ort::Session mul_sess{env, multi.string().c_str(), so};

    // ====== BINARY ======
    chk("binary io meta");
    Ort::AllocatorWithDefaultOptions alloc;
    size_t bin_in_cnt  = bin_sess.GetInputCount();
    size_t bin_out_cnt = bin_sess.GetOutputCount();
    if (bin_in_cnt < 1 || bin_out_cnt < 1) throw std::runtime_error("binary.onnx I/O invalid");

    std::vector<std::string> bin_in_names_str(bin_in_cnt);
    std::vector<const char*> bin_in_names(bin_in_cnt);
    std::vector<Ort::Value>  bin_inputs; bin_inputs.reserve(bin_in_cnt);

    if (bin_in_cnt == 1) {
        // -------- single input: vector [1, n_features]
        auto name = bin_sess.GetInputNameAllocated(0, alloc);
        bin_in_names_str[0] = name.get();
        bin_in_names[0] = bin_in_names_str[0].c_str();

        auto raw = get_input_shape(bin_sess, 0);
        print_shape("binary raw input shape", raw);
        auto sane = sanitize_single_vector(raw, n_features);
        print_shape("binary sanitized input shape", sane);

        size_t elem=1; for (auto d: sane) elem *= static_cast<size_t>(d);
        if (elem != static_cast<size_t>(n_features))
            throw std::runtime_error("elem_count != n_features");

        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        bin_inputs.emplace_back(
            Ort::Value::CreateTensor<float>(mem, features.data(), features.size(),
                                            sane.data(), sane.size()));
    } else {
        // -------- multi input: scalar tensors (e.g. [-1,1] or [1])
        std::cout << "binary: multi-input mode (" << bin_in_cnt << " inputs)\n";

        bin_inputs.clear();
        bin_inputs.reserve(bin_in_cnt);
        bin_in_names_str.clear();
        bin_in_names_str.reserve(bin_in_cnt);
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

        int matched = 0, unmatched = 0;
        for (size_t i=0;i<bin_in_cnt;++i){
            auto name = bin_sess.GetInputNameAllocated(i, alloc);
            std::string in_name = name.get();
            bin_in_names_str.push_back(in_name);

            auto raw = get_input_shape(bin_sess, i);
            print_shape(("binary raw input["+std::to_string(i)+"] "+in_name).c_str(), raw);
            auto sane = sanitize_scalar_input(raw);
            print_shape(("binary sanitized input["+std::to_string(i)+"]").c_str(), sane);

            int fidx = -1;
            auto it = feat_index.find(norm_key(in_name));
            if (it != feat_index.end()) fidx = it->second;
            else {
                std::string guess = in_name;
                std::replace(guess.begin(), guess.end(), '_', ' ');
                auto it2 = feat_index.find(norm_key(guess));
                if (it2 != feat_index.end()) fidx = it2->second;
            }

            if (fidx < 0) {
                ++unmatched;
                static thread_local float zero = 0.0f;
                bin_inputs.emplace_back(Ort::Value::CreateTensor<float>(mem, &zero, 1, sane.data(), sane.size()));
                std::cerr << "[WARN] cannot match input '" << in_name << "' to meta.feature_order — fill 0.0\n";
            } else {
                ++matched;
                float* ptr = &features[static_cast<size_t>(fidx)];
                bin_inputs.emplace_back(Ort::Value::CreateTensor<float>(mem, ptr, 1, sane.data(), sane.size()));
            }
        }
        std::cout << "binary input mapping: matched=" << matched << " unmatched=" << unmatched << "\n";
        bin_in_names.resize(bin_in_cnt);
        for (size_t i=0;i<bin_in_cnt;++i) bin_in_names[i] = bin_in_names_str[i].c_str();
    }

    // output name
    auto bin_out_name_alloc = bin_sess.GetOutputNameAllocated(0, alloc);
    const char* bin_out_name = bin_out_name_alloc.get();

    // run
    chk("run binary");
    auto bin_outs = bin_sess.Run(Ort::RunOptions{nullptr},
                                 bin_in_names.data(), bin_inputs.data(), bin_in_names.size(),
                                 &bin_out_name, 1);
    if (bin_outs.empty()) throw std::runtime_error("binary inference returned no output");

    auto& bout = bin_outs.front();
    auto bout_shape = get_output_shape(bin_sess, 0);
    print_shape("binary output shape", bout_shape);
    auto bout_info  = bout.GetTensorTypeAndShapeInfo();
    auto bout_count = bout_info.GetElementCount();
    float* bout_data = bout.GetTensorMutableData<float>();

    float bin_prob = 0.0f;
    if (bout_count == 1) {
        float v = bout_data[0];
        bin_prob = (v < 0.f || v > 1.f) ? (1.f / (1.f + std::exp(-v))) : v;
    } else if (bout_count == 2) {
        float a = bout_data[0], b = bout_data[1];
        float m = std::max(a,b);
        float ea = std::exp(a - m), eb = std::exp(b - m);
        bin_prob = eb / (ea + eb);
    } else {
        float m = bout_data[0];
        for (size_t i=1;i<bout_count;++i) m = std::max(m, bout_data[i]);
        double sum=0.0, best=0.0; size_t arg=0;
        for (size_t i=0;i<bout_count;++i) {
            double p = std::exp(double(bout_data[i]-m));
            sum += p;
            if (p > best) { best = p; arg = i; }
        }
        bin_prob = static_cast<float>(best / sum);
        std::cout << "binary argmax = " << arg << " (softmax prob=" << bin_prob << ")\n";
    }

    bool is_attack = (bin_prob >= BIN_THRESHOLD);
    std::cout << "binary prob = " << bin_prob << " => is_attack=" << (is_attack ? "true":"false") << "\n";

    // ====== MULTICLASS ======
    if (is_attack) {
        chk("multiclass io meta");
        size_t mul_in_cnt  = mul_sess.GetInputCount();
        size_t mul_out_cnt = mul_sess.GetOutputCount();
        if (mul_in_cnt < 1 || mul_out_cnt < 1) throw std::runtime_error("multiclass.onnx I/O invalid");

        std::vector<std::string> mul_in_names_str(mul_in_cnt);
        std::vector<const char*> mul_in_names(mul_in_cnt);
        std::vector<Ort::Value>  mul_inputs; mul_inputs.reserve(mul_in_cnt);

        if (mul_in_cnt == 1) {
            auto name = mul_sess.GetInputNameAllocated(0, alloc);
            mul_in_names_str[0] = name.get();
            mul_in_names[0] = mul_in_names_str[0].c_str();

            auto raw = get_input_shape(mul_sess, 0);
            print_shape("multiclass raw input shape", raw);
            auto sane = sanitize_single_vector(raw, n_features);
            print_shape("multiclass sanitized input shape", sane);

            size_t elem=1; for (auto d: sane) elem *= static_cast<size_t>(d);
            if (elem != static_cast<size_t>(n_features))
                throw std::runtime_error("multiclass: elem_count != n_features");

            Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
            mul_inputs.emplace_back(
                Ort::Value::CreateTensor<float>(mem, features.data(), features.size(),
                                                sane.data(), sane.size()));
        } else {
            std::cout << "multiclass: multi-input mode (" << mul_in_cnt << " inputs)\n";
            Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

            int matched=0, unmatched=0;
            for (size_t i=0;i<mul_in_cnt;++i){
                auto name = mul_sess.GetInputNameAllocated(i, alloc);
                std::string in_name = name.get();
                mul_in_names_str[i] = in_name;

                auto raw = get_input_shape(mul_sess, i);
                print_shape(("multiclass raw input["+std::to_string(i)+"] "+in_name).c_str(), raw);
                auto sane = sanitize_scalar_input(raw);
                print_shape(("multiclass sanitized input["+std::to_string(i)+"]").c_str(), sane);

                int fidx = -1;
                auto it = feat_index.find(norm_key(in_name));
                if (it != feat_index.end()) fidx = it->second;
                else {
                    std::string guess = in_name;
                    std::replace(guess.begin(), guess.end(), '_', ' ');
                    auto it2 = feat_index.find(norm_key(guess));
                    if (it2 != feat_index.end()) fidx = it2->second;
                }

                if (fidx < 0) {
                    ++unmatched;
                    static thread_local float zero = 0.0f;
                    mul_inputs.emplace_back(Ort::Value::CreateTensor<float>(mem, &zero, 1, sane.data(), sane.size()));
                    std::cerr << "[WARN] (multi) cannot match input '" << in_name << "' -> 0.0\n";
                } else {
                    ++matched;
                    float* ptr = &features[static_cast<size_t>(fidx)];
                    mul_inputs.emplace_back(Ort::Value::CreateTensor<float>(mem, ptr, 1, sane.data(), sane.size()));
                }
            }
            std::cout << "multiclass input mapping: matched=" << matched << " unmatched=" << unmatched << "\n";
            for (size_t i=0;i<mul_in_cnt;++i) mul_in_names[i] = mul_in_names_str[i].c_str();
        }

        auto mul_out_name_alloc = mul_sess.GetOutputNameAllocated(0, alloc);
        const char* mul_out_name = mul_out_name_alloc.get();

        chk("run multiclass");
        auto mul_outs = mul_sess.Run(Ort::RunOptions{nullptr},
                                     mul_in_names.data(), mul_inputs.data(), mul_in_names.size(),
                                     &mul_out_name, 1);

        auto& mout = mul_outs.front();
        auto mout_shape = get_output_shape(mul_sess, 0);
        print_shape("multiclass output shape", mout_shape);
        auto mout_info  = mout.GetTensorTypeAndShapeInfo();
        auto mout_count = mout_info.GetElementCount();
        float* mout_data = mout.GetTensorMutableData<float>();

        float m = mout_data[0];
        for (size_t i=1;i<mout_count;++i) m = std::max(m, mout_data[i]);
        double sum=0.0, best=0.0; size_t arg=0;
        for (size_t i=0;i<mout_count;++i) {
            double p = std::exp(double(mout_data[i]-m));
            sum += p;
            if (p > best) { best = p; arg = i; }
        }
        float cls_conf = static_cast<float>(best / sum);
        std::cout << "multiclass argmax = " << arg << " (prob=" << cls_conf << ")\n";

        if (meta.contains("class_map") && meta["class_map"].is_object()) {
            auto it = meta["class_map"].find(std::to_string(arg));
            if (it != meta["class_map"].end() && it->is_string())
                std::cout << "class name = " << it->get<std::string>() << "\n";
        }
    }

    std::cout << "OK\n";
    return 0;

} catch (const Ort::Exception& e) {
    std::cerr << "[ORT] " << e.what() << "\n";
    return 1;
} catch (const std::exception& e) {
    std::cerr << "[ERR] " << e.what() << "\n";
    return 1;
}

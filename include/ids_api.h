#pragma once
#include <string>
#include <vector>
#include <unordered_map>

// ONNX Runtime
#include <onnxruntime/onnxruntime_cxx_api.h>

struct IDSResult {
    bool is_attack{false};
    float p_attack{0.0f};
    float bin_prob{0.0f};
    int   class_id{0};
    float class_prob{0.0f};
    std::string class_name{"Benign"};
};

// ====== นิยามเต็มของ IDSContext ย้ายมาไว้ใน header ======
struct IDSContext {
    std::vector<std::string> feature_order;
    std::unordered_map<std::string, int> feat_index;
    std::unordered_map<int, std::string> class_map;
    int64_t n_features{0};
    float bin_threshold{0.5f};

    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "ids-fp"};
    Ort::SessionOptions so{};
    mutable Ort::Session bin{nullptr};
    mutable Ort::Session mul{nullptr};

    size_t bin_in_cnt{0}, bin_out_cnt{0};
    size_t mul_in_cnt{0}, mul_out_cnt{0};
    bool single_input_bin{true};
    bool single_input_mul{true};

    std::vector<Ort::AllocatedStringPtr> bin_in_hold, bin_out_hold;
    std::vector<Ort::AllocatedStringPtr> mul_in_hold, mul_out_hold;
    std::vector<const char*> bin_in_names, bin_out_names;
    std::vector<const char*> mul_in_names, mul_out_names;

    Ort::MemoryInfo mem_info{Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU)};
};
// ===============================================

IDSContext ids_init(const std::string& artifacts_dir = "./artifacts",
                    const std::string& bin_name = "binary.onnx",
                    const std::string& mul_name = "multiclass.onnx",
                    const std::string& meta_name = "meta.json",
                    const std::string& thr_name  = "threshold.json");

IDSResult ids_predict_from_ordered(const IDSContext& ctx,
                                   const std::vector<float>& x);

IDSResult ids_predict(const IDSContext& ctx,
                      const std::unordered_map<std::string,float>& fmap);

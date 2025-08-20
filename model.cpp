// model.cpp
#include <onnxruntime/onnxruntime_cxx_api.h>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdlib>

static void usage(const char* prog) {
    std::cerr << "Usage:\n  " << prog
              << " --model <path/to/deploy_model.onnx> [--features N]\n";
}

int main(int argc, char** argv) {
    try {
        // --- Parse args ---
        if (argc < 3 || std::string(argv[1]) != "--model") {
            usage(argv[0]); return 2;
        }
        std::string model_path = argv[2];
        int64_t forced_features = -1;
        for (int i = 3; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--features") {
                forced_features = std::stoll(argv[i+1]);
            }
        }

        // --- ORT env/session ---
        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "smoke-test");
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        Ort::Session session(env, model_path.c_str(), opts);
        Ort::AllocatorWithDefaultOptions allocator;

        // --- Inspect input ---
        auto in_name_alloc = session.GetInputNameAllocated(0, allocator);
        std::string input_name = in_name_alloc.get();

        auto in_typeinfo = session.GetInputTypeInfo(0);
        auto in_tshape   = in_typeinfo.GetTensorTypeAndShapeInfo();
        auto onnx_shape  = in_tshape.GetShape(); // e.g. [-1, 59] หรือ [1, 59]

        // --- Decide feature count safely ---
        int64_t n_features = -1;
        if (!onnx_shape.empty()) {
            int64_t last = onnx_shape.back();
            if (last > 0) n_features = last; // fixed dim in model
        }
        if (n_features <= 0) {
            if (forced_features > 0) {
                n_features = forced_features;
            } else {
                // ค่า default ถ้ายังไม่ได้ระบุ (แก้ได้ตามโมเดลคุณ: 59 หรือ 77)
                n_features = 59;
                std::cerr << "[warn] Input feature dim is dynamic."
                          << " Using default --features " << n_features
                          << " (override with --features N)\n";
            }
        }

        // --- Build input tensor: [1, n_features] zeros ---
        std::vector<float> x(static_cast<size_t>(n_features), 0.0f);
        std::vector<int64_t> input_shape = {1, n_features};
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem, x.data(), x.size(), input_shape.data(), input_shape.size()
        );

        // --- Collect output names ---
        size_t out_count = session.GetOutputCount();
        std::vector<std::string> out_name_strs;
        out_name_strs.reserve(out_count);
        for (size_t i = 0; i < out_count; ++i) {
            auto nm = session.GetOutputNameAllocated(i, allocator);
            out_name_strs.emplace_back(nm.get());
        }
        std::vector<const char*> output_names;
        output_names.reserve(out_count);
        for (auto& s : out_name_strs) output_names.push_back(s.c_str());

        const char* in_names[] = { input_name.c_str() };

        // --- Run ---
        auto outputs = session.Run(
            Ort::RunOptions{nullptr},
            in_names, &input_tensor, 1,
            output_names.data(), output_names.size()
        );

        // --- Print results ---
        std::cout << "Model loaded: " << model_path << "\n";
        std::cout << "Input shape fed: [1," << n_features << "]\n";

        for (size_t i = 0; i < outputs.size(); ++i) {
            auto& out = outputs[i];
            if (!out.IsTensor()) {
                std::cout << "Output[" << i << "] is not a tensor (map/seq). Skip.\n";
                continue;
            }
            auto info  = out.GetTensorTypeAndShapeInfo();
            auto et    = info.GetElementType();
            auto shape = info.GetShape();

            std::cout << "Output[" << i << "] et=" << et << " shape=[";
            for (size_t k = 0; k < shape.size(); ++k) {
                std::cout << shape[k] << (k + 1 < shape.size() ? "," : "");
            }
            std::cout << "]\n";

            if (et == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
                const float* ptr = out.GetTensorData<float>();
                size_t n = info.GetElementCount();
                std::cout << "  values(" << n << "): ";
                for (size_t j = 0; j < n && j < 10; ++j) std::cout << ptr[j] << " ";
                if (n > 10) std::cout << "...";
                std::cout << "\n";
            } else {
                std::cout << "  (non-float tensor; not printing raw data)\n";
            }
        }

        std::cout << "OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 1;
    }
}
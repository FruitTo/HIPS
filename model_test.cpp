// main.cpp
#include <onnxruntime/onnxruntime_cxx_api.h>
#include <iostream>
#include <vector>
#include <string>
#include <cassert>

int main() {
    try {
        // 1) เตรียม ORT
        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "ddos-test");
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        // 2) โหลดโมเดล
        const char* model_path = "model.onnx";
        Ort::Session session(env, model_path, opts);
        Ort::AllocatorWithDefaultOptions allocator;

        // 3) ชื่ออินพุต/เอาต์พุต
        auto in_name_alloc = session.GetInputNameAllocated(0, allocator);
        std::string input_name = in_name_alloc.get();

        size_t out_count = session.GetOutputCount();
        std::vector<std::string> out_name_strs;
        out_name_strs.reserve(out_count);
        for (size_t i = 0; i < out_count; ++i) {
            auto nm = session.GetOutputNameAllocated(i, allocator);
            out_name_strs.emplace_back(nm.get());
        }
        std::vector<const char*> output_names;
        for (auto& s : out_name_strs) output_names.push_back(s.c_str());

        // 4) เตรียมอินพุต (ต้องตรงลำดับคอลัมน์)
        //    << ใส่ค่าจริงตามลำดับฟีเจอร์ของคุณ >>
        //    ถ้ายังไม่มีค่า ทดสอบด้วยศูนย์ก่อนก็ได้เพื่อเช็ค pipeline/ORT
        //    หมายเหตุ: จากลิสต์ที่ส่งมา มี 77 ฟีเจอร์ (ไม่รวม Label)
        const size_t N_FEATURES = 77;   // ปรับให้ตรงกับของคุณ
        std::vector<float> x(N_FEATURES, 0.0f); // ตัวอย่าง: ทั้งหมดเป็นศูนย์

        // 5) สร้าง Tensor shape = {batch=1, features=N_FEATURES}
        std::vector<int64_t> input_shape = {1, static_cast<int64_t>(x.size())};
        Ort::MemoryInfo mem_info = Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem_info, x.data(), x.size(), input_shape.data(), input_shape.size()
        );

        // 6) รัน
        const char* input_names[] = { input_name.c_str() };
        auto outputs = session.Run(
            Ort::RunOptions{nullptr},
            input_names, &input_tensor, 1,
            output_names.data(), output_names.size()
        );

        // 7) แสดงผล
        for (size_t i = 0; i < outputs.size(); ++i) {
            auto& out = outputs[i];
            if (out.IsTensor()) {
                auto info = out.GetTensorTypeAndShapeInfo();
                auto et = info.GetElementType();
                auto shape = info.GetShape();

                std::cout << "Output[" << i << "] tensor type=" << et << " shape=[";
                for (size_t k = 0; k < shape.size(); ++k) {
                    std::cout << shape[k] << (k + 1 < shape.size() ? "," : "");
                }
                std::cout << "]\n";

                if (et == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
                    const float* prob = out.GetTensorData<float>();
                    size_t n = info.GetElementCount();
                    std::cout << "  float values (" << n << "): ";
                    for (size_t j = 0; j < n && j < 10; ++j) std::cout << prob[j] << " ";
                    std::cout << (n > 10 ? "..." : "") << "\n";
                } else if (et == ONNX_TENSOR_ELEMENT_DATA_TYPE_STRING) {
                    // อ่านสตริงจาก C API
                    size_t total_len = 0;
                    Ort::GetApi().GetStringTensorDataLength(out, &total_len);
                    std::vector<char> buffer(total_len);
                    std::vector<size_t> offsets(info.GetElementCount());
                    Ort::GetApi().GetStringTensorContent(out, buffer.data(), buffer.size(),
                                                         offsets.data(), offsets.size());
                    // batch=1 -> มี 1 สตริง
                    std::string label(buffer.data(),
                                      (offsets.size() > 1 ? offsets[1] : buffer.size()));
                    std::cout << "  label: " << label << "\n";
                }
            } else {
                std::cout << "Output[" << i << "] is not a tensor (map/seq). Skip printing.\n";
            }
        }

        std::cout << "OK\n";
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

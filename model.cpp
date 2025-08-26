#include <onnxruntime/onnxruntime_cxx_api.h>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <string>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

json jsonLoad(string path)
{
    fstream f(path);
    return json::parse(f);
}

int main()
{
    const std::string artifacts = "./artifacts";
    json meta = jsonLoad(artifacts + "/meta.json");
    json thr = jsonLoad(artifacts + "/threshold.json");
    // Count of Feature
    const int64_t n_features = static_cast<int64_t>(meta["feature_order"].size());
    // Threshold value
    const float BIN_THRESHOLD = thr.value("BIN_THRESHOLD", 0.5f);

    // Create Env
    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "ids");

    // Seesion Config
    Ort::SessionOptions so;
    so.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
    so.SetIntraOpNumThreads(1);

    // Create Session
    Ort::Session bin_sess{env, (artifacts + "/binary.onnx").c_str(), so};
    Ort::Session mul_sess{env, (artifacts + "/multiclass.onnx").c_str(), so};

    // แสดงชื่อ/รูปร่างอินพุตของ binary เพื่อเช็คว่าโหลดได้ถูก
    Ort::AllocatorWithDefaultOptions alloc;
    auto in_name = bin_sess.GetInputNameAllocated(0, alloc);
    auto in_info = bin_sess.GetInputTypeInfo(0).GetTensorTypeAndShapeInfo();
    auto in_shape = in_info.GetShape();

    cout << "binary input name = " << in_name.get() << "\nshape = [";
    for (size_t i = 0; i < in_shape.size(); ++i)
    {
        cout << in_shape[i] << (i + 1 < in_shape.size() ? ", " : "");
    }
    cout << "]\n";
}

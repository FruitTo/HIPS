// inference.cpp
#include "ids_runner.cpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <unordered_map>

using json = nlohmann::json;

static std::unordered_map<std::string,float> load_feature_map(const std::string& path){
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open features json: " + path);
    json j = json::parse(f, nullptr, true, true);
    if (!j.is_object()) throw std::runtime_error("features json must be an object {name: value, ...}");
    std::unordered_map<std::string,float> m;
    for (auto it=j.begin(); it!=j.end(); ++it){
        const auto& k = it.key();
        const auto& v = it.value();
        if (v.is_number()) {
            m[k] = v.get<float>();
        } else if (v.is_string()) {
            // เผื่อมาค่าเป็นสตริงตัวเลข
            m[k] = std::stof(v.get<std::string>());
        } // ถ้าไม่ใช่ ก็ข้าม
    }
    return m;
}

int main(int argc, char** argv) {
    try {
        std::string artifacts = "artifacts";
        std::string feat_json;
        if (argc >= 2) artifacts = argv[1];
        if (argc >= 3) feat_json = argv[2];

        IDSRunner ids(artifacts);

        // --- (ทางเลือก) บังคับให้รัน multiclass ตอนทดสอบ ---
        // ids.SetThreshold(0.0f);

        std::unordered_map<std::string,float> fmap;
        if (!feat_json.empty()) {
            fmap = load_feature_map(feat_json);
        } else {
            std::cerr << "[INFO] no features.json provided; using zeros (will likely get bin_prob ~ 0)\n";
        }

        IDSResult r = ids.Predict(fmap);
        std::cout << "is_attack=" << (r.is_attack ? "true" : "false")
                  << " bin_prob=" << r.bin_prob << "\n";
        if (r.is_attack) {
            std::cout << "class_id=" << r.class_id
                      << " name=" << r.class_name
                      << " prob=" << r.class_prob << "\n";
        }
        return 0;

    } catch (const Ort::Exception& e) {
        std::cerr << "[ORT] " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[ERR] " << e.what() << "\n";
        return 1;
    }
}

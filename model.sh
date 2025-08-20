g++ -std=c++17 model.cpp -I/opt/onnxruntime-1.22.1/include -L/opt/onnxruntime-1.22.1/lib -lonnxruntime  -o infer_fix && ./infer_fix

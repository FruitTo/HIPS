export ORT=/opt/onnxruntime-1.22.1
g++ -std=c++17 onnx-test.cpp -I"$ORT/include" -L"$ORT/lib" -lonnxruntime \
   -Wl,-rpath,"$ORT/lib" -O2 -o onnx-test
./onnx-test

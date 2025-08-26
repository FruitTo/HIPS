export ORT=/opt/onnxruntime-1.22.1
g++ -std=c++17 model.cpp -I$ORT/include -L$ORT/lib -lonnxruntime -Wl,-rpath,$ORT/lib -o model 
./model

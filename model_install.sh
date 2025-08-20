sudo apt-get update
sudo apt-get install -y language-pack-en
sudo apt install nlohmann-json3-dev
sudo locale-gen en_US en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8

cd ~/Downloads/Programs
git clone --branch v1.22.1 --recursive https://github.com/microsoft/onnxruntime.git
cd onnxruntime

./build.sh --config RelWithDebInfo --build_shared_lib --parallel 4 --skip_tests
sudo cmake --install build/Linux/RelWithDebInfo --prefix /opt/onnxruntime-1.22.1
echo "/opt/onnxruntime-1.22.1/lib" | sudo tee /etc/ld.so.conf.d/onnxruntime.conf
sudo ldconfig

echo 'export PKG_CONFIG_PATH=/opt/onnxruntime-1.22.1/lib/pkgconfig:$PKG_CONFIG_PATH' >> ~/.bashrc
source ~/.bashrc

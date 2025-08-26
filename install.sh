#!/usr/bin/env bash
set -euo pipefail

echo "[*] install dependencies"
sudo apt update
sudo apt install -y \
  build-essential cmake git flex bison pkg-config \
  libpcap-dev libpcre3-dev libpcre2-dev zlib1g-dev \
  libdumbnet-dev libluajit-5.1-dev libssl-dev \
  libhwloc-dev liblzma-dev libunwind-dev cpputest \
  libsqlite3-dev uuid-dev libcmocka-dev \
  libnetfilter-queue-dev libmnl-dev autotools-dev libfl-dev \
  libgoogle-perftools-dev libtins-dev libxxhash-dev

function ensure_repo() {
  local url=$1 localdir=$2
  if [ -d "$localdir/.git" ]; then
    echo "[*] $localdir already have → git pull"
    git -C "$localdir" pull
  else
    echo "[*] Clone $url → $localdir"
    git clone "$url" "$localdir"
  fi
}

# libpcap
echo "[*] prepare libpcap"
ensure_repo https://github.com/the-tcpdump-group/libpcap.git /tmp/libpcap
cd /tmp/libpcap
./autogen.sh
./configure
make -j4
sudo make install
sudo ldconfig

# libdaq
echo "[*] prepare libdaq"
ensure_repo https://github.com/snort3/libdaq.git /tmp/libdaq
cd /tmp/libdaq
./bootstrap
./configure
make -j4 && sudo make install
sudo ldconfig

# snort3
echo "[*] prepare snort3"
ensure_repo https://github.com/snort3/snort3.git /tmp/snort3
cd /tmp/snort3
./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
cd build
make -j4 && sudo make install

sudo ldconfig

snort -V

# onnx
sudo apt-get install -y language-pack-en
sudo apt install nlohmann-json3-dev
sudo locale-gen en_US en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8

git clone --branch v1.22.1 --recursive https://github.com/microsoft/onnxruntime.git
cd onnxruntime

./build.sh --config RelWithDebInfo --build_shared_lib --parallel 4 --skip_tests
sudo cmake --install build/Linux/RelWithDebInfo --prefix /opt/onnxruntime-1.22.1
echo "/opt/onnxruntime-1.22.1/lib" | sudo tee /etc/ld.so.conf.d/onnxruntime.conf
sudo ldconfig

echo 'export PKG_CONFIG_PATH=/opt/onnxruntime-1.22.1/lib/pkgconfig:$PKG_CONFIG_PATH' >> ~/.bashrc
source ~/.bashrc

# json library
git clone https://github.com/nlohmann/json.git
cd json
mkdir build
cd build
cmake ..
sudo make install
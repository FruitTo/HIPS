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

# sudo ethtool -K enp2s0 tx off rx off
# sudo ethtool -K enp2s0 tx on rx on

# sudo ip link set enp2s0 promisc on
# sudo ip link set enp2s0 promisc off

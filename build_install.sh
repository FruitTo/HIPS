#!/bin/bash

# Define the base directory
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Define paths
SNORT_DIR="$BASE_DIR/bin/snort3"
BUILD_DIR="$SNORT_DIR/build"
INSTALL_DIR="$BASE_DIR/bin/install/snort3"
DEPENDENCIES_DIR="$BASE_DIR/bin/dependencies"

# Compiler setup (try GCC 13 first, fallback to GCC 12 if there's a crash)
export CC=/usr/bin/gcc-13
export CXX=/usr/bin/g++-13

# Setup environment for libraries
export PKG_CONFIG_PATH=$(realpath "$DEPENDENCIES_DIR/lib/pkgconfig")
export LD_LIBRARY_PATH=$(realpath "$DEPENDENCIES_DIR/lib")

# Clone Snort repository if not present
if [ ! -d "$SNORT_DIR" ]; then
    echo "Cloning Snort3 repository..."
    git clone https://github.com/snort3/snort3.git "$SNORT_DIR"
fi

cd "$SNORT_DIR"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

# Check if GCC 13 works, if not fall back to GCC 12
if ! echo "int main(){}" | $CC -o test_gcc && ./test_gcc; then
    echo "GCC 13 failed, switching to GCC 12"
    export CC=/usr/bin/gcc-12
    export CXX=/usr/bin/g++-12
    rm -f test_gcc
fi

# Run cmake
cmake .. \
  -DCMAKE_INSTALL_PREFIX=$(realpath "$INSTALL_DIR") \
  -DCMAKE_PREFIX_PATH=$(realpath "$DEPENDENCIES_DIR") \
  -DCMAKE_LIBRARY_PATH=$(realpath "$DEPENDENCIES_DIR/lib") \
  -DCMAKE_INCLUDE_PATH=$(realpath "$DEPENDENCIES_DIR/include") \
  -DPKG_CONFIG_EXECUTABLE=/usr/bin/pkg-config \
  -DPCAP_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/include") \
  -DDAQ_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/include") \
  -DPCRE2_PCRE2_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/include") \
  -DZLIB_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/include") \
  -DLUAJIT_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/luajit/src") \
  -DHWLOC_INCLUDE_DIR=$(realpath "$DEPENDENCIES_DIR/include") \
  -DPCAP_LIBRARY=$(realpath "$DEPENDENCIES_DIR/lib/libpcap.so") \
  -DDAQ_LIBRARIES=$(realpath "$DEPENDENCIES_DIR/lib/libdaq.so") \
  -DPCRE2_PCRE2_LIBRARY=$(realpath "$DEPENDENCIES_DIR/lib/libpcre2-8.so") \
  -DZLIB_LIBRARY=$(realpath "$DEPENDENCIES_DIR/lib/libz.so") \
  -DLUAJIT_LIBRARY=$(realpath "$DEPENDENCIES_DIR/lib/libluajit-5.1.so") \
  -DHWLOC_LIBRARY=$(realpath "$DEPENDENCIES_DIR/lib/libhwloc.so")

# Build Snort (use -j1 to avoid compiler issues)
make -j4

# Install Snort
make install

echo "Snort has been successfully installed in $INSTALL_DIR"

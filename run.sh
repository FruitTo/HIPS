#!/bin/bash
set -euo pipefail

SOURCE_FILE="main.cpp"
OUTPUT_FILE="${SOURCE_FILE%.cpp}_exe"

CXX=${CXX:-g++}
CXX_FLAGS=${CXX_FLAGS:-"-std=c++20 -O2 -Wall -Wextra -pthread"}
INCLUDE_FLAGS="-I./include"

ORT=${ORT:-/opt/onnxruntime-1.22.1}
LIBDIR="$ORT/lib"
if [ ! -d "$LIBDIR" ]; then LIBDIR="$ORT/lib64"; fi

ONNX_INC="-I$ORT/include"
ONNX_LIB="-L$LIBDIR -lonnxruntime -Wl,-rpath,$LIBDIR"

LIB_FLAGS="-L./local/lib -ltins -lpcap -lssl -lxxhash -Wl,-rpath,\$ORIGIN/local/lib"

$CXX $CXX_FLAGS $INCLUDE_FLAGS $ONNX_INC "$SOURCE_FILE" onnx-api.cpp -o "$OUTPUT_FILE" $LIB_FLAGS $ONNX_LIB

if [[ "$SOURCE_FILE" == "main.cpp" ]]; then
  sudo env LD_LIBRARY_PATH="./local/lib:$LIBDIR" "./$OUTPUT_FILE"
else
  env LD_LIBRARY_PATH="./local/lib:$LIBDIR" "./$OUTPUT_FILE"
fi

#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: ./run.sh <source_file.cpp>"
  exit 1
fi

SOURCE_FILE=$1
OUTPUT_FILE="${SOURCE_FILE%.cpp}_exe"

CXX=g++
CXX_FLAGS="-std=c++20 -Wall -Wextra -g -pthread"
LIB_FLAGS="-ltins -lpcap -lssl -ljsoncpp -lxxhash"  # ต้องมี -lxxhash
INCLUDE_FLAGS="-I./include"

echo "Compiling $SOURCE_FILE with C++20..."
echo "Libraries: $LIB_FLAGS"  # เพิ่มเพื่อ debug

$CXX $CXX_FLAGS $INCLUDE_FLAGS "$SOURCE_FILE" -o "$OUTPUT_FILE" $LIB_FLAGS

if [ $? -eq 0 ]; then
  echo "Compilation successful. Running..."
  if [[ "$SOURCE_FILE" == "main.cpp" ]]; then
    sudo ./"$OUTPUT_FILE"
  else
    ./"$OUTPUT_FILE"
  fi
else
  echo "Compilation failed!"
  exit 1
fi

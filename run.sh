#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: ./run.sh <source_file.cpp>"
  exit 1
fi

SOURCE_FILE="$1"
OUTPUT_FILE="${SOURCE_FILE%.cpp}_exe"

CXX=g++
CXX_FLAGS="-std=c++20 -Wall -Wextra -g -pthread"
INCLUDE_FLAGS="-I./include"
LIB_FLAGS="-L./local/lib -ltins -lpcap -lssl -lxxhash -Wl,-rpath=\$ORIGIN/local/lib"

echo "Compiling $SOURCE_FILE..."
$CXX $CXX_FLAGS $INCLUDE_FLAGS "$SOURCE_FILE" -o "$OUTPUT_FILE" $LIB_FLAGS

if [ $? -eq 0 ]; then

  if [[ "$SOURCE_FILE" == "main.cpp" ]]; then
    sudo LD_LIBRARY_PATH=./local/lib ./"$OUTPUT_FILE"
  else
    LD_LIBRARY_PATH=./local/lib ./"$OUTPUT_FILE"
  fi
else
  echo "Compilation failed!"
  exit 1
fi

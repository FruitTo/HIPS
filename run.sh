#!/bin/bash

# Check if a source file is provided
if [ -z "$1" ]; then
  echo "Usage: sudo ./run.sh <source_file.cpp>"
  exit 1
fi

# Set your source file and output file
SOURCE_FILE=$1
OUTPUT_FILE="${SOURCE_FILE%.cpp}"

# Compiler and flags
CXX=g++
CXX_FLAGS="-std=c++17" # use C++17 for modern features
LIB_FLAGS="-ltins -lpcap -lssl -ljsoncpp"

# Compile the source file
$CXX $CXX_FLAGS "$SOURCE_FILE" -o "$OUTPUT_FILE" $LIB_FLAGS

# Check if compilation succeeded
if [ $? -eq 0 ]; then
  echo "Compilation successful. Running..."
  sudo ./"$OUTPUT_FILE"
else
  echo "Compilation failed!"
  exit 1
fi

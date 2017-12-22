#!/bin/bash
# Usage: ANDROID_NDK=<PATH TO NDK> generate.sh
ABIS="armeabi-v7a arm64-v8a x86 x86_64"

for ABI in $ABIS
do
  BUILD_DIR="$(pwd)/build_${ABI}"
  mkdir -p ${BUILD_DIR} && cd ${BUILD_DIR}
  cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
    -DANDROID_TOOLCHAIN=clang \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DANDROID_ABI=${ABI} \
    -DANDROID_PIE=on \
    -DANDROID_STL=c++_static \
    ..
  make -j3 install && cd .. && rm -rf ${BUILD_DIR}
done

echo All done!




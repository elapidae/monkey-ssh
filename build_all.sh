#!/bin/bash -e

git submodule update --init --recursive

mkdir -p build-all
cd build-all
    mkdir -p middle-side
    cd middle-side
        cmake ../../monkey-middle-side
        cmake --build . --config Release -j8
    cd ..
    mkdir -p end-side
    cd end-side
        cmake ../../monkey-end-side
        cmake --build . --config Release -j8
    cd ..
cd ..


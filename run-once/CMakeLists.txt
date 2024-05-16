cmake_minimum_required(VERSION 3.5)

project(run-once LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VLIBS_DIR ../vlibs2)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
include(${VLIBS_DIR}/cmake/vbyte_buffer.cmake)
include(${VLIBS_DIR}/cmake/vlog.cmake)

add_executable(${PROJECT_NAME} main.cpp ${V_SOURCES} ${V_HEADERS})

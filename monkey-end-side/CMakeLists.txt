cmake_minimum_required(VERSION 3.5)

project(monkey-end-side LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( VLIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../vlibs2 )
include(${VLIBS_DIR}/cmake/threads.cmake)
include(${VLIBS_DIR}/cmake/vnetwork.cmake)
include(${VLIBS_DIR}/cmake/vtimer.cmake)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
set( SRC ${V_HEADERS} ${V_SOURCES} )

add_executable( ${PROJECT_NAME} main.cpp ${SRC} )
target_link_libraries( ${PROJECT_NAME} ${V_LIBRARIES} )

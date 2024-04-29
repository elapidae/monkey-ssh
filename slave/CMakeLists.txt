cmake_minimum_required(VERSION 3.5)

project( monkey-slave LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

set(VLIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../vlibs2)
include(${VLIBS_DIR}/cmake/threads.cmake)
include(${VLIBS_DIR}/cmake/vnetwork.cmake)
include(${VLIBS_DIR}/cmake/vtimer.cmake)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
include(${VLIBS_DIR}/cmake/vbyte_buffer.cmake)
include(${VLIBS_DIR}/cmake/vsettings.cmake)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
set( SRC ${V_HEADERS} ${V_SOURCES} )

set( SHARED_DIR ${CMAKE_CURRENT_LIST_DIR}/../shared )
include_directories(${SHARED_DIR})
set( SRC ${SRC}
    ${SHARED_DIR}/monkey_rsa.cpp
    ${SHARED_DIR}/monkey_rsa.h
    ${SHARED_DIR}/monkey_aes.cpp
    ${SHARED_DIR}/monkey_aes.h
    ${SHARED_DIR}/settings.cpp
    ${SHARED_DIR}/settings.h
    ${SHARED_DIR}/keyval.cpp
    ${SHARED_DIR}/keyval.h
   )

set( SRC ${SRC}
     ${SHARED_DIR}/side_socket.h
     ${SHARED_DIR}/side_socket.cpp
    )

# apt install libssl-dev
find_package( OpenSSL REQUIRED )

add_executable( ${PROJECT_NAME} main.cpp ${SRC} )
target_link_libraries( ${PROJECT_NAME} ${V_LIBRARIES} OpenSSL::SSL )

cmake_minimum_required(VERSION 3.5)

project(monkey-middle-side LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VLIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../vlibs2)
include(${VLIBS_DIR}/cmake/threads.cmake)
include(${VLIBS_DIR}/cmake/vnetwork.cmake)
include(${VLIBS_DIR}/cmake/vtimer.cmake)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
include(${VLIBS_DIR}/cmake/vbyte_buffer.cmake)
include(${VLIBS_DIR}/cmake/vsettings.cmake)
include(${VLIBS_DIR}/cmake/vcmdline_parser.cmake)
set(SRC ${V_HEADERS} ${V_SOURCES})

# import pkg-config
find_package( PkgConfig REQUIRED )
if (PKG_CONFIG_FOUND)
    pkg_check_modules(sodium REQUIRED libsodium)
endif()
if ( NOT sodium_FOUND )
    message( FATAL_ERROR sodium )
endif()
message( STATUS "sodium libs: '${sodium_LIBRARIES}', inc: '${sodium_INCLUDEDIR}'" )
include_directories( ${sodium_INCLUDEDIR}/sodium )
set( V_LIBRARIES ${V_LIBRARIES} ${sodium_LIBRARIES} )

set( SRC ${SRC}
     monkey_rsa.cpp
     monkey_rsa.h
     monkey_aes.cpp
     monkey_aes.h
     node_socket.cpp
     node_socket.h
     node_server.cpp
     node_server.h
     settings.cpp
     settings.h
     side_socket.cpp
     side_socket.h
     keyval.cpp
     keyval.h
    )

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} main.cpp ${SRC})
target_link_libraries( ${PROJECT_NAME} ${V_LIBRARIES} ssh OpenSSL::SSL )

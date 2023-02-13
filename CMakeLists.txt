cmake_minimum_required(VERSION 3.21)
project(OvpncltWrapper)

set(CMAKE_CXX_STANDARD 17)

message("generator is set to ${CMAKE_GENERATOR}")
message("CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")

#set(CLI_OVPNDCO "1")
# set(USE_OPENSSL "1")
set(CMAKE_INSTALL_CONFIG_NAME "Debug")
set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/install" CACHE PATH "Installation directory")

cmake_policy(SET CMP0077 NEW)
#cmake_policy(SET CMP0048 NEW)

project(OvpncltWrapper)
message("PROJECT_NAME = ${PROJECT_NAME}")

# Set mbedtls options
OPTION(ENABLE_PROGRAMS "" OFF)
OPTION(USE_SHARED_MBEDTLS_LIBRARY "" OFF)
OPTION(ENABLE_TESTING "" OFF)

#OPTION(NO_LZO "" ON)
#OPTION(HAVE_LZ4 "" ON)
#OPTION(HAVE_LZO "" OFF)

ADD_DEFINITIONS(-DNO_LZO)

set(CORE_DIR ${CMAKE_CURRENT_LIST_DIR}/core)
MESSAGE("CORE_DIR = ${CORE_DIR}")
set(KOVPN_SOURCE "${CORE_DIR}/../kovpn" CACHE PATH "ovpn-dco kernel module source tree")
set(OVPN_DCO_SOURCE "${CORE_DIR}/../ovpn-dco" CACHE PATH "ovpn-dco kernel module source tree")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

# required modules for our task
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckIncludeFiles)
include(ExternalProject)

add_subdirectory(core)

add_executable(${PROJECT_NAME}
        main.cpp CustomClient.hpp
        )
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/core
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/asio/asio/include
        )

target_compile_definitions(${PROJECT_NAME} PRIVATE
        -DUSE_OPENSSL
        -DHAVE_CONFIG_H
        -DHAVE_LZO
        -DHAVE_LZ4
        -DASIO_STANDALONE
        -DUSE_ASIO
        -DOPENVPN_CORE_GIT_VERSION=\"${OPENVPN3_GIT}\"
        -DOPENVPN_SHOW_SESSION_TOKEN
        -DOPENSSL_API_COMPAT=0x10200000L
        -DOPENVPN_ALLOW_INSECURE_CERTPROFILE
        -DENABLE_EXTERNAL_PKI
        )
target_link_libraries(${PROJECT_NAME} xkey ovpnclilib)

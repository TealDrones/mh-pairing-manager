############################################################################
#
# AUTERION CONFIDENTIAL
# __________________
#
#  [2019] Auterion AG
#  All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of Auterion AG and its suppliers,
# if any. The intellectual and technical concepts contained
# herein are proprietary to Auterion AG
# and its suppliers and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained
# from Auterion AG.
############################################################################

cmake_minimum_required(VERSION 3.5)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(PkgConfig REQUIRED)

project(pairing-manager)

set(CMAKE_CXX_STANDARD 14)

add_definitions(
    -Wall
    -Wextra
    -Wno-unused-parameter
    -DCARDEMU_SUPPORT
    -DUNSECURE_DEBUG
)

file(GLOB CPP_SRC_FILES
    main.cpp
    pairingmanager.cpp
    crc32.cpp
    util.cpp
    jsoncpp.cpp
    openssl_aes.cpp
    openssl_base64.cpp
    openssl_rsa.cpp
    openssl_rand.cpp
    mavlinkhandler.cpp
)

set_source_files_properties(
    ${CPP_SRC_FILES}
    PROPERTIES
    LANGUAGE CXX
)

add_executable(${PROJECT_NAME}
    ${CPP_SRC_FILES}
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../mavlink/common
)

link_directories(
    ${PROJECT_SOURCE_DIR}/../served/lib
)

target_compile_options(${PROJECT_NAME} PUBLIC
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/../served/src
)

target_link_libraries(pairing-manager
    pthread
    served
    udev
    rt
    z
    crypto
)

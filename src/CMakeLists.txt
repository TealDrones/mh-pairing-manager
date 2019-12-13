############################################################################
#
# Copyright (c) 2019 Auterion AG. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name Auterion nor the names of its contributors may be
#    used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
############################################################################

cmake_minimum_required(VERSION 3.10)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(PkgConfig REQUIRED)
find_package(GTest REQUIRED)

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
    pairing_manager.cpp
    crc32.cpp
    util.cpp
    jsoncpp.cpp
    openssl_aes.cpp
    openssl_base64.cpp
    openssl_rsa.cpp
    openssl_rand.cpp
    mavlink_handler.cpp
    helper.cpp
)

add_library(pairing-manager-lib  "${CPP_SRC_FILES}" "${C_SRC_FILES}")

add_executable(${PROJECT_NAME}
    main.cpp
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

include_directories(
  ${PROJECT_SOURCE_DIR}/../served/src
  )

target_link_libraries(${PROJECT_NAME}
  PUBLIC
    pairing-manager-lib
)

target_link_libraries(pairing-manager-lib
  pthread
  served
  udev
  rt
  z
  crypto
)

set(SRCS_TEST
  helper_test.cpp
  pairing_manager_test.cpp
)
add_executable(PAIRING_MANAGER_GTESTS ${SRCS_TEST})
target_link_libraries(PAIRING_MANAGER_GTESTS ${GTEST_MAIN_LIBRARIES} ${GTEST_LIBRARIES} pairing-manager-lib)
add_test(NAME PAIRING_MANAGER_GTESTS COMMAND PAIRING_MANAGER_GTESTS)

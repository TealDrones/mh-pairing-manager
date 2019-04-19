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
project(pairing-manager)
option(SERVED_BUILD_SHARED "" OFF)
option(SERVED_BUILD_STATIC "" ON)
option(SERVED_BUILD_TESTS "" OFF)
option(SERVED_BUILD_EXAMPLES "" OFF)
add_subdirectory(served)
add_subdirectory(src)

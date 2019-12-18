/****************************************************************************
 *
 *   Copyright (c) 2019 Auterion AG. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name Auterion nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#include <stdlib.h>
#include "gtest/gtest.h"

#include "helper.h"
#include "pairing_manager.h"

TEST(helper_test, check_env_variables) {
  // GIVEN: the pairing manager class constructor and some environment variables
  PairingManager pairing_manager;
  // don't repeat pattern: it changes the global state
  setenv("PAIRING_MNG_DEVICE_NAME", "machine_name_test", 0);
  setenv("PAIRING_MNG_TYPE", "type", 0);

  // WHEN: we check for the environment variables
  check_env_variables(pairing_manager);

  // THEN: we expect the class memebers to be initialized with the environment variables if present, otherwise
  // with default values
  EXPECT_EQ("machine_name_test", pairing_manager.machine_name);
  EXPECT_EQ("/data/", pairing_manager.persistent_folder);
  EXPECT_EQ("type", pairing_manager.link_type);
  EXPECT_EQ("192.168.168", pairing_manager.ip_prefix);
  EXPECT_EQ("192.168.168.2", pairing_manager.air_unit_ip);
  EXPECT_EQ("29351", pairing_manager.pairing_port);
  EXPECT_EQ("12345678", pairing_manager.config_password);
  EXPECT_EQ("", pairing_manager.pairing_encryption_key);
  EXPECT_EQ("MH", pairing_manager.pairing_network_id);
  EXPECT_EQ("36", pairing_manager.pairing_channel);
  EXPECT_EQ("", pairing_manager.zerotier_id);
  EXPECT_EQ("eno1", pairing_manager.ethernet_device);

  // cleanup environment variables for next tests
  unsetenv("PAIRING_MNG_DEVICE_NAME");
  unsetenv("PAIRING_MNG_TYPE");
}

TEST(helper_test, parse_argv) {
  // GIVEN: the pairing manager class constructor and all the possible command line arguments
  PairingManager pairing_manager;
  const char *const argv[] = {
      "name",  "-n", "machine_name", "-d", "/data",         "-m", "12550",    "-p", "33333",      "-l",
      "link",  "-i", "192.168.168",  "-a", "192.168.168.2", "-c", "auterion", "-k", "1234567890", "-s",
      "CH_36", "-f", "36",           "-z", "123",           "-e", "eth0",     "-m", "12345"};

  // WHEN: we parse the command line arguments
  parse_argv(sizeof(argv) / sizeof(argv[0]), const_cast<char *const *>(argv), pairing_manager);

  // THEN: we expect the class memebers to updated with the variables from the command line
  EXPECT_EQ("machine_name", pairing_manager.machine_name);
  EXPECT_EQ("/data/", pairing_manager.persistent_folder);
  EXPECT_EQ("link", pairing_manager.link_type);
  EXPECT_EQ("192.168.168", pairing_manager.ip_prefix);
  EXPECT_EQ("192.168.168.2", pairing_manager.air_unit_ip);
  EXPECT_EQ("33333", pairing_manager.pairing_port);
  EXPECT_EQ("auterion", pairing_manager.config_password);
  EXPECT_EQ("1234567890", pairing_manager.pairing_encryption_key);
  EXPECT_EQ("CH_36", pairing_manager.pairing_network_id);
  EXPECT_EQ("36", pairing_manager.pairing_channel);
  EXPECT_EQ("123", pairing_manager.zerotier_id);
  EXPECT_EQ("eth0", pairing_manager.ethernet_device);
  EXPECT_EQ(12345, pairing_manager.mavlink_udp_port);
}

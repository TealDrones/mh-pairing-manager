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

#include "pairing_manager.h"
#include "gtest/gtest.h"

#include <stdlib.h>

TEST(pairing_manager_test, parse_buffer) {
  PairingManager pairing_manager;
  pairing_manager.link_type = "MH";
  pairing_manager.config_password = "auterionfct";
  pairing_manager.persistent_folder = "/tmp";

  std::string cmd;
  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;
  std::string config_pwd = "auterion";
  std::string modem_name = "microhard_test";
  std::string new_modem_ip = "192.168.168.2";
  std::string encryption_key = "foo";
  std::string network_id = "CH";
  std::string channel = "36";
  std::string bandwidth = "1";
  std::string power = "7";
  int n = 0;

  char buffer1[] = "login:\n";
  n = sizeof(buffer1) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer1, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("admin\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::PASSWORD, state);

  char buffer2[] = "Password:\n";
  n = sizeof(buffer2) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer2, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ(config_pwd + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::SYSTEM_SUMMARY, state);

  char buffer3[] = "Entering\n";
  n = sizeof(buffer3) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer3, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MSSYSI\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::ENCRYPTION_TYPE, state);

  char buffer4[] = "OK\n";
  n = sizeof(buffer4) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWVENCRYPT\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::CRYPTO_KEY, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWVENCRYPT=1," + encryption_key + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::MODEM_NAME, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MSMNAME=" + modem_name + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::MODEM_IP, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MNLAN=lan,EDIT,0," + new_modem_ip + ",255.255.255.0\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::POWER, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWTXPOWER=" + power + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::FREQUENCY, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWFREQ=" + channel + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::BANDWIDTH, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWBAND=" + bandwidth + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::NETWORK_ID, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWNETWORKID=" + network_id + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::SAVE, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT&W\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::WRITE_FLASH, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ(ConfigMicrohardState::DONE, state);
}

TEST(pairing_manager_test, parse_buffer_error) {
  PairingManager pairing_manager;
  pairing_manager.link_type = "MH";
  pairing_manager.config_password = "auterionfct";
  pairing_manager.persistent_folder = "/tmp";

  std::string cmd;
  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;
  std::string config_pwd = "auterion";
  std::string modem_name = "microhard_test";
  std::string new_modem_ip = "192.168.168.2";
  std::string encryption_key = "foo";
  std::string network_id = "CH";
  std::string channel = "36";
  std::string bandwidth = "1";
  std::string power = "7";
  int n = 0;

  char buffer1[] = "login:\n";
  n = sizeof(buffer1) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer1, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("admin\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::PASSWORD, state);

  char buffer2[] = "Password:\n";
  n = sizeof(buffer2) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer2, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ(config_pwd + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::SYSTEM_SUMMARY, state);

  char buffer3[] = "Entering\n";
  n = sizeof(buffer3) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer3, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MSSYSI\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::ENCRYPTION_TYPE, state);

  char buffer4[] = "OK\n";
  n = sizeof(buffer4) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWVENCRYPT\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::CRYPTO_KEY, state);

  n = sizeof(buffer4) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                               power);
  EXPECT_EQ("AT+MWVENCRYPT=1," + encryption_key + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::MODEM_NAME, state);

  for (size_t i = 0; i < 7; i++) {
    char buffer4[] = "ERROR\n";
    n = sizeof(buffer4) / sizeof(char);
    pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, modem_name, new_modem_ip, encryption_key, network_id, channel, bandwidth,
                                 power);
    EXPECT_EQ(ConfigMicrohardState::MODEM_NAME, state);
  }

  EXPECT_TRUE(state != ConfigMicrohardState::DONE);
}

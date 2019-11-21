/***************************************************************************
*
* AUTERION CONFIDENTIAL
* __________________
*
*  [2019] Auterion AG
*  All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of Auterion AG and its suppliers,
* if any. The intellectual and technical concepts contained
* herein are proprietary to Auterion AG
* and its suppliers and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Auterion AG.
***************************************************************************/

#include "gtest/gtest.h"
#include "pairing_manager.h"

#include <stdlib.h>

TEST(pairing_manager_test, parse_buffer)
{
  PairingManager pairing_manager;
  pairing_manager.link_type = "MH";
  pairing_manager.config_password = "auterionfct";
  pairing_manager.persistent_folder = "/home/martina/";

  std::string cmd;
  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;
  std::string config_pwd = "auterion";
  std::string encryption_key = "foo";
  std::string network_id = "CH";
  std::string channel = "36";
  std::string bandwidth = "1";
  std::string power = "7";
  int n = 0;

  char buffer1[] = "login:\n";
  n = sizeof(buffer1) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer1, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("admin\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::PASSWORD, state);

  char buffer2[] = "Password:\n";
  n = sizeof(buffer2) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer2, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ(config_pwd + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::CRYPTO_KEY, state);

  char buffer3[] = "Entering\n";
  n = sizeof(buffer3) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer3, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWVENCRYPT=1," + encryption_key + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::POWER, state);

  char buffer4[] = "OK\n";
  n = sizeof(buffer4) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWTXPOWER=" + power + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::FREQUENCY, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWFREQ=" + channel + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::BANDWIDTH, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWBAND=" + bandwidth + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::NETWORK_ID, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWNETWORKID=" + network_id + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::SAVE, state);

  pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT&W\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::DONE, state);
}

TEST(pairing_manager_test, parse_buffer_error)
{
  PairingManager pairing_manager;
  pairing_manager.link_type = "MH";
  pairing_manager.config_password = "auterionfct";
  pairing_manager.persistent_folder = "/home/martina/";

  std::string cmd;
  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;
  std::string config_pwd = "auterion";
  std::string encryption_key = "foo";
  std::string network_id = "CH";
  std::string channel = "36";
  std::string bandwidth = "1";
  std::string power = "7";
  int n = 0;

  char buffer1[] = "login:\n";
  n = sizeof(buffer1) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer1, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("admin\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::PASSWORD, state);

  char buffer2[] = "Password:\n";
  n = sizeof(buffer2) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer2, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ(config_pwd + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::CRYPTO_KEY, state);

  char buffer3[] = "Entering\n";
  n = sizeof(buffer3) / sizeof(char);
  pairing_manager.parse_buffer(cmd, state, buffer3, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
  EXPECT_EQ("AT+MWVENCRYPT=1," + encryption_key + "\n", cmd);
  EXPECT_EQ(ConfigMicrohardState::POWER, state);

  for (size_t i = 0; i < 5; i++) {
    char buffer4[] = "ERROR\n";
    n = sizeof(buffer4) / sizeof(char);
    pairing_manager.parse_buffer(cmd, state, buffer4, n, config_pwd, encryption_key, network_id, channel, bandwidth, power);
    EXPECT_EQ(ConfigMicrohardState::POWER, state);
  }

  EXPECT_TRUE(state != ConfigMicrohardState::DONE);
}

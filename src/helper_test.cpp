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

#include <stdlib.h>
#include "gtest/gtest.h"

#include "helper.h"
#include "pairingmanager.h"


TEST(helper_test, check_env_variables)
{
  // GIVEN: the pairing manager class constructor and some environment variables
  PairingManager pairing_manager;
  // don't repeat pattern: it changes the global state
  setenv("PAIRING_MNG_DEVICE_NAME","machine_name_test", 0);
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

TEST(helper_test, parse_argv)
{
  // GIVEN: the pairing manager class constructor and all the possible command line arguments
  PairingManager pairing_manager;
  const char * const argv[] = {
        "name",
        "-n", "machine_name",
        "-d", "/data",
        "-m", "12550",
        "-p", "33333",
        "-l", "link",
        "-i", "192.168.168",
        "-a", "192.168.168.2",
        "-c", "auterion",
        "-k", "1234567890",
        "-s", "CH_36",
        "-f", "36",
        "-z", "123",
        "-e", "eth0",
        "-m", "12345"
    };

  // WHEN: we parse the command line arguments
  parse_argv(sizeof(argv)/sizeof(argv[0]), const_cast<char * const *>(argv), pairing_manager);

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

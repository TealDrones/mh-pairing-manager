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

  // THEN: we expect the class memebers to be initiazed with the environment variables if present, otherwise
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

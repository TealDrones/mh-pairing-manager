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

#include "helper.h"

#include <unistd.h>

void help_argv_description(const char* pgm) {
  std::cout << pgm
            << " [OPTIONS...]\n\n"
               "  -n --machine-name      Machine name. Default: BALENA_DEVICE_NAME_AT_INIT or gethostname.\n"
               "  -m --mavlink-port      MavLink port on which we listen for MAV_CMD_START_RX_PAIR. Default: 14531\n"
               "  -p --pairing-port      Pairing port on which QGC send pair and connect commands. Default: 29351\n"
               "  -l --link-type         Link type. MH ... Microhard, ZT ... ZeroTier, TS ... Taisync\n"
               "  -k --pairing-key       Pairing encryption key\n"
               "  -d --persistent-folder Folder in which pairing information is permanently stored. Default: /data\n"
               "  -h --help              Print this message\n"
               "\n"
               "Microhard specific options:\n"
               "  -i --ip-prefix         Prefix for Microhard network. Default: 192.168.168\n"
               "  -a --air-unit-ip       IP of Microhard air unit. Default: 192.168.168.2\n"
               "  -c --config-password   Configuration password for Microhard Admin user\n"
               "  -s --pairing-net-id    Microhard pairing network id. Default: MH\n"
               "  -f --pairing-channel   Pairing channel\n"
               "  -b --pairing-bandwidth Pairing bandwidth\n"
               "\n"
               "ZeroTier specific options:\n"
               "  -z --zerotier-id       ZeroTier ID\n"
               "\n"
               "Taisync specific options:\n"
               "  -e --ethernet-device   Ethernet device to use. Default: eno1\n"
               "\n"
               "Environment variables:\n"
               "  PAIRING_MNG_DEVICE_NAME           equivalent to -n\n"
               "  PAIRING_MNG_PERSISTENT_FOLDER     equivalent to -d\n"
               "  PAIRING_MNG_TYPE                  equivalent to -l\n"
               "  PAIRING_MNG_IP_PREFIX             equivalent to -i\n"
               "  PAIRING_MNG_AIR_UNIT_IP           equivalent to -a\n"
               "  PAIRING_MNG_PAIRING_PORT          equivalent to -p\n"
               "  PAIRING_MNG_CONFIG_PWD            equivalent to -c\n"
               "  PAIRING_MNG_ENCRYPTION_KEY        equivalent to -k\n"
               "  PAIRING_MNG_PAIRING_NETWORK_ID    equivalent to -s\n"
               "  PAIRING_MNG_PAIRING_CHANNEL       equivalent to -f\n"
               "  PAIRING_MNG_PAIRING_BANDWIDTH     equivalent to -b\n"
               "  PAIRING_MNG_ZEROTIER_ID           equivalent to -z\n"
               "  PAIRING_MNG_ETHERNET_DEVICE       equivalent to -e\n";
}

void parse_argv(int argc, char* const argv[], PairingManager& pairing_manager) {
  static const struct option options[] = {
      {"machine-name", required_argument, nullptr, 'n'},    {"persistent-folder", required_argument, nullptr, 'd'},
      {"mavlink-port", required_argument, nullptr, 'm'},    {"pairing-port", required_argument, nullptr, 'p'},
      {"link-type", required_argument, nullptr, 'l'},       {"ip-prefix", required_argument, nullptr, 'i'},
      {"air-unit-ip", required_argument, nullptr, 'a'},     {"config-password", required_argument, nullptr, 'c'},
      {"pairing-key", required_argument, nullptr, 'k'},     {"pairing-net-id", required_argument, nullptr, 's'},
      {"pairing-channel", required_argument, nullptr, 'f'}, {"pairing-bandwidth", required_argument, nullptr, 'b'},
      {"zerotier-id", required_argument, nullptr, 'z'},
      {"ethernet-device", required_argument, nullptr, 'e'}, {"help", no_argument, nullptr, 'h'}};
  int c;
  bool invalid_argument = false;
  while ((c = getopt_long(argc, argv, "n:d:m:p:l:i:a:c:k:s:f:b:z:e:h", options, nullptr)) >= 0) {
    switch (c) {
      case 'h':
        help_argv_description(argv[0]);
        exit(0);
      case 'n':
        pairing_manager.machine_name = optarg;
        break;
      case 'd':
        pairing_manager.persistent_folder = std::string(optarg) + "/";
        break;
      case 'l':
        pairing_manager.link_type = optarg;
        break;
      case 'i':
        pairing_manager.ip_prefix = optarg;
        pairing_manager.pairing_cc_ip = pairing_manager.ip_prefix + ".10";
        pairing_manager.air_unit_ip = pairing_manager.ip_prefix + ".2";
        break;
      case 'a':
        pairing_manager.air_unit_ip = optarg;
        break;
      case 'c':
        pairing_manager.config_password = optarg;
        break;
      case 'k':
        pairing_manager.pairing_encryption_key = optarg;
        break;
      case 's':
        pairing_manager.pairing_network_id = optarg;
        break;
      case 'f':
        pairing_manager.pairing_channel = optarg;
        break;
      case 'b':
        pairing_manager.pairing_bandwidth = optarg;
        break;
      case 'z':
        pairing_manager.zerotier_id = optarg;
        break;
      case 'e':
        pairing_manager.ethernet_device = optarg;
        break;
      case 'm':
        if (!atoi(optarg, pairing_manager.mavlink_udp_port)) {
          invalid_argument = true;
        }
        break;
      case 'p':
        pairing_manager.pairing_port = optarg;
        break;
      case '?':
      default:
        help_argv_description(argv[0]);
        exit(-1);
    }
  }
  /* positional arguments */
  if (optind != argc || invalid_argument) {
    std::cout << timestamp() << "Invalid argument" << std::endl;
    help_argv_description(argv[0]);
    exit(-1);
  }
}

void check_env_variables(PairingManager& pairing_manager) {
  char buffer[1024];

  if (const char* name = std::getenv("PAIRING_MNG_DEVICE_NAME")) {
    pairing_manager.machine_name = name;
  } else if (const char* name = std::getenv("BALENA_DEVICE_NAME_AT_INIT")) {
    pairing_manager.machine_name = name;
  } else if (gethostname(buffer, sizeof(buffer)) == 0) {
    pairing_manager.machine_name = buffer;
  }

  if (const char* val = std::getenv("PAIRING_MNG_PERSISTENT_FOLDER")) {
    pairing_manager.persistent_folder = std::string(val) + "/";
  }

  if (const char* val = std::getenv("PAIRING_MNG_TYPE")) {
    pairing_manager.link_type = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_AIR_UNIT_IP")) {
    pairing_manager.air_unit_ip = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_IP_PREFIX")) {
    pairing_manager.ip_prefix = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_PAIRING_PORT")) {
    pairing_manager.pairing_port = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_CONFIG_PWD")) {
    pairing_manager.config_password = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_ENCRYPTION_KEY")) {
    pairing_manager.pairing_encryption_key = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_PAIRING_NETWORK_ID")) {
    pairing_manager.pairing_network_id = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_PAIRING_CHANNEL")) {
    pairing_manager.pairing_channel = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_PAIRING_BANDWIDTH")) {
    pairing_manager.pairing_bandwidth = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_ZEROTIER_ID")) {
    pairing_manager.zerotier_id = val;
  }

  if (const char* val = std::getenv("PAIRING_MNG_ETHERNET_DEVICE")) {
    pairing_manager.ethernet_device = val;
  }
}

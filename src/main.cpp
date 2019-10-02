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

/**
 * @file main.cpp
 *
 * @author Matej Frančeškin (Matej@auterion.com)
 */

#include <condition_variable>
#include <csignal>
#include <getopt.h>
#include <iostream>
#include <served/served.hpp>

#include "mavlinkhandler.h"
#include "pairingmanager.h"
#include "util.h"

static bool should_exit = false;
static std::mutex m;
static std::condition_variable cv;

//-----------------------------------------------------------------------------
void quit_handler(int /*sig*/)
{
    std::unique_lock<std::mutex> lk(m);
    should_exit = true;
    cv.notify_one();
}

//-----------------------------------------------------------------------------
static void
help(const char* pgm)
{
    printf(
        "%s [OPTIONS...]\n\n"
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
        "  PAIRING_MNG_ZEROTIER_ID           equivalent to -z\n"
        "  PAIRING_MNG_ETHERNET_DEVICE       equivalent to -e\n",
        pgm);
}

//-----------------------------------------------------------------------------
static void
parse_argv(int argc, char *argv[], PairingManager& pairing_manager)
{
    static const struct option options[] =
        {
            {"machine-name",      required_argument, nullptr, 'n'},
            {"persistent-folder", required_argument, nullptr, 'd'},
            {"mavlink-port",      required_argument, nullptr, 'm'},
            {"pairing-port",      required_argument, nullptr, 'p'},
            {"link-type",         required_argument, nullptr, 'l'},
            {"ip-prefix",         required_argument, nullptr, 'i'},
            {"air-unit-ip",       required_argument, nullptr, 'a'},
            {"config-password",   required_argument, nullptr, 'c'},
            {"pairing-key",       required_argument, nullptr, 'k'},
            {"pairing-net-id",    required_argument, nullptr, 's'},
            {"pairing-channel",   required_argument, nullptr, 'f'},
            {"zerotier-id",       required_argument, nullptr, 'z'},
            {"ethernet-device",   required_argument, nullptr, 'e'},
            {"help",              no_argument,       nullptr, 'h'}
        };
    int c;
    bool invalid_argument = false;
    while ((c = getopt_long(argc, argv, "n:d:m:p:l:i:a:c:k:s:f:z:e:h", options, nullptr)) >= 0) {
        switch (c) {
        case 'h':
            help(argv[0]);
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
            pairing_manager.air_unit_ip = optarg;
            break;
        case 'a':
            pairing_manager.ip_prefix = optarg;
            break;
        case 'c':
            pairing_manager.config_password = optarg;
            break;
        case 'k':
            pairing_manager.pairing_encryption_key = optarg;
            break;
        case 's':
            pairing_manager.pairing_network_id = to_upper(optarg);
            break;
        case 'f':
            pairing_manager.pairing_channel = optarg;
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
            help(argv[0]);
            exit(-EINVAL);
        }
    }
    /* positional arguments */
    if (optind != argc || invalid_argument) {
        std::cout << timestamp() << "Invalid argument" << std::endl;
        help(argv[0]);
        exit(-EINVAL);
    }
}

//-----------------------------------------------------------------------------
static void
check_env_variables(PairingManager& pairing_manager)
{
    char buffer[1024];

    if (const char* name = std::getenv("PAIRING_MNG_DEVICE_NAME")) {
        pairing_manager.machine_name = name;
    } else if (const char* name = std::getenv("BALENA_DEVICE_NAME_AT_INIT")) {
        pairing_manager.machine_name = name;
    } else if (gethostname(buffer, sizeof(buffer))==0) {
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
        pairing_manager.pairing_network_id = to_upper(val);
    }

    if (const char* val = std::getenv("PAIRING_MNG_PAIRING_CHANNEL")) {
        pairing_manager.pairing_channel = val;
    }

    if (const char* val = std::getenv("PAIRING_MNG_ZEROTIER_ID")) {
        pairing_manager.zerotier_id = val;
    }

    if (const char* val = std::getenv("PAIRING_MNG_ETHERNET_DEVICE")) {
        pairing_manager.ethernet_device = val;
    }
}

//-----------------------------------------------------------------------------
int
main(int argc, char *argv[])
{
    PairingManager pairing_manager;
    MAVLinkHandler mav_handler;

    check_env_variables(pairing_manager);
    parse_argv(argc, argv, pairing_manager);

    if (!pairing_manager.init()) {
        std::cout << timestamp() << "Could not initialize pairing manager" << std::endl;
        return -1;
    }

    std::cout << timestamp() << "Starting pairing manager" << std::endl;

    served::multiplexer mux;
    mux.handle("/status").get([](served::response& res, const served::request&) {
        std::cout << timestamp() << "Got status request." << std::endl;
        res << "Running";
    });
    mux.handle("/pair").post([&](served::response& res, const served::request& req) {
        res << pairing_manager.pair_gcs(req.body());
    });
    mux.handle("/unpair").post([&](served::response& res, const served::request& req) {
        res << pairing_manager.unpair_gcs(req.body());
    });
    mux.handle("/connect").post([&](served::response& res, const served::request& req) {
        res << pairing_manager.connect_gcs(req.body());
    });
    mux.handle("/disconnect").post([&](served::response& res, const served::request& req) {
        res << pairing_manager.disconnect_gcs(req.body());
    });
    mux.handle("/channel").post([&](served::response& res, const served::request& req) {
        res << pairing_manager.set_channel(req.body());
    });
#ifdef UNSECURE_DEBUG
    // Used for debugging if pairing button on PX4 is not available
    mux.handle("/startpairing").get([&pairing_manager](served::response& res, const served::request&) {
        res << "Pairing command " << (pairing_manager.handlePairingCommand() ? "accepted." : "denied.");
    });
#endif
    std::cout << timestamp() << "Listening on http://localhost:" << pairing_manager.pairing_port << "/pair" << std::endl;
    served::net::server server("0.0.0.0", pairing_manager.pairing_port, mux);
    server.run(3, false);

    //-- Start MAVLink handler
    mav_handler.init(pairing_manager.mavlink_udp_port, 198, [&](mavlink_message_t *msg, struct sockaddr* srcaddr) {
        if (msg->msgid == MAVLINK_MSG_ID_COMMAND_LONG) {
            mavlink_command_long_t cmd;
            mavlink_msg_command_long_decode(msg, &cmd);
            switch (cmd.command) {
                case MAV_CMD_START_RX_PAIR: {
                    // GCS pairing request handled by a companion (param1 = 10).
                    if (cmd.param1 == 10.f) {
                        unsigned char result = pairing_manager.handlePairingCommand() ? MAV_RESULT_ACCEPTED : MAV_RESULT_DENIED;
                        mav_handler.send_cmd_ack(msg->sysid, msg->compid, MAV_CMD_START_RX_PAIR, result, srcaddr);
                        break;
                    }
                }
            }
        }
    });

    signal(SIGINT,  quit_handler);
    signal(SIGTERM, quit_handler);
    std::unique_lock<std::mutex> lk(m);

    while (!should_exit)
    {
        cv.wait(lk);
    }

    server.stop();
    return 0;
}

//-----------------------------------------------------------------------------

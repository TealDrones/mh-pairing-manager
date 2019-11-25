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
#include <served/served.hpp>

#include "helper.h"
#include "mavlink_handler.h"

static bool should_exit = false;
static std::mutex m;
static std::condition_variable cv;

//-----------------------------------------------------------------------------
void quit_handler(int /*sig*/) {
  std::unique_lock<std::mutex> lk(m);
  should_exit = true;
  cv.notify_one();
}
//-----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
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
  mux.handle("/pair").post(
      [&](served::response& res, const served::request& req) { res << pairing_manager.pair_gcs_request(req.body()); });
  mux.handle("/unpair").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.unpair_gcs_request(req.body());
  });
  mux.handle("/connect").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.connect_gcs_request(req.body());
  });
  mux.handle("/disconnect").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.disconnect_gcs_request(req.body());
  });
  mux.handle("/channel").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.set_channel_request(req.body());
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
  mav_handler.init(pairing_manager.mavlink_udp_port, 198, [&](mavlink_message_t* msg, struct sockaddr* srcaddr) {
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

  signal(SIGINT, quit_handler);
  signal(SIGTERM, quit_handler);
  std::unique_lock<std::mutex> lk(m);

  while (!should_exit) {
    cv.wait(lk);
  }

  server.stop();
  return 0;
}

//-----------------------------------------------------------------------------

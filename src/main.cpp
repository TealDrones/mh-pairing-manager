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

static std::mutex m;
static std::condition_variable cv;

//-----------------------------------------------------------------------------
void quit_handler(int /*sig*/) {
  std::unique_lock<std::mutex> lk(m);
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
  mux.handle("/status").post([&](served::response& res, const served::request&) {
    res << pairing_manager.status_request();
  });
  mux.handle("/pair").post([&](served::response& res, const served::request& req) { 
    res << pairing_manager.pair_gcs_request(req.body());
  });
  mux.handle("/unpair").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.unpair_gcs_request(req.body());
  });
  mux.handle("/connect").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.connect_gcs_request(req.body());
  });
  mux.handle("/disconnect").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.disconnect_gcs_request(req.body());
  });
  mux.handle("/modemparameters").post([&](served::response& res, const served::request& req) {
    res << pairing_manager.set_modem_parameters_request(req.body());
  });
#ifdef UNSECURE_DEBUG
  // Used for debugging if pairing button on PX4 is not available
  mux.handle("/startpairing").get([&pairing_manager](served::response& res, const served::request&) {
    res << "Pairing command " << (pairing_manager.handle_pairing_command() ? "accepted." : "denied.");
  });
#endif
  std::cout << timestamp() << "Listening on http://localhost:" << pairing_manager.pairing_port << "/pair" << std::endl;
  served::net::server server("0.0.0.0", pairing_manager.pairing_port, mux);
  server.run(3, false);

  //-- Start MAVLink handler
  mav_handler.init(pairing_manager.mavlink_udp_port, MAV_COMP_ID_PAIRING_MANAGER,
    [&](mavlink_message_t* msg, struct sockaddr* srcaddr) {
    switch (msg->msgid) {
      case MAVLINK_MSG_ID_COMMAND_LONG: {
        mavlink_command_long_t cmd;
        mavlink_msg_command_long_decode(msg, &cmd);
        switch (cmd.command) {
          case MAV_CMD_START_RX_PAIR: {
            // GCS pairing request handled by a companion (param1 = 10).
            if (cmd.param1 == 10.f) {
              unsigned char result = pairing_manager.handle_pairing_command() ? MAV_RESULT_ACCEPTED : MAV_RESULT_DENIED;
              mav_handler.send_cmd_ack(msg->sysid, msg->compid, MAV_CMD_START_RX_PAIR, result, srcaddr);
            }
            break;
          }
        }
        break;
      }
    }
  });

  pairing_manager.set_RSSI_report_callback([&](int rssi) {
    std::cout << timestamp() << "RSSI: " << rssi << std::endl;
    mav_handler.send_radio_status(static_cast<uint8_t>(-rssi));
  });

  signal(SIGINT, quit_handler);
  signal(SIGTERM, quit_handler);

  std::unique_lock<std::mutex> lk(m);
  cv.wait(lk);

  server.stop();

  exit(0);

  return 0;
}

//-----------------------------------------------------------------------------

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

#pragma once

#include <mavlink.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <mutex>
#include <thread>

class MAVLinkHandler {
 public:
  MAVLinkHandler();
  ~MAVLinkHandler();

  bool init(uint16_t localPort, uint8_t comp_id,
            std::function<void(mavlink_message_t* msg, struct sockaddr* srcaddr)> messageHandler);
  void send_mavlink_message(const mavlink_message_t* message, struct sockaddr* srcaddr = nullptr);
  void send_cmd_ack(uint8_t target_sysid, uint8_t target_compid, uint16_t cmd, unsigned char result,
                    struct sockaddr* srcaddr);
  void send_radio_status(uint8_t rssi);
  void run();
  uint8_t sysID() { return _sysID; }

 private:
  void send_heartbeat();

 private:
  uint8_t _compID = 0;
  uint8_t _sysID = 0;
  int _fd = -1;
  struct sockaddr_in _myaddr {};      ///< The locally bound address
  struct sockaddr_in _targetAddr {};  ///< Target address (router)
  struct pollfd _fds[1]{};
  bool _threadRunning = true;
  bool _hasTarget = false;
  bool _hasSysID = false;
  std::mutex _udpMutex;
  std::thread _udpThread;
  std::function<void(mavlink_message_t* msg, struct sockaddr* srcaddr)> _msgHandlerCallback = nullptr;
  std::chrono::steady_clock::time_point _lastHeartbeat;
};

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

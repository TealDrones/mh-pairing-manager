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

#include <iostream>

#include "mavlink_handler.h"
#include "util.h"

//-----------------------------------------------------------------------------
MAVLinkHandler::MAVLinkHandler()
{
    _lastHeartbeat = std::chrono::steady_clock::now();
    memset(&_targetAddr, 0, sizeof(_targetAddr));
}

//-----------------------------------------------------------------------------
MAVLinkHandler::~MAVLinkHandler()
{
    _threadRunning = false;
    if(_fd >= 0) {
        close(_fd);
        _fd = -1;
    }
    if(_udpThread.joinable()) {
        _udpThread.join();
    }
}

//-----------------------------------------------------------------------------
bool
MAVLinkHandler::init(uint16_t localPort, uint8_t comp_id, std::function<void(mavlink_message_t *msg, struct sockaddr* srcaddr)> messageHandler) {
    _compID = comp_id;
    _msgHandlerCallback = std::move(messageHandler);
    // Create socket
    if ((_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cout << timestamp() << "Create pairing-manager UDP socket failed" << std::endl;
        return false;
    }
    memset(&_myaddr, 0, sizeof(_myaddr));
    _myaddr.sin_family = AF_INET;
    _myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // Choose the default cam port
    _myaddr.sin_port = htons(localPort);
    if (::bind(_fd, reinterpret_cast<struct sockaddr*>(&_myaddr), sizeof(_myaddr)) < 0) {
        std::cout << timestamp() << "Bind failed for UDP port " << localPort << std::endl;
        return false;
    }
    _fds[0].fd = _fd;
    _fds[0].events = POLLIN;
    mavlink_status_t* chan_state = mavlink_get_channel_status(MAVLINK_COMM_1);
    chan_state->flags &= ~(MAVLINK_STATUS_FLAG_OUT_MAVLINK1);
    _udpThread = std::thread(&MAVLinkHandler::run, this);
    return true;
}

//-----------------------------------------------------------------------------
void
MAVLinkHandler::send_mavlink_message(const mavlink_message_t *message, struct sockaddr* srcaddr)
{
    struct sockaddr* target = srcaddr ? srcaddr : reinterpret_cast<struct sockaddr*>(&_targetAddr);
    uint8_t buffer[MAVLINK_MAX_PACKET_LEN];
    size_t packetlen = mavlink_msg_to_send_buffer(buffer, message);
    std::lock_guard<std::mutex> guard(_udpMutex);
    ssize_t len = sendto(_fd, buffer, packetlen, 0, target, sizeof(_targetAddr));
    if (len <= 0) {
        std::cout << timestamp() << "Failed sending mavlink message: " << message->msgid << std::endl;
    }
}

//-----------------------------------------------------------------------------
void
MAVLinkHandler::send_cmd_ack(uint8_t target_sysid, uint8_t target_compid, uint16_t cmd, unsigned char result, struct sockaddr* srcaddr)
{
    if(_hasSysID) {
        mavlink_message_t msg;
        mavlink_msg_command_ack_pack_chan(
            _sysID,
            _compID,
            MAVLINK_COMM_1,
            &msg,
            cmd,
            result,
            100,
            0,
            target_sysid,
            target_compid);
        send_mavlink_message(&msg, srcaddr);
    }
}

//-----------------------------------------------------------------------------
void
MAVLinkHandler::send_heartbeat()
{
    if(_hasSysID) {
        mavlink_message_t msg;
        mavlink_msg_heartbeat_pack_chan(_sysID, _compID, MAVLINK_COMM_1, &msg, MAV_TYPE_GENERIC, MAV_AUTOPILOT_GENERIC, 0, 0, 0);
        send_mavlink_message(&msg);
    }
    fflush(stdout);
    fflush(stderr);
}

//-----------------------------------------------------------------------------
void
MAVLinkHandler::run()
{
    std::cout << timestamp() << "MAVLink thread started" << std::endl;
    mavlink_status_t  status;
    mavlink_message_t msg;
    unsigned char buffer[16 * 1024];
    while (_threadRunning) {
        ::poll(&_fds[0], (sizeof(_fds[0]) / sizeof(_fds[0])), 1000);
        if(_fd < 0) {
            break;
        }
        if (_fds[0].revents & POLLIN) {
            struct sockaddr srcaddr{};
            socklen_t addrlen = sizeof(srcaddr);
            ssize_t len = recvfrom(_fd, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&srcaddr), &addrlen);
            if (len > 0) {
                for (unsigned i = 0; i < len; ++i)
                {
                    if (mavlink_parse_char(MAVLINK_COMM_1, buffer[i], &msg, &status))
                    {
                        if(!_hasTarget) {
                            _hasTarget = true;
                            memcpy(&_targetAddr, &srcaddr, sizeof(_targetAddr));
                            char addr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &(_targetAddr.sin_addr), addr, INET_ADDRSTRLEN);
                            std::cout << timestamp() << "Got UDP target: " << addr << ":" << std::dec << ntohs(_targetAddr.sin_port) << std::endl;
                        }
                        if (!_hasSysID && msg.compid == MAV_COMP_ID_AUTOPILOT1 && msg.msgid == MAVLINK_MSG_ID_HEARTBEAT) {
                            _sysID = msg.sysid;
                            _hasSysID = true;
                        }
                        // Have a message, handle it
                        if(_msgHandlerCallback) {
                            _msgHandlerCallback(&msg, &srcaddr);
                        }
                        memset(&status, 0, sizeof(status));
                        memset(&msg, 0, sizeof(msg));
                    }
                }
            }
        }
        // Our heartbeat
        if(_hasTarget) {
            auto current = std::chrono::steady_clock::now();
            if(std::chrono::duration_cast<std::chrono::milliseconds>(current - _lastHeartbeat).count() > 1000) {
                _lastHeartbeat = current;
                send_heartbeat();
            }
        }
    }
    std::cout << timestamp() << "MAVLink thread stopped" << std::endl;
}

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

#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "json/json.h"
#include "openssl_aes.h"
#include "openssl_rsa.h"

const std::string default_pairing_channel = "36";
const std::string default_transmit_power = "7";

/**
* State Transitions:
* LOGIN -> PASSWORD -> CRYPTO_KEY -> POWER -> FREQUENCY -> BANDWIDTH -> NETWORK_ID -> SAVE -> DONE
**/
enum class ConfigMicrohardState {
  LOGIN,
  PASSWORD,
  SYSTEM_SUMMARY,
  CRYPTO_KEY,
  MODEM_NAME,
  MODEM_CHECK_NAME,
  MODEM_IP,
  POWER,
  DISTANCE,
  DEFAULT_FREQUENCY,
  FREQUENCY,
  BANDWIDTH,
  NETWORK_ID,
  SAVE,
  WRITE_FLASH,
  DONE,
  GET_STATUS,
  READ_STATUS,
  ENCRYPTION_TYPE,
  NONE
};

class PairingManager {
 public:
  PairingManager();
  ~PairingManager();

  bool init();
  std::string pair_gcs_request(const std::string& req_body);
  std::string unpair_gcs_request(const std::string& req_body);
  std::string connect_gcs_request(const std::string& req_body);
  std::string disconnect_gcs_request(const std::string& req_body);
  std::string set_modem_parameters_request(const std::string& req_body);
  std::string status_request();
  bool handle_pairing_command();
  void set_RSSI_report_callback(std::function<void(int)> report_callback);

  // Parameters
  std::string link_type;
  std::string machine_name = "unknown";
  std::string ip_prefix = "192.168.168";
  std::string pairing_cc_ip = ip_prefix + ".10";
  std::string air_unit_ip = ip_prefix + ".2";
  std::string pairing_port = "29351";
  std::string config_password = "12345678";
  std::string pairing_encryption_key = "";
  std::string pairing_network_id = "MH";
  std::string pairing_channel = default_pairing_channel;
  std::string pairing_bandwidth = "";
  std::string zerotier_id = "";
  std::string ethernet_device = "eno1";
  std::string persistent_folder = "/data/";
  int mavlink_udp_port = 14531;

  /**
  * @brief       parses the communication to configure the microhard radio
  * @param[out]  cmd, AT command to send to the microhard
  * @param[out]  state, stage of the microhard configuration
  * @param[in]   buffer, microhard response to a command
  * @param[in]   n, number of bytes read from socket
  * @param[in]   config_pwd, configuration password to log into a microhard via telnet
  * @param[in]   encryption_key, key to encrypt the communication between microhards
  * @param[in]   network_id, id to identify a network of devices
  * @param[in]   channel, channel where the microhards communicate while paired
  * @param[in]   bandwidth, each channel bandwidth [MHz]
  * @param[in]   power, transmission power
  **/
  void parse_buffer(std::string& cmd, ConfigMicrohardState& state, char* buffer, int n,
                    const std::string& config_pwd, const std::string& modem_name,
                    const std::string& new_modem_ip, const std::string& encryption_key,
                    const std::string& network_id, const std::string& channel, const std::string& bandwidth,
                    const std::string& power, bool check_name = false);

  /**
  * @brief       parses the the microhard radio response to an AT command
  * @param[in]   output, string containing the microhard response
  * @returns     true if the AT command succeeded
  **/
  static bool check_at_result(const std::string& output);

  /**
  * @brief       parses the the microhard radio response to an AT command for getting modem name
  * @param[in]   output, string containing the microhard response
  * @returns     true if the name matches
  **/
  static bool check_at_result_modem_name(const std::string& output, const std::string& name);

  /**
  * @brief       parses the the microhard radio response to an AT command for getting encryption type
  * @param[in]   output, string containing the microhard response
  * @returns     true if the name matches
  **/
  static bool check_at_result_encryption_type(const std::string& output, std::string& type);

  /**
  * @brief       prints the microhard response to AT commands for debugging purposes
  * @param[in]   logbuf, string containing the microhard response
  **/
  static void print_microhard_buffer_debug(std::string& logbuf);

 private:
  OpenSSL_AES _aes;
  OpenSSL_RSA _rsa;
  OpenSSL_RSA _gcs_rsa;
  Json::Value _pairing_val;
  bool _pairing_mode = false;
  std::string _ip = "";
  std::string _port = "";
  std::mutex _udp_mutex;
  std::mutex _mh_mutex;
  std::mutex _quit_mutex;
  std::mutex _operation_mutex;
  std::condition_variable _quit_cv;
  std::function<void(int)> _rssi_report_callback;
  bool _get_status_initialized = false;
  int _fd;
  std::string _system_summary;
  std::string _encryption_type = "1";

  bool _config_timeout_running = false;
  std::mutex _config_timeout_mutex;
  std::condition_variable _config_timeout_cv;

  std::chrono::steady_clock::time_point _last_pairing_time_stamp;

  void configure_microhard_network_interface(const std::string& ip);
  bool configure_microhard_now(const std::string& air_ip, const std::string& config_pwd,
                           const std::string& modem_name,
                           const std::string& new_mh_ip, const std::string& encryption_key,
                           const std::string& network_id, const std::string& channel,
                           const std::string& bandwidth, const std::string& power,
                           bool check_name = false);
  void configure_microhard(const std::string& air_ip, const std::string& config_pwd,
                           const std::string& modem_name, const std::string& new_cc_ip,
                           const std::string& new_mh_ip, const std::string& encryption_key,
                           const std::string& network_id, const std::string& channel,
                           const std::string& bandwidth, const std::string& power);
  void reconfigure_microhard();
  bool create_gcs_pairing_json(const std::string& s,
                               std::string& cc_ip, std::string& mh_ip,
                               std::string& connect_key, std::string& channel,
                               std::string& bandwidth, std::string& network_id);
  void create_pairing_val();
  void create_pairing_val_for_zerotier(Json::Value& val);
  void create_pairing_val_for_microhard(Json::Value& val);
  void create_pairing_val_for_taisync(Json::Value& val);
  void open_udp_endpoint(const std::string& ip, const std::string& port);
  void refresh_udp_endpoint();
  void remove_endpoint(const std::string& name);
  /**
  * @brief       writes to the mavlink router pipe
  * @param[in]   msg, buffer to be written
  **/
  void write_to_mavlink_router_pipe(const std::string& msg);
  /**
  * @brief      print json for debugging purposes
  * @param[in]  msg, message to be printed together with values
  * @param[int] val, json value
  **/
  static void print_json(const std::string& msg, const Json::Value& val);
  bool unpair_gcs(const std::string& req_body);
  bool connect_gcs(const std::string& req_body, std::string& channel);
  /**
  * @brief      decrypts a string and converts into a json
  * @param[in]  in, input string
  * @param[out] out, output json
  * @returns    true if the conversion into json was successful
  **/
  bool decrypt_string_to_json(const std::string& in, Json::Value& out);
  bool disconnect_gcs(const std::string& req_body);
  /**
  * @brief       connects a socket to the vehicle
  * @param[in]   sock, socket file descriptor
  * @param[in]   air_ip, vehicle ip address
  * @reurns      true, if the connection succeeded
  **/
  bool is_socket_connected(const int& sock, const std::string& air_ip);
  bool set_modem_parameters(const std::string& req_body, Json::Value& val);
  bool set_modem_parameters(const std::string& new_network_id, const std::string& new_ch, const std::string& power,
                            const std::string& new_bandwidth);
  bool write_json_gcs_file(std::string filename, Json::Value& val, bool print = true);
  bool verify_request(const std::string& req_body, Json::Value& val);
  std::string pack_response(Json::Value& response);
  std::string get_json_gcs_filename();
  std::string get_prev_json_gcs_filename();
  /**
  * @brief      converts from json to string
  * @param[in]  val, json data stucture
  * @returns    json data in string type
  **/
  std::string from_json_to_string(const Json::Value& val);

  /**
  * @brief      Reads and handles Microhard modem status
  * @returns    json data in string type
  **/
  bool get_microhard_modem_status();

  /**
  * @brief      Parse Microhard modem status output
  * @param[in]  output, what modem returns when asked for status
  **/
  void parse_microhard_modem_status(std::string output);

  void start_modem_config_timeout();
  void stop_modem_config_timeout();

  void quit();
};

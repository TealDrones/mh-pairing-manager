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

#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "json/json.h"
#include "openssl_aes.h"
#include "openssl_rsa.h"

const std::string default_pairing_channel = "36";
const std::string default_pairing_bandwidth = "1";
const std::string default_transmit_power = "7";

/**
* State Transitions:
* LOGIN -> PASSWORD -> CRYPTO_KEY -> POWER -> FREQUENCY -> BANDWIDTH -> NETWORK_ID -> SAVE -> DONE
**/
enum class ConfigMicrohardState {
  LOGIN,
  PASSWORD,
  CRYPTO_KEY,
  POWER,
  FREQUENCY,
  BANDWIDTH,
  NETWORK_ID,
  SAVE,
  DONE,
  GET_STATUS,
  READ_STATUS,
  NONE
};

class PairingManager {
 public:
  PairingManager();
  ~PairingManager();

  bool init();
  std::string get_pairing_json();
  std::string pair_gcs_request(const std::string& req_body);
  std::string unpair_gcs_request(const std::string& req_body);
  std::string connect_gcs_request(const std::string& req_body);
  std::string disconnect_gcs_request(const std::string& req_body);
  std::string set_channel_request(const std::string& req_body);
  bool handlePairingCommand();
  void set_RSSI_report_callback(std::function<void(int)> report_callback);

  // Parameters
  std::string link_type;
  std::string machine_name = "unknown";
  std::string ip_prefix = "192.168.168";
  std::string air_unit_ip = "192.168.168.2";
  std::string pairing_port = "29351";
  std::string config_password = "12345678";
  std::string pairing_encryption_key = "";
  std::string pairing_network_id = "MH";
  std::string pairing_channel = default_pairing_channel;
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
  static void parse_buffer(std::string& cmd, ConfigMicrohardState& state, char* buffer, int n,
                           const std::string& config_pwd, const std::string& encryption_key,
                           const std::string& network_id, const std::string& channel, const std::string& bandwidth,
                           const std::string& power);

  /**
  * @brief       parses the the microhard radio response to an AT command
  * @param[in]   output, string containing the microhard response
  * @returns     true if the AT command succeeded
  **/
  static bool check_at_result(const std::string& output);

  /**
  * @brief       prints the microhard response to AT commands for debugging purposes
  * @param[in]   logbuf, string containing the microhard response
  **/
  static void print_microhard_buffer_debug(std::string& logbuf);

 private:
  OpenSSL_AES _aes;
  OpenSSL_RSA _rsa;
  OpenSSL_RSA _gcs_rsa;
  std::string _pairing_json = "";
  Json::Value _pairing_val;
  std::mutex _pairing_mutex;
  bool _pairing_mode = false;
  std::string _ip = "";
  std::string _port = "";
  std::mutex _udp_mutex;
  std::mutex _mh_mutex;
  std::function<void(int)> _rssi_report_callback;
  bool _get_status_initialized = false;
  int _fd;

  std::chrono::steady_clock::time_point _last_pairing_time_stamp;

  void configure_microhard(const std::string& air_ip, const std::string& config_pwd, const std::string& encryption_key,
                           const std::string& network_id, const std::string& channel, const std::string& bandwidth,
                           const std::string& power);
  void reconfigure_microhard();
  bool create_gcs_pairing_json(const std::string& s, std::string& connect_key, std::string& channel,
                               std::string& bandwidth, std::string& network_id);
  void create_pairing_json();
  void create_pairing_json_for_zerotier(Json::Value& val);
  void create_pairing_json_for_microhard(Json::Value& val);
  void create_pairing_json_for_taisync(Json::Value& val);
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
  bool set_channel(const std::string& req_body, Json::Value& val);
  bool set_channel(const std::string& new_network_id, const std::string& new_ch, const std::string& power,
                   const std::string& new_bandwidth);
  bool write_json_gcs_file(Json::Value& val);
  bool verify_request(const std::string& req_body, Json::Value& val);
  std::string pack_response(Json::Value& response);
  std::string get_json_gcs_filename();
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
};

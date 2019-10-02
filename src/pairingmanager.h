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

#include <mutex>
#include <string>
#include <thread>

#include "openssl_aes.h"
#include "openssl_rsa.h"
#include "json/json.h"

const std::string default_pairing_channel = "36";
const std::string default_pairing_bandwidth = "1";
const std::string default_transmit_power = "7";

class PairingManager
{
public:
    PairingManager();

    bool        init();
    std::string get_pairing_json();
    std::string pair_gcs(const std::string& req_body);
    std::string unpair_gcs(const std::string& req_body);
    std::string connect_gcs(const std::string& req_body);
    std::string disconnect_gcs(const std::string& req_body);
    std::string set_channel(const std::string& req_body);
    bool        handlePairingCommand();

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
    int         mavlink_udp_port = 14531;

private:
    OpenSSL_AES _aes;
    OpenSSL_RSA _rsa;
    OpenSSL_RSA _gcs_rsa;
    std::string _pairing_json = "";
    Json::Value _pairing_val;
    std::mutex  _pairing_mutex;
    bool        _pairing_mode = false;
    std::string _ip = "";
    std::string _port = "";
    std::mutex  _udp_mutex;
    std::mutex  _mh_mutex;

    std::chrono::steady_clock::time_point _last_pairing_time_stamp;

    void        _configure_microhard(const std::string& air_ip, const std::string& config_pwd,
                                     const std::string& encryption_key, const std::string& network_id,
                                     const std::string& channel, const std::string& bandwidth,
                                     const std::string& power);
    void        _reconfigure_microhard();
    bool        _create_gcs_pairing_json(const std::string& s, std::string& connect_key,
                                         std::string& channel, std::string& bandwidth,
                                         std::string& network_id);
    void        _create_pairing_json();
    void        _create_pairing_json_for_zerotier(Json::Value& val);
    void        _create_pairing_json_for_microhard(Json::Value& val);
    void        _create_pairing_json_for_taisync(Json::Value& val);
    void        _open_udp_endpoint(const std::string& ip, const std::string& port);
    void        _refresh_udp_endpoint();
    void        _remove_endpoint(const std::string& name);
    bool        _unpair_gcs(const std::string& req_body);
    bool        _connect_gcs(const std::string& req_body, std::string& channel);
    bool        _disconnect_gcs(const std::string& req_body);
    bool        _set_channel(const std::string& req_body, Json::Value& val);
    bool        _set_channel(const std::string& new_network_id, const std::string& new_ch,
                             const std::string& power, const std::string& new_bandwidth);
    bool        _write_json_gcs_file(Json::Value& val);
    bool        _check_at_result(const std::string& output);
    bool        _verify_request(const std::string& req_body, Json::Value& val);
    std::string _pack_response(Json::Value& response);
    std::string _get_json_gcs_filename();
};
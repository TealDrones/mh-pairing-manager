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
 * @file pairingmanager.cpp
 *
 * @author Matej Frančeškin (Matej@auterion.com)
 */

#include <fstream>
#include <iostream>
#include <served/served.hpp>

#include "openssl_rand.h"
#include "pairingmanager.h"
#include "util.h"

using namespace std::chrono_literals;

const int random_aes_key_length = 8;
const int microhard_settings_port = 23;
const char* json_filename = "temp_pairing.json";
const char* json_gcs_filename = "pairing.json";
const char* pipe_path = "/tmp/mavlink_router_pipe";

//-----------------------------------------------------------------------------
PairingManager::PairingManager() :
    _aes()
{
    _last_pairing_time_stamp = std::chrono::steady_clock::now();
}

//-----------------------------------------------------------------------------
bool
PairingManager::init()
{
    if (access(persistent_folder.c_str(), 0) != 0) {
        std::cout << "Persistent directory " << persistent_folder << " does not exist. Using current working directory." << std::endl;
        persistent_folder = "./";
    }

    _aes.init(pairing_encryption_key);
    _create_pairing_json();

    std::thread([this]() {
        while (true)
        {
            _udp_mutex.lock();
            _refresh_udp_endpoint();
            _udp_mutex.unlock();
            std::this_thread::sleep_for(10s);
        }
    }).detach();

    return true;
}

//-----------------------------------------------------------------------------
void
PairingManager::_configure_microhard(
    const std::string& air_ip,
    const std::string& config_pwd,
    const std::string& encryption_key,
    const std::string& network_id,
    const std::string& channel,
    const std::string& bandwidth,
    const std::string& power)
{
    std::lock_guard<std::mutex> guard(_mh_mutex);
    bool connected = false;
    int retries = 5;
    bool done = false;

    if (config_pwd == "") {
        std::cout << timestamp() << "Microhard config password not set." << std::endl;
        return;
    }

    while (retries > 0 && !done) {
        std::cout << timestamp() << "Configure microhard." << std::endl;
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            fcntl(sock, F_SETFL, O_NONBLOCK);
            struct sockaddr_in serv_addr;
            memset(&serv_addr, '0', sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(microhard_settings_port);
            if (inet_pton(AF_INET, air_ip.c_str(), &serv_addr.sin_addr) > 0)
            {
                connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
                fd_set fdset;
                struct timeval tv;
                FD_ZERO(&fdset);
                FD_SET(sock, &fdset);
                tv.tv_sec = 10;             /* 10 second timeout */
                tv.tv_usec = 0;
                if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
                    int so_error;
                    socklen_t len = sizeof so_error;
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                    if (so_error == 0) {
                        connected = true;
                    }
                }
            }
            if (connected) {
                char buffer[1024];
                int state = 0;
                std::string output;
                std::string logbuf;
                std::string cmd;

                auto start_time = std::chrono::steady_clock::now();
                while (true) {
                    auto end_time = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() > 5000) {
                        std::cout << timestamp() << "Microhard configuration timeout." << std::endl;
                        break;
                    }

                    int n = read(sock, buffer, sizeof(buffer));
                    if (n <= 0) {
                        std::this_thread::sleep_for(10ms);
                        continue;
                    }
                    buffer[n] = 0;
                    output += buffer;
                    logbuf += buffer;
#ifdef UNSECURE_DEBUG
                    size_t i = logbuf.find('\n');
                    while (i != std::string::npos) {
                        std::string s = logbuf.substr(0, i);
                        std::cout << timestamp() << "MH: " << s << std::endl;
                        logbuf = (i + 1 > logbuf.length()) ? "" : logbuf.substr(i + 1);
                        i = logbuf.find('\n');
                    }
#endif
                    if (state == 0 && output.find("login:") != std::string::npos) {
                        state = 1;
                        cmd = "admin\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                    } else if (state == 1 && output.find("Password:") != std::string::npos) {
                        state = 2;
                        cmd = config_pwd + "\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                    } else if (state == 2 && output.find("Entering") != std::string::npos) {
                        if (!encryption_key.empty()) {
                            cmd = "AT+MWVENCRYPT=1," + encryption_key + "\n";
                        } else {
                            cmd = "AT+MWVENCRYPT=0\n";
                        }
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        output = "";
                        state = 3;
                    } else if (state == 3 && _check_at_result(output)) {
                        cmd = "AT+MWTXPOWER=" + power + "\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        output = "";
                        state = 4;
                    } else if (state == 4 && _check_at_result(output)) {
                        cmd = "AT+MWFREQ=" + channel + "\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        output = "";
                        std::cout << timestamp() << "Set Microhard channel: " << channel << std::endl;
                        state = 5;
                    } else if (state == 5 && _check_at_result(output)) {
                        cmd = "AT+MWBAND=" + bandwidth + "\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        output = "";
                        std::cout << timestamp() << "Set Microhard bandwidth: " << bandwidth << std::endl;
                        state = 6;
                    } else if (state == 6 && _check_at_result(output)) {
                        cmd = "AT+MWNETWORKID=" + network_id + "\n";
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        output = "";
                        std::cout << timestamp() << "Set Microhard network Id: " << network_id << std::endl;
                        state = 7;
                    } else if (state == 7 && _check_at_result(output)) {
                        cmd = std::string("AT&W\n");
                        send(sock, cmd.c_str(), cmd.length(), 0);
                        std::this_thread::sleep_for(500ms);
#ifdef UNSECURE_DEBUG
                        std::cout << timestamp() << "Set Microhard encryption key: " << encryption_key << std::endl;
#else                      
                        std::cout << timestamp() << "Set Microhard encryption key." << std::endl;
#endif                    
                        done = true;
                        break;
                    }
                }
            }
            close(sock);
            retries--;
        }
    }
    if (!done) {
        std::cout << timestamp() << "Could not configure Microhard modem. Exiting ..." << std::endl;
        std::this_thread::sleep_for(3s);
        exit(-1);
    }
}

//-----------------------------------------------------------------------------
bool
PairingManager::_check_at_result(const std::string& output)
{
    return (output.find("OK") != std::string::npos || output.find("ERROR:") != std::string::npos);
}

//-----------------------------------------------------------------------------
void
PairingManager::_reconfigure_microhard()
{
    _configure_microhard(_pairing_val["AIP"].asString(), _pairing_val["CP"].asString(),
                         _pairing_val["EK"].asString(), pairing_network_id,
                         pairing_channel, _pairing_val["BW"].asString(),
                         default_transmit_power);
}

//-----------------------------------------------------------------------------
void
PairingManager::_create_pairing_json_for_zerotier(Json::Value& val)
{
    val["ZTID"] = zerotier_id;
    std::string zt = exec("zerotier-cli listnetworks");
    std::cout << timestamp() << "ZeroTier networks: "  << std::endl << zt << std::endl;
    // 200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>
    // 200 listnetworks 8286ac0e473776f2 trusting_wozniak f2:29:9c:07:20:2c OK PRIVATE ztrtazw6fv fcc5:b1da:fc5f:ab40:2e80:0000:0000:0001/40,10.144.48.71/16
    try {
        std::string ip = split(split(split(split(zt, '\n')[1], ' ')[8], ',')[1], '/')[0];
        val["IP"] = ip;
    } catch (...) {
        std::cout << timestamp() << "Could not get ZeroTier IP. Exiting ..." << std::endl;
        std::this_thread::sleep_for(3s);
        exit(-1);
    }
}

//-----------------------------------------------------------------------------
void
PairingManager::_create_pairing_json_for_microhard(Json::Value& val)
{
    for (auto i : scan_ifaces()) {
        if (i.find(ip_prefix.c_str()) != std::string::npos) {
            val["IP"] = i;
            break;
        }
    }

    val["AIP"] = air_unit_ip;
    val["CP"] = config_password;
    val["BW"] = default_pairing_bandwidth;
    val["PW"] = default_transmit_power;

    bool error = true;
    std::ifstream in(_get_json_gcs_filename());
    if (in) {
        std::stringstream ss;
        Json::Value val_;
        Json::CharReaderBuilder jsonReader;
        std::string errs;

        ss << _aes.decrypt(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()));
        if (Json::parseFromStream(jsonReader, ss, &val_, &errs)) {
            _rsa.generate_public(val_["DevPublicKey"].asString());
            _rsa.generate_private(val_["DevPrivateKey"].asString());
            _gcs_rsa.generate_public(val_["PublicKey"].asString());

            val["EK"] = val_["EK"];
            val["CC"] = val_["CC"];
            val["NID"] = val_["NID"];
            val["PW"] = val_["PW"];
            val["BW"] = val_["BW"];

            error = false;
        }
    }

    if (error) {
        val["EK"] = OpenSSL_Rand::random_string(random_aes_key_length);
        val["CC"] = pairing_channel;
        val["NID"] = pairing_network_id;
        val["PW"] = default_transmit_power;
    }

    _configure_microhard(val["AIP"].asString(), val["CP"].asString(), val["EK"].asString(),
                         val["NID"].asString(),
                         val["CC"].asString(), val["BW"].asString(), val["PW"].asString());
}

//-----------------------------------------------------------------------------
void
PairingManager::_create_pairing_json_for_taisync(Json::Value& val)
{
    std::string cmd = std::string("ifconfig ") + ethernet_device + " 192.168.0.2 up";
    exec(cmd.c_str());
}

//-----------------------------------------------------------------------------
std::string
PairingManager::get_pairing_json()
{
    if (!_pairing_json.empty()) {
        return _pairing_json;
    }

    _pairing_val["LT"] = link_type;
    _pairing_val["PP"] = pairing_port;
    if (link_type == "ZT") {
        _create_pairing_json_for_zerotier(_pairing_val);
    } else if (link_type == "MH") {
        _create_pairing_json_for_microhard(_pairing_val);
    } else if (link_type == "TS") {
        _create_pairing_json_for_taisync(_pairing_val);
    }
    Json::StreamWriterBuilder builder;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << Json::writeString(builder, _pairing_val) << std::endl;
#endif    

    builder["commentStyle"] = "None";
    builder["indentation"] = "";

    std::stringstream ss;
    ss << Json::writeString(builder, _pairing_val);
    _pairing_json = _aes.encrypt(ss.str());

    return _pairing_json;
}

//-----------------------------------------------------------------------------
void
PairingManager::_create_pairing_json()
{
    std::ofstream out(json_filename);
    if (!out) {
        std::cout << timestamp() << "Failed to open " << json_filename << " for writing" << std::endl;
        return;
    }
    out << get_pairing_json();
    if (out.bad()) {
        std::cout << timestamp() << "Failed to write to file " << json_filename << std::endl;
    }
    out.close();
}

//-----------------------------------------------------------------------------
bool
PairingManager::_create_gcs_pairing_json(const std::string& s, std::string& connect_key,
                                         std::string& channel, std::string& bandwidth, 
                                         std::string& network_id)
{
    std::stringstream ss1;
    ss1 << _aes.decrypt(s);

    Json::Value val;
    Json::CharReaderBuilder jsonReader;
    std::string errs;

    if (!Json::parseFromStream(jsonReader, ss1, &val, &errs)) {
        std::cout << timestamp() << "Failed to parse" << errs << std::endl;
        return false;
    }

    connect_key = val["EK"].asString();
    channel = val["CC"].asString();
    bandwidth = val["BW"].asString();
    network_id = val["NID"].asString();
    val["PW"] = default_transmit_power;

    _gcs_rsa.generate_public(val["PublicKey"].asString());
    _rsa.generate();
    val["DevPublicKey"] = _rsa.get_public_key();
    val["DevPrivateKey"] = _rsa.get_private_key();

    return _write_json_gcs_file(val);
}

//-------------------------------------------------------------------
void
PairingManager::_refresh_udp_endpoint()
{
    int fd = open(pipe_path, O_RDWR);
    if (fd < 0) {
        std::cout << timestamp() << "Failed to open pipe: " << pipe_path << std::endl;
        return;
    }

    if (!_ip.empty() && !_port.empty()) {
        std::cout << timestamp() << "Refreshing UDP endpoint " << _ip << ":" << _port << std::endl;
        // Start new UDP endpoint in mavlink router with specified IP
        // Op UDP Name IP Port Eavesdropping
        std::string msg = "add udp gcs " + _ip + " " + _port + " 0";
        write(fd, msg.c_str(), msg.length());
    }

    // Add local dynamic UDP endpoint for pairing manager connection
    std::string msg = "add udp pairing-manager 127.0.0.1 " + std::to_string(mavlink_udp_port) + " 0";
    write(fd, msg.c_str(), msg.length());
    close(fd);
}

//-------------------------------------------------------------------
void
PairingManager::_remove_endpoint(const std::string& name)
{
    int fd = open(pipe_path, O_RDWR);
    if (fd < 0) {
        return;
    }

    std::cout << timestamp() << "Removing UDP endpoint: " << name << std::endl;
    std::string msg = "remove " + name;
    write(fd, msg.c_str(), msg.length());

    close(fd);
}

//-------------------------------------------------------------------
void
PairingManager::_open_udp_endpoint(const std::string& ip, const std::string& port)
{
    std::lock_guard<std::mutex> guard(_udp_mutex);
    _ip = ip;
    _port = port;
    _refresh_udp_endpoint();
}

//-----------------------------------------------------------------------------
std::string
PairingManager::pair_gcs(const std::string& req_body)
{
    std::string connect_key;
    std::string channel;
    std::string bandwidth;
    std::string network_id;
    Json::Value val;
    val["CMD"] = "pair";
    val["NM"] = machine_name;

    if (_create_gcs_pairing_json(req_body, connect_key, channel, bandwidth, network_id) &&
         connect_key != "" && channel != "" && network_id != "") {
        std::cout << timestamp()
            << "Got connect key"
#ifdef UNSECURE_DEBUG
            << ": " << connect_key
#endif            
            << " and channel: " << channel
            << " and bandwidth: " << bandwidth
            << " and network id: " << network_id
            << std::endl;
        std::lock_guard<std::mutex> guard(_pairing_mutex);
        _pairing_mode = false;
        _configure_microhard(_pairing_val["AIP"].asString(), _pairing_val["CP"].asString(),
                              connect_key, network_id,
                              channel, bandwidth, default_transmit_power);
        val["CC"] = channel;
        val["NID"] = network_id;
        val["RES"] = "accepted";
        val["PublicKey"] = _rsa.get_public_key();
    } else {
        std::cout << timestamp() << "Did not get the connect key" << std::endl;
        val["RES"] = "rejected";
    }
    std::string message = _pack_response(val);

    return _aes.encrypt(message);
}

//-----------------------------------------------------------------------------
bool
PairingManager::_verify_request(const std::string& req_body, Json::Value& val)
{
    auto a = split(_rsa.decrypt(req_body), ';');
    if (a.size() < 2 || !_gcs_rsa.verify(a[0], a[1])) {
        return false;
    }
    std::stringstream ss;
    ss << a[0];

    Json::CharReaderBuilder jsonReader;
    std::string errs;

    if (!Json::parseFromStream(jsonReader, ss, &val, &errs)) {
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
std::string
PairingManager::_pack_response(Json::Value& response)
{
    Json::StreamWriterBuilder builder;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << "Response Json:" << std::endl;
    std::cout << timestamp() << Json::writeString(builder, response) << std::endl;
#endif
    builder["commentStyle"] = "None";
    builder["indentation"] = "";
    std::stringstream ss;
    ss << Json::writeString(builder, response);

    return ss.str();
}

//-----------------------------------------------------------------------------
std::string
PairingManager::unpair_gcs(const std::string& req_body)
{
    std::cout << timestamp() << "Got unpair request" << std::endl;

    Json::Value val;
    val["CMD"] = "unpair";
    val["NM"] = machine_name;
    if (_unpair_gcs(req_body)) {
        val["RES"] = "accepted";
    } else {
        val["RES"] = "rejected";
    }
    std::string message = _pack_response(val);

    return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool
PairingManager::_unpair_gcs(const std::string& req_body)
{
    Json::Value val;
    if (!_verify_request(req_body, val)) {
        std::cout << timestamp() << "Unpair request verification failed" << std::endl;
        return false;
    }
    std::cout << timestamp() << "Unpair request verification succeeded. " << std::endl;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << "Unpair Json:" << std::endl;
    Json::StreamWriterBuilder builder;
    std::cout << timestamp() << Json::writeString(builder, val) << std::endl;
#endif
    std::lock_guard<std::mutex> udp_guard(_udp_mutex);
    _ip = "";
    _port = "";
    _remove_endpoint("gcs");
    remove(_get_json_gcs_filename().c_str());

    std::lock_guard<std::mutex> pairing_guard(_pairing_mutex);
    if (!_pairing_mode) {
        _pairing_val["EK"] = OpenSSL_Rand::random_string(random_aes_key_length);
        _reconfigure_microhard();
    }

    return true;
}

//-----------------------------------------------------------------------------
std::string
PairingManager::connect_gcs(const std::string& req_body)
{
    std::cout << timestamp() << "Got connect request" << std::endl;

    Json::Value val;
    val["CMD"] = "connect";
    val["NM"] = machine_name;
    std::string channel;
    if (_connect_gcs(req_body, channel)) {
        val["RES"] = "accepted";
        val["CC"] = channel;
    } else {
        val["RES"] = "rejected";
    }
    std::string message = _pack_response(val);

    return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool
PairingManager::_connect_gcs(const std::string& req_body, std::string& channel)
{
    Json::Value val;
    if (!_verify_request(req_body, val)) {
        std::cout << timestamp() << "Connection request verification failed" << std::endl;
        return false;
    }
    std::cout << timestamp() << "Connection request verification succeeded. " << std::endl;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << "Connect Json:" << std::endl;
    Json::StreamWriterBuilder builder;
    std::cout << timestamp() << Json::writeString(builder, val) << std::endl;
#endif
    if (!_set_channel(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
        std::cout << timestamp() << "Set channel failed!" << std::endl;
        return false;
    }

    channel = val["CC"].asString();
    std::string ip = val["IP"].asString();
    std::string port = val["P"].asString();
    if (!ip.empty() && !port.empty()) {
        std::cout << timestamp() << "Creating UDP endpoint " << ip << ":" << port << std::endl;
        _open_udp_endpoint(ip, port);
    }

    return true;
}

//-----------------------------------------------------------------------------
std::string
PairingManager::disconnect_gcs(const std::string& req_body)
{
    std::cout << timestamp() << "Got disconnect request" << std::endl;

    Json::Value val;
    val["CMD"] = "disconnect";
    val["NM"] = machine_name;
    if (_disconnect_gcs(req_body)) {
        val["RES"] = "accepted";
    } else {
        val["RES"] = "rejected";
    }
    std::string message = _pack_response(val);

    return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool
PairingManager::_disconnect_gcs(const std::string& req_body)
{
    Json::Value val;
    if (!_verify_request(req_body, val)) {
        std::cout << timestamp() << "Disconnect request verification failed" << std::endl;
        return false;
    }
    std::cout << timestamp() << "Disconnect request verification succeeded. " << std::endl;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << "Disconnect Json:" << std::endl;
    Json::StreamWriterBuilder builder;
    std::cout << timestamp() << Json::writeString(builder, val) << std::endl;
#endif
    if (!_set_channel(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
        std::cout << timestamp() << "Set channel failed!" << std::endl;
        return false;
    }

    _remove_endpoint("gcs");

    return true;
}

//-----------------------------------------------------------------------------
std::string
PairingManager::set_channel(const std::string& req_body)
{
    std::cout << timestamp() << "Got set channel request: " << req_body << std::endl;

    Json::Value val;
    if (_set_channel(req_body, val)) {
        val["RES"] = "accepted";
    } else {
        val["RES"] = "rejected";
    }
    val["CMD"] = "channel";
    val["NM"] = machine_name;
    std::string message = _pack_response(val);

    return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool
PairingManager::_set_channel(const std::string& req_body, Json::Value& val)
{
    if (!_verify_request(req_body, val)) {
        std::cout << timestamp() << "Set channel request verification failed" << std::endl;
        return false;
    }
    std::cout << timestamp() << "Set channel verification succeeded. " << std::endl;
#ifdef UNSECURE_DEBUG
    std::cout << timestamp() << "Set channel Json:" << std::endl;
    Json::StreamWriterBuilder builder;
    std::cout << timestamp() << Json::writeString(builder, val) << std::endl;
#endif
    if (!_set_channel(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
        std::cout << timestamp() << "Set channel failed!" << std::endl;
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
bool
PairingManager::_set_channel(const std::string& new_network_id, const std::string& new_ch,
                             const std::string& power, const std::string& new_bandwidth)
{
    try {
        int ch = std::stoi(new_ch);
        if (ch < 1 || ch > 81) {
            return false;
        }
    } catch (...) {
        return false;
    }

    std::ifstream in(_get_json_gcs_filename());
    if (!in) {
        return false;
    }
    std::stringstream ss;
    ss << _aes.decrypt(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()));

    Json::Value val;
    Json::CharReaderBuilder jsonReader;
    std::string errs;

    if (!Json::parseFromStream(jsonReader, ss, &val, &errs)) {
        return false;
    }
    val["CC"] = new_ch;
    val["PW"] = power;
    val["NID"] = new_network_id;
    std::string connect_key = val["EK"].asString();

    if (!_write_json_gcs_file(val)) {
        return false;
    }

    std::thread([this, connect_key, new_network_id, new_ch, new_bandwidth, power]() {
        std::this_thread::sleep_for(100ms);
        std::cout << "Setting channel: " << new_ch << " Power: " << power << " Network ID: " << new_network_id << std::endl;
        _configure_microhard(_pairing_val["AIP"].asString(), _pairing_val["CP"].asString(),
                             connect_key, new_network_id, new_ch, new_bandwidth, power);
    }).detach();

    return true;
}

//-----------------------------------------------------------------------------
bool
PairingManager::_write_json_gcs_file(Json::Value& val)
{
    std::cout << timestamp() << "Write Json GCS file:" << std::endl;
    Json::StreamWriterBuilder builder;
#ifdef UNSECURE_DEBUG    
    std::cout << timestamp() << Json::writeString(builder, val) << std::endl;
#endif    
    builder["commentStyle"] = "None";
    builder["indentation"] = "";

    std::stringstream ss;
    ss << Json::writeString(builder, val);
    std::string modified_s = _aes.encrypt(ss.str());
    std::string json_gcs_filename = _get_json_gcs_filename();
    std::ofstream out(json_gcs_filename);
    if (!out) {
        std::cout << timestamp() << "Failed to open " << json_gcs_filename << " for writing" << std::endl;
        return false;
    }
    out << modified_s;

    bool res = true;
    if (out.bad()) {
        std::cout << timestamp() << "Failed to write to file " << json_gcs_filename << std::endl;
        res = false;
    }
    out.close();

    return res;
}

//-----------------------------------------------------------------------------
bool
PairingManager::handlePairingCommand()
{
    std::cout << timestamp() << "Got pairing command" << std::endl;
    bool result = false;
    _pairing_mutex.lock();
    auto now = std::chrono::steady_clock::now();

    if (!_pairing_mode ||
        std::chrono::duration_cast<std::chrono::milliseconds>(now - _last_pairing_time_stamp).count() > 3000) {

        _pairing_mode = true;
        _last_pairing_time_stamp = now;
        _pairing_mutex.unlock();
        if (_pairing_val["LT"] == "MH") {
            std::lock_guard<std::mutex> udp_guard(_udp_mutex);
            _ip = "";
            _port = "";
            _remove_endpoint("gcs");
            _configure_microhard(_pairing_val["AIP"].asString(),
                                 _pairing_val["CP"].asString(),
                                 pairing_encryption_key,
                                 pairing_network_id,
                                 pairing_channel,
                                 default_pairing_bandwidth,
                                 default_transmit_power);
            result = true;
        }
    } else {
        _pairing_mutex.unlock();
    }

    return result;
}

//-----------------------------------------------------------------------------
std::string
PairingManager::_get_json_gcs_filename()
{
    return persistent_folder + json_gcs_filename;
};

//-----------------------------------------------------------------------------

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
 * @file pairing_manager.cpp
 *
 * @author Matej Frančeškin (Matej@auterion.com)
 */

#include <cerrno>
#include <fstream>
#include <iostream>
#include <served/served.hpp>

#include "openssl_rand.h"
#include "pairing_manager.h"
#include "util.h"

using namespace std::chrono_literals;

const int random_aes_key_length = 8;
const int microhard_settings_port = 23;
const int max_num_of_devices = 10;
const int connect_mh_ip_start = 20;
const char* json_gcs_filename = "pairing.json";
const char* pipe_path = "/tmp/mavlink_router_pipe";
const std::string modem_netmask = "255.255.255.0";

//-----------------------------------------------------------------------------
PairingManager::PairingManager() : _aes() {
  _last_pairing_time_stamp = std::chrono::steady_clock::now();
  _fd = open(pipe_path, O_RDWR);
  if (_fd < 0) {
    std::string string_pipe_path(pipe_path);
    throw std::runtime_error("Failed to open pipe: " + string_pipe_path + " (" + strerror(errno) + ")");
  }
}

PairingManager::~PairingManager() { close(_fd); }

//-----------------------------------------------------------------------------
bool PairingManager::init() {
  if (access(persistent_folder.c_str(), 0) != 0) {
    std::cout << "Persistent directory " << persistent_folder << " does not exist. Using current working directory."
              << std::endl;
    persistent_folder = "./";
  }

  _aes.init(pairing_encryption_key);
  create_pairing_val();

  std::thread([this]() {
    while (true) {
      _udp_mutex.lock();
      refresh_udp_endpoint();
      _udp_mutex.unlock();
      std::unique_lock<std::mutex> lk(_quit_mutex);
      if (_quit_cv.wait_for(lk, 10s) != std::cv_status::timeout) {
        break;
      }
    }
  }).detach();

  std::thread([this]() {
    int retries = 0;
    while (true) {
      auto time_to_wait = 1s;
      bool status_result = get_microhard_modem_status();
      if (status_result || !_get_status_initialized) {
        if (status_result) {
          _get_status_initialized = true;
        }
        retries = 0;
        time_to_wait = 3s;
      } else {
        retries++;
      }
      if (retries > 5) {
        std::cout << timestamp() << "Could not get Microhard modem status. Exiting." << std::endl;
        quit();
        break;
      }
      std::unique_lock<std::mutex> lk(_quit_mutex);
      if (_quit_cv.wait_for(lk, time_to_wait) != std::cv_status::timeout) {
        break;
      }
    }
  }).detach();

  return true;
}

void PairingManager::quit() {
  _ip = "";
  _port = "";
  remove_endpoint("gcs");
  {
    std::unique_lock<std::mutex> lk(_quit_mutex);
    _quit_cv.notify_one();
  }
  exit(0);
}

void PairingManager::print_microhard_buffer_debug(std::string& logbuf) {
  size_t i = logbuf.find('\n');
  while (i != std::string::npos) {
    std::string s = logbuf.substr(0, i);
    std::cout << timestamp() << "MH: " << s << std::endl;
    logbuf = (i + 1 > logbuf.length()) ? "" : logbuf.substr(i + 1);
    i = logbuf.find('\n');
  }
}

void PairingManager::parse_buffer(std::string& cmd, ConfigMicrohardState& state, char* buffer, int n,
                                  const std::string& config_pwd, const std::string& modem_name,
                                  const std::string& new_modem_ip, const std::string& encryption_key,
                                  const std::string& network_id, const std::string& channel,
                                  const std::string& bandwidth, const std::string& power,
                                  bool check_name) {
  std::string logbuf;
  std::string output;
  buffer[n] = 0;
  output += buffer;
  logbuf += buffer;
  cmd = "";
#ifdef UNSECURE_DEBUG
  print_microhard_buffer_debug(logbuf);
#endif
  bool skip;

  do {
    skip = false;
    if (state == ConfigMicrohardState::LOGIN && output.find("login:") != std::string::npos) {
      state = ConfigMicrohardState::PASSWORD;
      cmd = "admin\n";
    } else if (state == ConfigMicrohardState::PASSWORD && output.find("Password:") != std::string::npos) {
      state = ConfigMicrohardState::SYSTEM_SUMMARY;
      cmd = config_pwd + "\n";
      output = "";
    } else if (state == ConfigMicrohardState::SYSTEM_SUMMARY && output.find("Entering") != std::string::npos) {
      state = ConfigMicrohardState::ENCRYPTION_TYPE;
      cmd = "AT+MSSYSI\n";
      output = "";
    } else if (state == ConfigMicrohardState::ENCRYPTION_TYPE && check_at_result(output)) {
      _system_summary = output;
      state = ConfigMicrohardState::CRYPTO_KEY;
      cmd = "AT+MWVENCRYPT\n";
      output = "";
    } else if (state == ConfigMicrohardState::CRYPTO_KEY && check_at_result_encryption_type(output, _encryption_type)) {
      if (!encryption_key.empty()) {
        cmd = "AT+MWVENCRYPT=" + _encryption_type + "," + encryption_key + "\n";
      } else {
        cmd = "AT+MWVENCRYPT=0\n";
      }
      output = "";
      state = ConfigMicrohardState::MODEM_NAME;
    } else if (state == ConfigMicrohardState::MODEM_NAME && check_at_result(output)) {
      if (!modem_name.empty()) {
        if (check_name) {
          cmd = "AT+MSMNAME\n";
          std::cout << timestamp() << "Checking Microhard name: " << modem_name << std::endl;
          state = ConfigMicrohardState::MODEM_CHECK_NAME;
        } else {
          cmd = "AT+MSMNAME=" + modem_name + "\n";
          std::cout << timestamp() << "Set Microhard name: " << modem_name << std::endl;
          state = ConfigMicrohardState::MODEM_IP;
        }
        output = "";
      } else {
        skip = true;
        state = ConfigMicrohardState::MODEM_IP;
      }
    } else if (state == ConfigMicrohardState::MODEM_CHECK_NAME && check_at_result_modem_name(output, modem_name)) {
      skip = true;
      state = ConfigMicrohardState::MODEM_IP;
    } else if (state == ConfigMicrohardState::MODEM_IP && check_at_result(output)) {
      if (!new_modem_ip.empty()) {
        // cmd = "AT+MNLAN=lan,EDIT,0," + new_modem_ip + "," + modem_netmask + "\n";
        // output = "";
        // std::cout << timestamp() << "Set Microhard IP: " << new_modem_ip << std::endl;
        skip = true;
      } else {
        skip = true;
      }
      state = ConfigMicrohardState::POWER;
    } else if (state == ConfigMicrohardState::POWER && check_at_result(output)) {
      cmd = "AT+MWTXPOWER=" + power + "\n";
      output = "";
      state = ConfigMicrohardState::DISTANCE;
    } else if (state == ConfigMicrohardState::DISTANCE && check_at_result(output)) {
      if(std::stoi(power) == 30)
        cmd = "AT+MWDISTANCE=4000\n";
      else if (std::stoi(power) >= 20)
        cmd = "AT+MWDISTANCE=1000\n";
      else
        cmd = "AT+MWDISTANCE=500\n";
      output = "";
      if (_system_summary.find("DDL1800") != std::string::npos) {
        state = ConfigMicrohardState::DEFAULT_FREQUENCY;
      } else {
        state = ConfigMicrohardState::BANDWIDTH;
      }
    } else if (state == ConfigMicrohardState::DEFAULT_FREQUENCY && check_at_result(output)) {
      cmd = "AT+MWFREQ=15\n";
      output = "";
      state = ConfigMicrohardState::BANDWIDTH;
    } else if (state == ConfigMicrohardState::BANDWIDTH && check_at_result(output)) {
      std::string mh_model_bandwidth = bandwidth;
      if (mh_model_bandwidth == "") {
        if (_system_summary.find("DDL1800") != std::string::npos) {
          mh_model_bandwidth = "3";
        } else {
          mh_model_bandwidth = "1";
        }
      }
      cmd = "AT+MWBAND=" + mh_model_bandwidth + "\n";
      output = "";
      std::cout << timestamp() << "Set Microhard bandwidth: " << mh_model_bandwidth << std::endl;
      state = ConfigMicrohardState::FREQUENCY;
    } else if (state == ConfigMicrohardState::FREQUENCY && check_at_result(output)) {
      if (_system_summary.find("DDL1800") != std::string::npos) {
        cmd = "AT+MWFREQ=" + channel + "\n";
      } else {
        cmd = "AT+MWFREQ2400=" + channel + "\n";
      }
      output = "";
      std::cout << timestamp() << "Set Microhard channel: " << channel << std::endl;
      state = ConfigMicrohardState::NETWORK_ID;
    } else if (state == ConfigMicrohardState::NETWORK_ID && check_at_result(output)) {
      cmd = "AT+MWNETWORKID=" + network_id + "\n";
      output = "";
      std::cout << timestamp() << "Set Microhard network Id: " << network_id << std::endl;
      state = ConfigMicrohardState::SAVE;
    } else if (state == ConfigMicrohardState::SAVE && check_at_result(output)) {
      std::cout << timestamp() << "Saving configuration: AT&W" << std::endl;
      cmd = std::string("AT&W\n");
      state = ConfigMicrohardState::WRITE_FLASH;
    } else if (state == ConfigMicrohardState::WRITE_FLASH && check_at_result(output)) {
      skip = true;
      state = ConfigMicrohardState::DONE;
    }
  } while (skip);
}

bool PairingManager::is_socket_connected(const int& sock, const std::string& air_ip) {
  fcntl(sock, F_SETFL, O_NONBLOCK);
  struct sockaddr_in serv_addr;
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(microhard_settings_port);
  if (inet_pton(AF_INET, air_ip.c_str(), &serv_addr.sin_addr) > 0) {
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 3; /* 3 second timeout */
    tv.tv_usec = 0;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
      int so_error;
      socklen_t len = sizeof so_error;
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
      if (so_error == 0) {
        return true;
      }
    }
  }
  return false;
}

void PairingManager::configure_microhard_network_interface(const std::string& ip) {
  std::string current_ip = "";
  for (auto i : scan_ifaces()) {
    if (i.find(ip_prefix) != std::string::npos) {
      current_ip = i;
      break;
    }
  }

  while (current_ip != ip) {
    std::cout << timestamp() << "Configure microhard network interface " << ethernet_device << " " << current_ip << std::endl;
    std::string cmd = "ifconfig " + ethernet_device + " down";
    std::cout << cmd << std::endl;
    exec(cmd.c_str());
    std::this_thread::sleep_for(1000ms);
    cmd = "ifconfig " + ethernet_device + " " + ip + " up";
    std::cout << cmd << std::endl;
    exec(cmd.c_str());

    for (auto i : scan_ifaces()) {
      if (i.find(ip) != std::string::npos) {
        current_ip = i;
        break;
      }
    }
  }
  _pairing_val["CCIP"] = ip;
}

bool PairingManager::configure_microhard_now(
  const std::string& air_ip, const std::string& config_pwd,
  const std::string& modem_name,
  const std::string& new_mh_ip, const std::string& encryption_key,
  const std::string& network_id, const std::string& channel,
  const std::string& bandwidth, const std::string& power,
  bool check_name) {

  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;

  if (config_pwd == "") {
    std::cout << timestamp() << "Microhard config password not set." << std::endl;
    return false;
  }

  bool timeout = false;
  while (!timeout && state != ConfigMicrohardState::DONE) {
    std::cout << timestamp() << "Configure microhard " << air_ip << std::endl;

    state = ConfigMicrohardState::LOGIN;
    ConfigMicrohardState state_prev = state;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
      if (!is_socket_connected(sock, air_ip)) {
        close(sock);
        break;
      }
      char buffer[1024];
      std::string cmd;

      auto start_time = std::chrono::steady_clock::now();
      while (true) {
        auto end_time = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() > 5000) {
          std::cout << timestamp() << "Microhard configuration timeout." << std::endl;
          timeout = true;
          break;
        }

        int n = read(sock, buffer, sizeof(buffer));
        if (n <= 0) {
          std::this_thread::sleep_for(10ms);
          continue;
        }

        start_time = std::chrono::steady_clock::now();
        parse_buffer(cmd, state, buffer, n, config_pwd, modem_name, new_mh_ip, encryption_key, network_id, channel, bandwidth, power, check_name);

        if (state_prev != state && !cmd.empty()) {
          send(sock, cmd.c_str(), cmd.length(), 0);
        }

        state_prev = state;

        if (state == ConfigMicrohardState::DONE) {
          break;
        }
        if (!new_mh_ip.empty() && state == ConfigMicrohardState::WRITE_FLASH) {
          std::this_thread::sleep_for(1000ms);
          state = ConfigMicrohardState::DONE;
          break;
        }
      }
      close(sock);
    }
  }
  if (state != ConfigMicrohardState::DONE) {
    std::cout << timestamp() << "Could not configure Microhard modem." << std::endl;
    return false;
  }

  if (!new_mh_ip.empty()) {
    _pairing_val["MHIP"] = new_mh_ip;
  }

  _get_status_initialized = false;

  return true;
}

//-----------------------------------------------------------------------------
void PairingManager::configure_microhard(const std::string& air_ip, const std::string& config_pwd,
                                         const std::string& modem_name, const std::string& new_cc_ip,
                                         const std::string& new_mh_ip, const std::string& encryption_key,
                                         const std::string& network_id, const std::string& channel,
                                         const std::string& bandwidth, const std::string& power) {
  std::lock_guard<std::mutex> guard(_mh_mutex);
  std::vector<std::string> trial_list;

  // If network interface was not configured at all then we configure it 
  // before we start scanning for Microhard modem
  bool found = false;
  for (auto i : scan_ifaces()) {
    if (i.find(ip_prefix) != std::string::npos) {
      found = true;
      break;
    }
  }
  if (!found) {
    configure_microhard_network_interface(!new_cc_ip.empty() ? new_cc_ip : pairing_cc_ip);
  }

  for (int i = 0; i < max_num_of_devices; i++) {
    std::string trial_ip = ip_prefix + "." + std::to_string(i + connect_mh_ip_start);
    if (trial_ip != air_ip) {
      trial_list.push_back(air_ip);
      if (air_ip != air_unit_ip) {
        trial_list.push_back(air_unit_ip);
      }
      trial_list.push_back(trial_ip);
    }
  }

  for (auto i = trial_list.begin(); i != trial_list.end(); i++) {
    if (can_ping(*i, 1)) {
      std::cout << timestamp() << "Got ping response from " << *i << std::endl;
      if (configure_microhard_now(*i, config_pwd, modem_name, new_mh_ip, encryption_key, network_id, channel, bandwidth, power, *i != air_unit_ip)) {
        if (!new_cc_ip.empty()) {
          configure_microhard_network_interface(new_cc_ip);
        }
        return;
      }
    } else {
      std::cout << timestamp() << "Could not ping " << *i << std::endl;
    }
  }

  std::cout << timestamp() << "Could not configure Microhard modem. Exiting." << std::endl;
  std::this_thread::sleep_for(3s);
  quit();
}

//-----------------------------------------------------------------------------
bool PairingManager::check_at_result(const std::string& output) {
  return (output.find("OK") != std::string::npos || output.find("ERROR:") != std::string::npos);
}

//-----------------------------------------------------------------------------
bool PairingManager::check_at_result_modem_name(const std::string& output, const std::string& name) {
  return (output.find("OK") != std::string::npos && output.find("Host name:" + name) != std::string::npos);
}

//-----------------------------------------------------------------------------
bool PairingManager::check_at_result_encryption_type(const std::string& output, std::string& type) {
  const std::string key = "Encryption Type: ";
  std::size_t i = output.find(key);
  bool res = output.find("OK") != std::string::npos;
  if (res && i != std::string::npos) {
    type = output.substr(i + key.length(), 1);
  }

  return res;
}

//-----------------------------------------------------------------------------
void PairingManager::reconfigure_microhard() {
  configure_microhard(_pairing_val["MHIP"].asString(), _pairing_val["CP"].asString(),
                      machine_name, pairing_cc_ip, air_unit_ip,
                      _pairing_val["EK"].asString(), pairing_network_id,
                      pairing_channel, _pairing_val["BW"].asString(), default_transmit_power);
}

//-----------------------------------------------------------------------------
void PairingManager::create_pairing_val_for_zerotier(Json::Value& val) {
  val["ZTID"] = zerotier_id;
  std::string zt = exec("zerotier-cli listnetworks");
  std::cout << timestamp() << "ZeroTier networks: " << std::endl << zt << std::endl;
  // 200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>
  // 200 listnetworks 8286ac0e473776f2 trusting_wozniak f2:29:9c:07:20:2c OK PRIVATE ztrtazw6fv
  // fcc5:b1da:fc5f:ab40:2e80:0000:0000:0001/40,10.144.48.71/16
  try {
    std::string ip = split(split(split(split(zt, '\n')[1], ' ')[8], ',')[1], '/')[0];
    val["IP"] = ip;
  } catch (...) {
    std::cout << timestamp() << "Could not get ZeroTier IP. Exiting ..." << std::endl;
    std::this_thread::sleep_for(3s);
    quit();
  }
}

//-----------------------------------------------------------------------------
void PairingManager::create_pairing_val_for_microhard(Json::Value& val) {
  for (auto i : scan_ifaces()) {
    if (i.find(ip_prefix) != std::string::npos) {
      val["IP"] = i;
      break;
    }
  }

  val["CP"] = config_password;
  val["BW"] = pairing_bandwidth;
  val["PW"] = default_transmit_power;
  val["CCIP"] = pairing_cc_ip;
  val["MHIP"] = air_unit_ip;

  bool error = true;
  std::ifstream in(get_json_gcs_filename());
  if (in) {
    Json::Value val_from_json_gcs;
    bool success = decrypt_string_to_json(
        std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), val_from_json_gcs);
    if (success) {
      _rsa.generate_public(val_from_json_gcs["DevPublicKey"].asString());
      _rsa.generate_private(val_from_json_gcs["DevPrivateKey"].asString());
      _gcs_rsa.generate_public(val_from_json_gcs["PublicKey"].asString());

      auto v = val_from_json_gcs["CCIP"].asString();
      if (!v.empty()) {
        val["CCIP"] = v;
      }
      v = val_from_json_gcs["MHIP"].asString();
      if (!v.empty()) {
        val["MHIP"] = v;
      }
      v = val_from_json_gcs["BW"].asString();
      if (!v.empty()) {
        val["BW"] = v;
      }
      val["EK"] = val_from_json_gcs["EK"];
      val["CC"] = val_from_json_gcs["CC"];
      val["NID"] = val_from_json_gcs["NID"];
      val["PW"] = val_from_json_gcs["PW"];

      error = false;
    }
  }

  if (error) {
    // always default to the pairing encryption key so the drone is ready to go.
    //val["EK"] = OpenSSL_Rand::random_string(random_aes_key_length);
    val["EK"] = pairing_encryption_key;
    val["CC"] = pairing_channel;
    val["NID"] = pairing_network_id;
    val["PW"] = default_transmit_power;
  }

  configure_microhard(val["MHIP"].asString(), val["CP"].asString(),
                      machine_name, val["CCIP"].asString(), "",
                      val["EK"].asString(), val["NID"].asString(),
                      val["CC"].asString(), val["BW"].asString(), val["PW"].asString());
}

//-----------------------------------------------------------------------------
void PairingManager::create_pairing_val_for_taisync(Json::Value& val) {
  std::string cmd = std::string("ifconfig ") + ethernet_device + " 192.168.0.2 up";
  exec(cmd.c_str());
}

//-----------------------------------------------------------------------------
void PairingManager::create_pairing_val() {
  _pairing_val["LT"] = link_type;
  _pairing_val["PP"] = pairing_port;
  if (link_type == "ZT") {
    create_pairing_val_for_zerotier(_pairing_val);
  } else if (link_type == "MH") {
    create_pairing_val_for_microhard(_pairing_val);
  } else if (link_type == "TS") {
    create_pairing_val_for_taisync(_pairing_val);
  }

  print_json("", _pairing_val);
}

//-----------------------------------------------------------------------------
bool PairingManager::create_gcs_pairing_json(const std::string& s,
                                             std::string& cc_ip, std::string& mh_ip,
                                             std::string& connect_key, std::string& channel,
                                             std::string& bandwidth, std::string& network_id) {
  Json::Value val;
  bool success = decrypt_string_to_json(s, val);
  if (!success) {
    return false;
  }

  cc_ip = val["CCIP"].asString();
  mh_ip = val["MHIP"].asString();
  connect_key = val["EK"].asString();
  channel = val["CC"].asString();
  bandwidth = val["BW"].asString();
  network_id = val["NID"].asString();
  val["PW"] = default_transmit_power;

  _gcs_rsa.generate_public(val["PublicKey"].asString());
  _rsa.generate();
  val["DevPublicKey"] = _rsa.get_public_key();
  val["DevPrivateKey"] = _rsa.get_private_key();

  return write_json_gcs_file(get_json_gcs_filename(), val);
}

bool PairingManager::decrypt_string_to_json(const std::string& in, Json::Value& out) {
  std::stringstream ss(_aes.decrypt(in));
  Json::CharReaderBuilder jsonReader;
  std::string error;

  if (!Json::parseFromStream(jsonReader, ss, &out, &error)) {
    std::cout << timestamp() << "Failed to parse" << error << std::endl;
    return false;
  }

  return true;
}

//-------------------------------------------------------------------
void PairingManager::refresh_udp_endpoint() {
  if (!_ip.empty() && !_port.empty()) {
    std::cout << timestamp() << "Refreshing UDP endpoint " << _ip << ":" << _port << std::endl;
    // Start new UDP endpoint in mavlink router with specified IP
    // On UDP Name IP Port Eavesdropping
    std::string msg = "add udp gcs " + _ip + " " + _port + " 0";
    write_to_mavlink_router_pipe(msg);
  }
  // Add local dynamic UDP endpoint for pairing manager connection
  std::string msg = "add udp pairing-manager 127.0.0.1 " + std::to_string(mavlink_udp_port) + " 0";
  write_to_mavlink_router_pipe(msg);
}

//-------------------------------------------------------------------
void PairingManager::remove_endpoint(const std::string& name) {
  std::cout << timestamp() << "Removing UDP endpoint: " << name << std::endl;
  std::string msg = "remove " + name;
  write_to_mavlink_router_pipe(msg);
}

void PairingManager::write_to_mavlink_router_pipe(const std::string& msg) {
  // Add end of line to ensure proper command parsing on the mavlink-router side
  std::string msg_with_end_of_line = msg + "\n";
  write(_fd, msg_with_end_of_line.c_str(), msg_with_end_of_line.length());
}

//-------------------------------------------------------------------
void PairingManager::open_udp_endpoint(const std::string& ip, const std::string& port) {
  std::lock_guard<std::mutex> guard(_udp_mutex);
  _ip = ip;
  _port = port;
  refresh_udp_endpoint();
}

//-----------------------------------------------------------------------------
std::string PairingManager::pair_gcs_request(const std::string& req_body) {
  std::string cc_ip;
  std::string mh_ip;
  std::string connect_key;
  std::string channel;
  std::string bandwidth;
  std::string network_id;
  Json::Value val;
  val["CMD"] = "pair";
  val["NM"] = machine_name;

  std::lock_guard<std::mutex> guard(_operation_mutex);
  if (_pairing_mode &&
      create_gcs_pairing_json(req_body, cc_ip, mh_ip, connect_key, channel, bandwidth, network_id) &&
      cc_ip != "" && mh_ip != "" && connect_key != "" && channel != "" && network_id != "") {
    std::cout << timestamp() << "Got CC IP: " << cc_ip << ", MH IP: " << mh_ip << ", connect key"
#ifdef UNSECURE_DEBUG
              << ": " << connect_key
#endif
              << ", channel: " << channel << ", bandwidth: " << bandwidth << ", network id: " << network_id
              << std::endl;
    _pairing_mode = false;

    // Change modem parameters after the response was sent
    std::thread([this, cc_ip, mh_ip, connect_key, network_id, channel, bandwidth]() {
      std::this_thread::sleep_for(1000ms);
      configure_microhard(air_unit_ip, _pairing_val["CP"].asString(),
                          machine_name, cc_ip, mh_ip,
                          connect_key, network_id, channel,
                          bandwidth, default_transmit_power);
    }).detach();
    val["IP"] = cc_ip;
    val["CC"] = channel;
    val["NID"] = network_id;
    val["RES"] = "accepted";
    val["PublicKey"] = _rsa.get_public_key();
  } else {
    std::cout << timestamp() << "Pairing command from GCS rejected" << std::endl;
    val["RES"] = "rejected";
  }
  std::string message = pack_response(val);

  return _aes.encrypt(message);
}

//-----------------------------------------------------------------------------
bool PairingManager::verify_request(const std::string& req_body, Json::Value& val) {
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
std::string PairingManager::pack_response(Json::Value& response) {
  print_json("Response Json:", response);

  return from_json_to_string(response);
}

//-----------------------------------------------------------------------------
std::string PairingManager::unpair_gcs_request(const std::string& req_body) {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got unpair request" << std::endl;

  Json::Value val;
  val["CMD"] = "unpair";
  val["NM"] = machine_name;
  if (unpair_gcs(req_body)) {
    val["RES"] = "accepted";
  } else {
    val["RES"] = "rejected";
  }
  std::string message = pack_response(val);

  return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool PairingManager::unpair_gcs(const std::string& req_body) {
  Json::Value val;
  if (!verify_request(req_body, val)) {
    std::cout << timestamp() << "Unpair request verification failed" << std::endl;
    return false;
  }
  std::cout << timestamp() << "Unpair request verification succeeded. " << std::endl;
  print_json("Unpair Json:", val);

  std::lock_guard<std::mutex> udp_guard(_udp_mutex);
  _ip = "";
  _port = "";
  remove_endpoint("gcs");
  remove(get_json_gcs_filename().c_str());

  if (!_pairing_mode) {
    // always default to the pairing encryption_key so the drone is ready to go.
    //_pairing_val["EK"] = OpenSSL_Rand::random_string(random_aes_key_length);
    _pairing_val["EK"] = pairing_encryption_key;
    // Change modem parameters after the response was sent
    std::thread([this]() {
      std::this_thread::sleep_for(1000ms);
      reconfigure_microhard();
    }).detach();
  }

  return true;
}

//-----------------------------------------------------------------------------
std::string PairingManager::connect_gcs_request(const std::string& req_body) {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got connect request" << std::endl;

  Json::Value val;
  val["CMD"] = "connect";
  val["NM"] = machine_name;
  std::string channel;
  if (connect_gcs(req_body, channel)) {
    val["RES"] = "accepted";
    val["CC"] = channel;
  } else {
    val["RES"] = "rejected";
  }
  std::string message = pack_response(val);

  return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool PairingManager::connect_gcs(const std::string& req_body, std::string& channel) {
  Json::Value val;
  if (!verify_request(req_body, val)) {
    std::cout << timestamp() << "Connection request verification failed" << std::endl;
    return false;
  }
  std::cout << timestamp() << "Connection request verification succeeded. " << std::endl;
  print_json("Connect Json:", val);

  if (!set_modem_parameters(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
    std::cout << timestamp() << "Set channel failed!" << std::endl;
    return false;
  }

  channel = val["CC"].asString();
  std::string ip = val["IP"].asString();
  std::string port = val["P"].asString();
  if (!ip.empty() && !port.empty()) {
    std::cout << timestamp() << "Creating UDP endpoint " << ip << ":" << port << std::endl;
    open_udp_endpoint(ip, port);
  }

  return true;
}

//-----------------------------------------------------------------------------
std::string PairingManager::disconnect_gcs_request(const std::string& req_body) {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got disconnect request" << std::endl;

  Json::Value val;
  val["CMD"] = "disconnect";
  val["NM"] = machine_name;
  if (disconnect_gcs(req_body)) {
    val["RES"] = "accepted";
  } else {
    val["RES"] = "rejected";
  }
  std::string message = pack_response(val);

  return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool PairingManager::disconnect_gcs(const std::string& req_body) {
  Json::Value val;
  if (!verify_request(req_body, val)) {
    std::cout << timestamp() << "Disconnect request verification failed" << std::endl;
    return false;
  }
  std::cout << timestamp() << "Disconnect request verification succeeded. " << std::endl;
  print_json("Disconnect Json:", val);

  if (!set_modem_parameters(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
    std::cout << timestamp() << "Set channel failed!" << std::endl;
    return false;
  }

  remove_endpoint("gcs");

  return true;
}

//-----------------------------------------------------------------------------
std::string PairingManager::status_request() {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got status request." << std::endl;
  stop_modem_config_timeout();

  Json::Value res_val;
  res_val["CMD"] = "status";
  res_val["NM"] = machine_name;
  std::ifstream in(get_json_gcs_filename());
  if (in) {
    Json::Value val;
    if (decrypt_string_to_json(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), val)) {
      res_val["RES"] = "accepted";
      res_val["NID"] = val["NID"];
      res_val["CC"] = val["CC"];
      res_val["PW"] = val["PW"];
      res_val["BW"] = val["BW"];
    }
  } else {
    res_val["RES"] = "rejected";
  }

  std::string message = pack_response(res_val);
  return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
std::string PairingManager::set_modem_parameters_request(const std::string& req_body) {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got set modem parameters request: " << req_body << std::endl;

  Json::Value val;
  if (set_modem_parameters(req_body, val)) {
    val["RES"] = "accepted";
  } else {
    val["RES"] = "rejected";
  }
  val["CMD"] = "modemparameters";
  val["NM"] = machine_name;
  std::string message = pack_response(val);

  return _gcs_rsa.encrypt(message + ";" + _rsa.sign(message));
}

//-----------------------------------------------------------------------------
bool PairingManager::set_modem_parameters(const std::string& req_body, Json::Value& val) {
  if (!verify_request(req_body, val)) {
    std::cout << timestamp() << "Set modem parameters request verification failed" << std::endl;
    return false;
  }
  std::cout << timestamp() << "Set modem parameters verification succeeded. " << std::endl;
  print_json("Set modem parameters Json:", val);

  bool res = true;
  if (!set_modem_parameters(val["NID"].asString(), val["CC"].asString(), val["PW"].asString(), val["BW"].asString())) {
    std::cout << timestamp() << "Set modem parameters failed!" << std::endl;
    res = false;
  }
  start_modem_config_timeout();

  return res;
}

//-----------------------------------------------------------------------------
void PairingManager::print_json(const std::string& msg, const Json::Value& val) {
#ifdef UNSECURE_DEBUG
  Json::Value outval(val);
  outval.removeMember("PublicKey");
  outval.removeMember("DevPublicKey");
  outval.removeMember("DevPrivateKey");
  Json::StreamWriterBuilder builder;
  std::cout << timestamp() << msg << Json::writeString(builder, outval) << std::endl;
#endif
}

//-----------------------------------------------------------------------------
std::string PairingManager::from_json_to_string(const Json::Value& val) {
  Json::StreamWriterBuilder builder;
  builder["commentStyle"] = "None";
  builder["indentation"] = "";

  std::stringstream string_stream(Json::writeString(builder, val));
  return string_stream.str();
}

//-----------------------------------------------------------------------------
bool PairingManager::set_modem_parameters(const std::string& new_network_id, const std::string& new_ch,
                                          const std::string& power, const std::string& new_bandwidth) {
  try {
    int ch = std::stoi(new_ch);
    if (ch < 1 || ch > 81) {
      return false;
    }
  } catch (...) {
    return false;
  }

  std::ifstream in(get_json_gcs_filename());
  if (!in) {
    return false;
  }

  Json::Value val;
  bool success =
      decrypt_string_to_json(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), val);
  if (!success) {
    return false;
  }

  if (!write_json_gcs_file(get_prev_json_gcs_filename(), val, false)) {
    return false;
  }

  val["CC"] = new_ch;
  val["PW"] = power;
  val["NID"] = new_network_id;
  val["BW"] = new_bandwidth;
  std::string connect_key = val["EK"].asString();
  std::string mhip = val["MHIP"].asString();

  if (!write_json_gcs_file(get_json_gcs_filename(), val)) {
    return false;
  }

  std::cout << timestamp() << "Setting channel: " << new_ch << " Power: " << power << " Network ID: " << new_network_id << std::endl;
  configure_microhard(_pairing_val["MHIP"].asString(), _pairing_val["CP"].asString(),
                      machine_name, "", "",
                      connect_key, new_network_id,
                      new_ch, new_bandwidth, power);

  return true;
}

//-----------------------------------------------------------------------------
void PairingManager::start_modem_config_timeout() {
  std::thread([&]() {
    std::unique_lock<std::mutex> l(_config_timeout_mutex);
    _config_timeout_running = true;
    if (_config_timeout_cv.wait_for(l, 60s) == std::cv_status::timeout) {
      _config_timeout_running = false;
      std::cout << timestamp() << "Connection was not established. Reverting modem settings to previous state." << std::endl;
      // revert modem settings
      std::ifstream in(get_prev_json_gcs_filename());
      if (in) {
        Json::Value val;
        bool success =
          decrypt_string_to_json(std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()), val);
        if (success) {
          configure_microhard(_pairing_val["MHIP"].asString(), _pairing_val["CP"].asString(),
                              machine_name, "", "",
                              val["EK"].asString(), val["NID"].asString(),
                              val["CC"].asString(), val["BW"].asString(), val["PW"].asString());
        }
      }
    }
  }).detach();
}

//-----------------------------------------------------------------------------
void PairingManager::stop_modem_config_timeout() {
  if (_config_timeout_running) {
    _config_timeout_running = false;
    _config_timeout_cv.notify_one();
  }
}

//-----------------------------------------------------------------------------
bool PairingManager::write_json_gcs_file(std::string filename, Json::Value& val, bool print) {
  if (print) {
    print_json("Write Json GCS file " + filename + ":", val);
  }

  std::string s = from_json_to_string(val);
  std::string modified_s = _aes.encrypt(s);
  std::string json_gcs_filename = get_json_gcs_filename();
  std::ofstream out(filename);
  if (!out) {
    std::cout << timestamp() << "Failed to open " << filename << " for writing" << std::endl;
    return false;
  }
  out << modified_s;

  bool res = true;
  if (out.bad()) {
    std::cout << timestamp() << "Failed to write to file " << filename << std::endl;
    res = false;
  }
  out.flush();
  out.close();

  sync();
  
  return res;
}

//-----------------------------------------------------------------------------
bool PairingManager::handle_pairing_command() {
  std::lock_guard<std::mutex> guard(_operation_mutex);
  std::cout << timestamp() << "Got pairing command" << std::endl;
  bool result = false;
  auto now = std::chrono::steady_clock::now();

  if (!_pairing_mode ||
      std::chrono::duration_cast<std::chrono::milliseconds>(now - _last_pairing_time_stamp).count() > 5000) {
    _pairing_mode = true;
    _last_pairing_time_stamp = now;
    if (_pairing_val["LT"] == "MH") {
      std::lock_guard<std::mutex> udp_guard(_udp_mutex);
      _ip = "";
      _port = "";
      remove_endpoint("gcs");
      std::thread([this]() {
          configure_microhard(_pairing_val["MHIP"].asString(), _pairing_val["CP"].asString(),
                              machine_name, pairing_cc_ip, air_unit_ip,
                              pairing_encryption_key, pairing_network_id,
                              pairing_channel, pairing_bandwidth, default_transmit_power);
      }).detach();
      result = true;
    }
  }

  return result;
}

//-----------------------------------------------------------------------------
std::string PairingManager::get_json_gcs_filename() { 
  return persistent_folder + json_gcs_filename;
};

//-----------------------------------------------------------------------------
std::string PairingManager::get_prev_json_gcs_filename() { 
  return persistent_folder + json_gcs_filename + ".prev";
};

//-----------------------------------------------------------------------------
bool PairingManager::get_microhard_modem_status()
{
  std::lock_guard<std::mutex> guard(_mh_mutex);

  std::string modem_ip = _pairing_val["MHIP"].asString();
  if (!can_ping(modem_ip, 1)) {
    return false;
  }

  ConfigMicrohardState state = ConfigMicrohardState::LOGIN;

  bool timeout = false;
  while (!timeout && state != ConfigMicrohardState::DONE) {
    state = ConfigMicrohardState::LOGIN;
    ConfigMicrohardState state_prev = state;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
      if (!is_socket_connected(sock, modem_ip)) {
        close(sock);
        break;
      }

      char buffer[1024];
      std::string cmd;

      auto start_time = std::chrono::steady_clock::now();
      while (true) {
        auto end_time = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() > 6000) {
          timeout = true;
          break;
        }

        int n = read(sock, buffer, sizeof(buffer));
        if (n <= 0) {
          std::this_thread::sleep_for(10ms);
          continue;
        }

        start_time = std::chrono::steady_clock::now();

        std::string logbuf;
        std::string output;
        buffer[n] = 0;
        output += buffer;
        logbuf += buffer;
        cmd = "";
        if (state == ConfigMicrohardState::LOGIN && output.find("login:") != std::string::npos) {
          state = ConfigMicrohardState::PASSWORD;
          cmd = "admin\n";
        } else if (state == ConfigMicrohardState::PASSWORD && output.find("Password:") != std::string::npos) {
          state = ConfigMicrohardState::GET_STATUS;
          cmd = config_password + "\n";
        } else if (state == ConfigMicrohardState::GET_STATUS && output.find("Entering") != std::string::npos) {
          cmd = "AT+MWSTATUS\n";
          output = "";
          state = ConfigMicrohardState::READ_STATUS;
        } else if (state == ConfigMicrohardState::READ_STATUS && check_at_result(output)) {
          state = ConfigMicrohardState::DONE;
          parse_microhard_modem_status(output);
          break;
        }

        if (state_prev != state && !cmd.empty()) {
          send(sock, cmd.c_str(), cmd.length(), 0);
        }

        state_prev = state;
      }
      close(sock);
    }
  }

  return (state == ConfigMicrohardState::DONE);
}

//-----------------------------------------------------------------------------
void PairingManager::set_RSSI_report_callback(std::function<void(int)> report_callback) {
  _rssi_report_callback = std::move(report_callback);
}

//-----------------------------------------------------------------------------
/*
General Status
  MAC Address        : 00:0F:92:FB:81:4B
  Operation Mode     : Master
  Network ID         : SRR_2467
  Bandwidth          : 4 MHz
  Frequency          : 2467 MHz
  Tx Power           : 30 dBm
  Encryption Type    : AES-128
Traffic Status
  Receive Bytes      : 13.834KB
  Receive Packets    : 226
  Transmit Bytes     : 27.879KB
  Transmit Packets   : 276
Connection Info
  MAC Address        : 00:0F:92:FB:81:5F
  Tx Mod (MIMO)      : 64-QAM FEC 5/6 (On)
  Rx Mod (MIMO)      : QPSK FEC 1/2 (On)
  SNR (dB)           : 68
  RSSI (dBm)         : -33 [-33, -65]
  Noise Floor (dBm)  : -101
OK
*/

void PairingManager::parse_microhard_modem_status(std::string output) {
  auto i1 = output.find("RSSI (dBm)");
  if (i1 != std::string::npos) {
    auto i2 = output.find(": ", i1);
    if (i2 != std::string::npos) {
      i2 += 2;
      auto i3 = i2 + 1;
      while (i3 + 1 < output.length() && output[i3] >= '0' && output[i3] <= '9') {
        i3++;
      }
      if (i3 < output.length()) {
        int rssi;
        if (atoi(output.substr(i2, i3 - i2).c_str(), rssi)) {
          if (_rssi_report_callback) {
            _rssi_report_callback(rssi);
          }
        }
      }
    }
  }
}

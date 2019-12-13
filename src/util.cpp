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

#include <ifaddrs.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/time.h>
#include <algorithm>
#include <array>
#include <climits>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>

#include "util.h"

//-----------------------------------------------------------------------------
std::string timestamp() {
  char buffer[26];
  char msbuf[4];
  int millisec;
  struct tm* tm_info;
  struct timeval tv;

  gettimeofday(&tv, NULL);

  millisec = lrint(tv.tv_usec / 1000.0);  // Round to nearest millisec
  if (millisec >= 1000) {                 // Allow for rounding up to nearest second
    millisec -= 1000;
    tv.tv_sec++;
  }

  tm_info = localtime(&tv.tv_sec);

  strftime(buffer, 26, "%H:%M:%S", tm_info);
  sprintf(msbuf, "%03d", millisec);

  return std::string(buffer) + "." + msbuf + " - ";
}

//-----------------------------------------------------------------------------
std::string exec(const char* cmd) {
  std::array<char, 128> buffer;
  std::string result = "";
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (pipe) {
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
      result += buffer.data();
    }
  }
  return result;
}

//-----------------------------------------------------------------------------

struct iequal {
  bool operator()(int c1, int c2) const { return std::toupper(c1) == std::toupper(c2); }
};

bool iequals(const std::string& str1, const std::string& str2) {
  return std::equal(str1.begin(), str1.end(), str2.begin(), iequal());
}

//-----------------------------------------------------------------------------
std::vector<std::string> split(std::string str, char delimiter) {
  std::vector<std::string> internal;
  std::stringstream ss(str);  // Turn the string into a stream.
  std::string tok;

  while (getline(ss, tok, delimiter)) {
    internal.push_back(tok);
  }

  return internal;
}

//-----------------------------------------------------------------------------

std::vector<std::string> scan_ifaces() {
  std::vector<std::string> ifaces;
  struct ifaddrs *ifaddr, *ifa;
  char host[NI_MAXHOST];
  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return ifaces;
  }
  int n;
  //-- Walk through linked list, maintaining head pointer so we can free list later
  for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
    if (ifa->ifa_addr == nullptr) continue;
    if (ifa->ifa_addr->sa_family != AF_INET) continue;
    int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
    if (s != 0) {
      std::cout << timestamp() << "getnameinfo() failed: " << gai_strerror(s);
      continue;
    }
    bool connected = ifa->ifa_flags & IFF_UP;
    bool loopback = ifa->ifa_flags & IFF_LOOPBACK;
    if (connected && !loopback) {
      ifaces.push_back(std::string(host));
    }
  }
  freeifaddrs(ifaddr);
  return ifaces;
}

//-----------------------------------------------------------------------------
bool atoi(const char* a, int& val) {
  char* end;
  long v = strtol(a, &end, 10);
  if (end == a || *end != '\0' || errno == ERANGE || v < INT_MIN || v > INT_MAX) {
    return false;
  }
  val = static_cast<int>(v);
  return true;
}

//-----------------------------------------------------------------------------
bool can_ping(std::string ip, int timeout) {
  if (ip.empty()) {
    return false;
  }

  std::string cmd = "ping -c 1 -W " + std::to_string(timeout) + " -n " + ip;

  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
  if (!pipe) {
    return false;
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }

  return result.find("100% packet loss") == std::string::npos;
}

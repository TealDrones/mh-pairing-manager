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

#include <algorithm>
#include <array>
#include <climits>
#include <ifaddrs.h>
#include <iostream>
#include <functional>
#include <math.h>
#include <memory>
#include <net/if.h>
#include <netdb.h>
#include <sstream>
#include <sys/time.h>

#include "util.h"

//-----------------------------------------------------------------------------
std::string timestamp()
{
    char buffer[26];
    char msbuf[4];
    int millisec;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec   
    if (millisec>=1000) { // Allow for rounding up to nearest second
        millisec -=1000;
        tv.tv_sec++;
    }

    tm_info = localtime(&tv.tv_sec);

    strftime(buffer, 26, "%H:%M:%S", tm_info);
    sprintf(msbuf, "%03d", millisec);

    return std::string(buffer) + "." + msbuf + " - ";
}

//-----------------------------------------------------------------------------
std::string
exec(const char* cmd)
{
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

struct iequal
{
    bool operator()(int c1, int c2) const
    {
        return std::toupper(c1) == std::toupper(c2);
    }
};
 
bool
iequals(const std::string& str1, const std::string& str2)
{
    return std::equal(str1.begin(), str1.end(), str2.begin(), iequal());
}

//-----------------------------------------------------------------------------
std::vector<std::string>
split(std::string str, char delimiter)
{
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream.
    std::string tok;
 
    while (getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }
 
    return internal;
}

//-----------------------------------------------------------------------------

std::vector<std::string>
scan_ifaces()
{
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
        if (ifa->ifa_addr == nullptr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST,  nullptr, 0, NI_NUMERICHOST);
        if (s != 0) {
            std::cout << timestamp() << "getnameinfo() failed: " << gai_strerror(s);
            continue;
        }
        bool connected = ifa->ifa_flags & IFF_UP;
        bool loopback  = ifa->ifa_flags & IFF_LOOPBACK;
        if (connected && !loopback) {
            ifaces.push_back(std::string(host));
        }
   }
   freeifaddrs(ifaddr);
   return ifaces;
}

//-----------------------------------------------------------------------------
std::string 
random_string(uint length)
{
    srand(time(nullptr));
    auto randchar = []() -> char
    {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const uint max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

//-----------------------------------------------------------------------------
bool atoi(char *a, int& val)
{
    char *end;
    long v = strtol(a, &end, 10); 
    if (end == a || *end != '\0' || errno == ERANGE || v < INT_MIN || v > INT_MAX) {
        return false;
    }
    val = static_cast<int>(v);
    return true;
}

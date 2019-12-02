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

#include <string>
#include <vector>

std::string timestamp();

std::string exec(const char* cmd);

bool iequals(const std::string& str1, const std::string& str2);

std::vector<std::string> split(std::string str, char delimiter);

std::vector<std::string> scan_ifaces();

bool atoi(char* a, int& val);
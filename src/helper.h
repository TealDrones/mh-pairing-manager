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

#include <getopt.h>
#include <iostream>

#include "pairing_manager.h"
#include "util.h"

void help_argv_description(const char* pgm);
void parse_argv(int argc, char* const argv[], PairingManager& pairing_manager);
void check_env_variables(PairingManager& pairing_manager);

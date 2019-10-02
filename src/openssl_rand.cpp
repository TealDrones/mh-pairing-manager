/*************************************************************************
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

#include "openssl_rand.h"
#include <openssl/rand.h>
#include <memory>
//-----------------------------------------------------------------------------
std::string
OpenSSL_Rand::random_string(uint length)
{
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    const int max_index = (sizeof(charset) - 1);

    std::string str(length, 0);
    std::unique_ptr<unsigned char[]> buffer(new unsigned char[length]);
    if (RAND_bytes(buffer.get(), static_cast<int>(length)) == 1) {
        for (unsigned int i = 0; i < length; i++) {
            str[i] = charset[buffer.get()[i] % max_index];
        }
    } else {
        exit(-1);
    }

    return str;
}

//-----------------------------------------------------------------------------

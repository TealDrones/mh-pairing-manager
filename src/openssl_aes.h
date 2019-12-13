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

#include <openssl/evp.h>
#include <string>

const unsigned long long default_salt = 0x368de30e8ec063ce;

class OpenSSL_AES {
 public:
  OpenSSL_AES();

  OpenSSL_AES(std::string password, unsigned long long salt = default_salt, bool use_compression = true) {
    init(password, salt, use_compression);
  }

  ~OpenSSL_AES();

  void init(std::string password, unsigned long long salt = default_salt, bool use_compression = true);

  void deinit();

  std::string encrypt(std::string plain_text);

  std::string decrypt(std::string cipher_text);

 private:
  bool _initialized = false;
  std::string _password;
  unsigned long long _salt = default_salt;
  bool _use_compression = false;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  EVP_CIPHER_CTX *enc_cipher_context = nullptr;
  EVP_CIPHER_CTX *dec_cipher_context = nullptr;
#else
  EVP_CIPHER_CTX enc_cipher_context;
  EVP_CIPHER_CTX dec_cipher_context;
#endif
};

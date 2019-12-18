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

#include "openssl_base64.h"

#include <openssl/bio.h>
#include <memory>

//-----------------------------------------------------------------------------
struct BIOFreeAll {
  void operator()(BIO* p) { BIO_free_all(p); }
};

std::string OpenSSL_Base64::encode(const std::vector<unsigned char>& binary) {
  std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
  BIO* sink = BIO_new(BIO_s_mem());
  BIO_push(b64.get(), sink);
  BIO_write(b64.get(), binary.data(), static_cast<int>(binary.size()));
  BIO_ctrl(b64.get(), BIO_CTRL_FLUSH, 0, nullptr);
  const char* encoded;
  const unsigned long len = static_cast<unsigned long>(BIO_ctrl(sink, BIO_CTRL_INFO, 0, &encoded));

  return std::string(encoded, len);
}

//-----------------------------------------------------------------------------
std::vector<unsigned char> OpenSSL_Base64::decode(std::string encoded) {
  std::unique_ptr<BIO, BIOFreeAll> b64(BIO_new(BIO_f_base64()));
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
  BIO* source = BIO_new_mem_buf(encoded.c_str(), -1);  // read-only source
  BIO_push(b64.get(), source);
  const unsigned long maxlen = encoded.length() / 4 * 3 + 1;
  std::vector<unsigned char> decoded(maxlen);
  const unsigned long len = static_cast<unsigned long>(BIO_read(b64.get(), decoded.data(), static_cast<int>(maxlen)));
  decoded.resize(len);

  return decoded;
}

//-----------------------------------------------------------------------------

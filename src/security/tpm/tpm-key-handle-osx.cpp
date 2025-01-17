/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/tpm/tpm-key-handle-osx.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/key-handle-osx.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_OSX_SECURITY 1.
#include <ndn-ind/ndn-ind-config.h>
#if NDN_IND_HAVE_OSX_SECURITY

#include <stdexcept>
#include <ndn-ind/security/tpm/tpm-back-end-osx.hpp>
#include <ndn-ind/security/tpm/tpm-key-handle-osx.hpp>

using namespace std;

namespace ndn_ind {

TpmKeyHandleOsx::TpmKeyHandleOsx(const KeyRefOsx& key)
: key_(key)
{
  if (key_.get() == 0)
    throw runtime_error("TpmKeyHandleOsx: The key is not set");
}

Blob
TpmKeyHandleOsx::doSign
  (DigestAlgorithm digestAlgorithm, const uint8_t* data, size_t dataLength) const
{
  return TpmBackEndOsx::sign(key_, digestAlgorithm, data, dataLength);
}

Blob
TpmKeyHandleOsx::doDecrypt(const uint8_t* cipherText, size_t cipherTextLength) const
{
  return TpmBackEndOsx::decrypt(key_, cipherText, cipherTextLength);
}

Blob
TpmKeyHandleOsx::doDerivePublicKey() const
{
  return TpmBackEndOsx::derivePublicKey(key_);
}

}

#endif // NDN_IND_HAVE_OSX_SECURITY

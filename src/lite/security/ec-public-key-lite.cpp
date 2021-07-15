/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/lite/security/ec-public-key-lite.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2016-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

#include "../../c/security/ec-public-key.h"
#include <ndn-ind/lite/security/ec-public-key-lite.hpp>

#if NDN_IND_HAVE_LIBCRYPTO

namespace ndn_ind {

EcPublicKeyLite::EcPublicKeyLite()
{
  ndn_EcPublicKey_initialize(this);
}

EcPublicKeyLite::~EcPublicKeyLite()
{
  ndn_EcPublicKey_finalize(this);
}

ndn_Error
EcPublicKeyLite::decode
  (const uint8_t* publicKeyDer, size_t publicKeyDerLength)
{
  return ndn_EcPublicKey_decode(this, publicKeyDer, publicKeyDerLength);
}

ndn_Error
EcPublicKeyLite::encode
  (bool includeParameters, uint8_t* encoding, size_t& encodingLength) const
{
  return ndn_EcPublicKey_encode
    (this, includeParameters ? 1 : 0, encoding, &encodingLength);
}

bool
EcPublicKeyLite::verifyWithSha256
  (const uint8_t *signature, size_t signatureLength, const uint8_t *data,
   size_t dataLength) const
{
  return ndn_EcPublicKey_verifyWithSha256
    (this, signature, signatureLength, data, dataLength) != 0;
}

ndn_Error
EcPublicKeyLite::verifySha256WithEcdsaSignature
  (const uint8_t *signature, size_t signatureLength, const uint8_t *data,
   size_t dataLength, const uint8_t *publicKeyDer, size_t publicKeyDerLength,
   bool &verified)
{
  int intResult;
  ndn_Error status = ndn_verifySha256WithEcdsaSignature
    (signature, signatureLength, data, dataLength, publicKeyDer,
     publicKeyDerLength, &intResult);
  verified = (intResult != 0);
  return status;
}

}

#endif // NDN_IND_HAVE_LIBCRYPTO

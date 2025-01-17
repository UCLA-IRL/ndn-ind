/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/verification-helpers.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Use CertificateV2 getSignedEncoding.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/verification-helpers.cpp
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

#include <stdexcept>
#include <ndn-ind/security/security-exception.hpp>
#include <ndn-ind/security/v2/certificate-v2.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/lite/security/ec-public-key-lite.hpp>
#include <ndn-ind/lite/security/rsa-public-key-lite.hpp>
#include <ndn-ind/security/verification-helpers.hpp>

using namespace std;

namespace ndn_ind {

bool
VerificationHelpers::verifySignature
  (const uint8_t* buffer, size_t bufferLength, const uint8_t* signature,
   size_t signatureLength, const PublicKey& publicKey,
   DigestAlgorithm digestAlgorithm)
{
  bool verified;

  if (digestAlgorithm == DIGEST_ALGORITHM_SHA256) {
#if NDN_IND_HAVE_LIBCRYPTO
    if (publicKey.getKeyType() == KEY_TYPE_RSA) {
      if (RsaPublicKeyLite::verifySha256WithRsaSignature
          (signature, signatureLength, buffer, bufferLength,
           publicKey.getKeyDer().buf(), publicKey.getKeyDer().size(),
           verified) != 0)
        return false;

      return verified;
    }
    else if (publicKey.getKeyType() == KEY_TYPE_EC) {
      if (EcPublicKeyLite::verifySha256WithEcdsaSignature
          (signature, signatureLength, buffer, bufferLength,
           publicKey.getKeyDer().buf(), publicKey.getKeyDer().size(),
           verified) != 0)
        return false;

      return verified;
    }
    else
#endif
      throw invalid_argument("verifySignature: Invalid key type");
  }
  else
    throw invalid_argument("verifySignature: Invalid digest algorithm");
}

bool
VerificationHelpers::verifySignature
  (const uint8_t* buffer, size_t bufferLength, const uint8_t* signature,
   size_t signatureLength, const Blob& publicKeyDer,
   DigestAlgorithm digestAlgorithm)
{
  try {
    return verifySignature
      (buffer, bufferLength, signature, signatureLength, PublicKey(publicKeyDer),
       digestAlgorithm);
  } catch (const UnrecognizedKeyFormatException&) {
    return false;
  }
}

bool
VerificationHelpers::verifyDataSignature
  (const Data& data, const PublicKey& publicKey, DigestAlgorithm digestAlgorithm,
   WireFormat& wireFormat)
{
  SignedBlob signedEncoding;
  Blob signatureValue;
  const CertificateV2* certificate = dynamic_cast<const CertificateV2*>(&data);
  if (certificate) {
    // Special case: Use the CertificateV2 methods which may have special processing.
    signedEncoding = certificate->getSignedEncoding(wireFormat);
    if (signedEncoding.isNull())
      return false;
    signatureValue = certificate->getSignatureValue();
  }
  else {
    try {
      signedEncoding = data.wireEncode(wireFormat);
      signatureValue = data.getSignature()->getSignature();
    } catch (const std::exception&) {
      return false;
    }
  }

  return verifySignature
    (signedEncoding.signedBuf(), signedEncoding.signedSize(),
     signatureValue.buf(), signatureValue.size(), publicKey, digestAlgorithm);
}

bool
VerificationHelpers::verifyDataSignature
  (const Data& data, const Blob& publicKeyDer, DigestAlgorithm digestAlgorithm,
   WireFormat& wireFormat)
{
  try {
    return verifyDataSignature
      (data, PublicKey(publicKeyDer), digestAlgorithm, wireFormat);
  } catch (const UnrecognizedKeyFormatException&) {
    return false;
  }
}

bool
VerificationHelpers::verifyInterestSignature
  (const Interest& interest, const PublicKey& publicKey,
   DigestAlgorithm digestAlgorithm, WireFormat& wireFormat)
{
  ptr_lib::shared_ptr<Signature> signature = extractSignature
    (interest, wireFormat);
  if (!signature)
    return false;

  SignedBlob encoding;
  try {
    encoding = interest.wireEncode(wireFormat);
  } catch (const std::exception&) {
    return false;
  }

  return verifySignature
    (encoding.signedBuf(), encoding.signedSize(),
     signature->getSignature().buf(), signature->getSignature().size(),
     publicKey, digestAlgorithm);
}

bool
VerificationHelpers::verifyInterestSignature
  (const Interest& interest, const Blob& publicKeyDer,
   DigestAlgorithm digestAlgorithm, WireFormat& wireFormat)
{
  try {
    return verifyInterestSignature
      (interest, PublicKey(publicKeyDer), digestAlgorithm, wireFormat);
  } catch (const UnrecognizedKeyFormatException&) {
    return false;
  }
}

bool
VerificationHelpers::verifyDigest
  (const uint8_t* buffer, size_t bufferLength, const uint8_t* digest,
   size_t digestLength, DigestAlgorithm digestAlgorithm)
{
  if (digestAlgorithm == DIGEST_ALGORITHM_SHA256) {
    return CryptoLite::verifyDigestSha256Signature
      (digest, digestLength, buffer, bufferLength);
  }
  else
    throw invalid_argument("verifySignature: Invalid digest algorithm");
}

bool
VerificationHelpers::verifyDataDigest
  (const Data& data, DigestAlgorithm digestAlgorithm, WireFormat& wireFormat)
{
  SignedBlob encoding;
  try {
    encoding = data.wireEncode(wireFormat);
  } catch (const std::exception&) {
    return false;
  }

  return verifyDigest
    (encoding.signedBuf(), encoding.signedSize(),
     data.getSignature()->getSignature().buf(),
     data.getSignature()->getSignature().size(), digestAlgorithm);
}

bool
VerificationHelpers::verifyInterestDigest
  (const Interest& interest, DigestAlgorithm digestAlgorithm,
   WireFormat& wireFormat)
{
  ptr_lib::shared_ptr<Signature> signature = extractSignature
    (interest, wireFormat);
  if (!signature)
    return false;

  SignedBlob encoding;
  try {
    encoding = interest.wireEncode(wireFormat);
  } catch (const std::exception&) {
    return false;
  }

  return verifyDigest
    (encoding.signedBuf(), encoding.signedSize(),
     signature->getSignature().buf(), signature->getSignature().size(),
     digestAlgorithm);
}

ptr_lib::shared_ptr<Signature>
VerificationHelpers::extractSignature
  (const Interest& interest, WireFormat& wireFormat)
{
  if (interest.getName().size() < 2)
    return ptr_lib::shared_ptr<Signature>();

  try {
    return wireFormat.decodeSignatureInfoAndValue
      (interest.getName().get(-2).getValue(),
       interest.getName().get(-1).getValue());
  } catch (std::exception& e) {
    return ptr_lib::shared_ptr<Signature>();
  }
}

}

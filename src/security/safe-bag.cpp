/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/safe-bag.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/safe-bag.cpp
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

#include <ndn-ind/security/certificate/public-key.hpp>
#include <ndn-ind/sha256-with-rsa-signature.hpp>
#include <ndn-ind/sha256-with-ecdsa-signature.hpp>
#include <ndn-ind/encoding/tlv-wire-format.hpp>
#include <ndn-ind/security/tpm/tpm.hpp>
#include <ndn-ind/security/tpm/tpm-back-end-memory.hpp>
#include "../encoding/tlv-decoder.hpp"
#include "../encoding/tlv-encoder.hpp"
#include <ndn-ind/security/safe-bag.hpp>

using namespace std;
using namespace std::chrono;

namespace ndn {

void
SafeBag::wireDecode(const uint8_t* input, size_t inputLength)
{
  // Decode directly as TLV. We don't support the WireFormat abstraction
  // because this isn't meant to go directly on the wire.
  TlvDecoder decoder(input, inputLength);
  size_t endOffset = decoder.readNestedTlvsStart(ndn_Tlv_SafeBag_SafeBag);

  // Get the bytes of the certificate and decode.
  size_t certificateBeginOffset = decoder.offset;
  size_t certificateEndOffset = decoder.readNestedTlvsStart(ndn_Tlv_Data);
  decoder.seek(certificateEndOffset);
  certificate_ = ptr_lib::make_shared<Data>();
  certificate_->wireDecode
    (decoder.getSlice(certificateBeginOffset, certificateEndOffset),
     *TlvWireFormat::get());
  
  privateKeyBag_ = Blob(decoder.readBlobTlv(ndn_Tlv_SafeBag_EncryptedKeyBag));

  decoder.finishNestedTlvs(endOffset);
}

Blob
SafeBag::wireEncode()
{
  // Encode directly as TLV. We don't support the WireFormat abstraction
  // because this isn't meant to go directly on the wire.
  TlvEncoder encoder(256);

  encoder.writeNestedTlv(ndn_Tlv_SafeBag_SafeBag, encodeValue, this);

  return encoder.finish();
}

void
SafeBag::encodeValue(const void *context, TlvEncoder &encoder)
{
  const SafeBag& safeBag =  *(const SafeBag *)context;

  // Add the entire Data packet encoding as is.
  encoder.writeArray(safeBag.certificate_->wireEncode(*TlvWireFormat::get()));
  encoder.writeBlobTlv(ndn_Tlv_SafeBag_EncryptedKeyBag, safeBag.privateKeyBag_);
}

ptr_lib::shared_ptr<CertificateV2>
SafeBag::makeSelfSignedCertificate
  (const Name& keyName, Blob privateKeyBag, Blob publicKeyEncoding,
   const uint8_t* password, size_t passwordLength,
   DigestAlgorithm digestAlgorithm, WireFormat& wireFormat)
{
  ptr_lib::shared_ptr<CertificateV2> certificate(new CertificateV2());

  // Set the name.
  auto now = system_clock::now();
  Name certificateName(keyName);
  certificateName.append("self").appendVersion((uint64_t)toMillisecondsSince1970(now));
  certificate->setName(certificateName);

  // Set the MetaInfo.
  certificate->getMetaInfo().setType(ndn_ContentType_KEY);
  // Set a one-hour freshness period.
  certificate->getMetaInfo().setFreshnessPeriod(hours(1));

  // Set the content.
  PublicKey publicKey(publicKeyEncoding);
  certificate->setContent(publicKey.getKeyDer());

  // Create a temporary in-memory Tpm and import the private key.
  Tpm tpm("", "", ptr_lib::make_shared<TpmBackEndMemory>());
  tpm.importPrivateKey
    (keyName, privateKeyBag.buf(), privateKeyBag.size(), password,
     passwordLength);

  // Set the signature info.
  if (publicKey.getKeyType() == KEY_TYPE_RSA)
    certificate->setSignature(Sha256WithRsaSignature());
  else if (publicKey.getKeyType() == KEY_TYPE_EC)
    certificate->setSignature(Sha256WithEcdsaSignature());
  else
    throw invalid_argument("Unsupported key type");
  Signature* signatureInfo = certificate->getSignature();
  KeyLocator::getFromSignature(signatureInfo).setType(ndn_KeyLocatorType_KEYNAME);
  KeyLocator::getFromSignature(signatureInfo).setKeyName(keyName);

  // Set a 20-year validity period.
  ValidityPeriod::getFromSignature(signatureInfo).setPeriod
    (now, now + hours(20 * 365 * 24));

  // Encode once to get the signed portion.
  SignedBlob encoding = certificate->wireEncode(wireFormat);

  Blob signatureBytes = tpm.sign
    (encoding.signedBuf(), encoding.signedSize(), keyName, digestAlgorithm);
  signatureInfo->setSignature(signatureBytes);

  // Encode again to include the signature.
  certificate->wireEncode(wireFormat);

  return certificate;
}


}

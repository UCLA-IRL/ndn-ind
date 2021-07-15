/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
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
#include <ndn-ind/interest.hpp>
#include <ndn-ind/data.hpp>
#include <ndn-ind/control-parameters.hpp>
#include <ndn-ind/control-response.hpp>
#include <ndn-ind/digest-sha256-signature.hpp>
#include <ndn-ind/sha256-with-rsa-signature.hpp>
#include <ndn-ind/sha256-with-ecdsa-signature.hpp>
#include <ndn-ind/hmac-with-sha256-signature.hpp>
#include <ndn-ind/generic-signature.hpp>
#include <ndn-ind/delegation-set.hpp>
#include <ndn-ind/encrypt/encrypted-content.hpp>
#include <ndn-ind/lite/encoding/tlv-0_3-wire-format-lite.hpp>
#include "tlv-encoder.hpp"
#include <ndn-ind/encoding/tlv-0_3-wire-format.hpp>

using namespace std;

namespace ndn_ind {

static bool didCanBePrefixWarning_ = false;

Blob
Tlv0_3WireFormat::encodeName(const Name& name)
{
  struct ndn_NameComponent nameComponents[100];
  NameLite nameLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));
  name.get(nameLite);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t dummyBeginOffset, dummyEndOffset, encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeName
       (nameLite, &dummyBeginOffset, &dummyEndOffset,
        DynamicUInt8ArrayLite::downCast(output), &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeName
  (Name& name, const uint8_t *input, size_t inputLength)
{
  struct ndn_NameComponent nameComponents[100];
  NameLite nameLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));

  ndn_Error error;
  size_t dummyBeginOffset, dummyEndOffset;
  if ((error = Tlv0_3WireFormatLite::decodeName
       (nameLite, input, inputLength, &dummyBeginOffset, &dummyEndOffset)))
    throw runtime_error(ndn_getErrorString(error));

  name.set(nameLite);
}

Blob
Tlv0_3WireFormat::encodeInterest
  (const Interest& interest, size_t *signedPortionBeginOffset,
   size_t *signedPortionEndOffset)
{
  if (!interest.getDidSetCanBePrefix_() && !didCanBePrefixWarning_) {
    printf
      ("WARNING: The default CanBePrefix will change. See Interest::setDefaultCanBePrefix() for details.\n");
    didCanBePrefixWarning_ = true;
  }

  struct ndn_NameComponent nameComponents[100];
  struct ndn_ExcludeEntry excludeEntries[100];
  struct ndn_NameComponent keyNameComponents[100];
  InterestLite interestLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     excludeEntries, sizeof(excludeEntries) / sizeof(excludeEntries[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));
  Blob blob1, blob2;
  interest.get(interestLite, *this, blob1, blob2);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeInterest
       (interestLite, signedPortionBeginOffset, signedPortionEndOffset,
        DynamicUInt8ArrayLite::downCast(output), &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeInterest
  (Interest& interest, const uint8_t *input, size_t inputLength,
   size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_ExcludeEntry excludeEntries[100];
  struct ndn_NameComponent keyNameComponents[100];
  InterestLite interestLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     excludeEntries, sizeof(excludeEntries) / sizeof(excludeEntries[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeInterest
       (interestLite, input, inputLength, signedPortionBeginOffset,
        signedPortionEndOffset)))
    throw runtime_error(ndn_getErrorString(error));

  if (interestLite.getForwardingHintWireEncoding().buf()) {
    // Throw any decoding exceptions now before calling set.
    DelegationSet delegationSet;
    decodeDelegationSet
      (delegationSet, interestLite.getForwardingHintWireEncoding().buf(),
       interestLite.getForwardingHintWireEncoding().size());
  }

  interest.set(interestLite, *this);
}

Blob
Tlv0_3WireFormat::encodeData(const Data& data, size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent keyNameComponents[100];
  DataLite dataLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));
  data.get(dataLite);

  DynamicUInt8Vector output(1500);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeData
       (dataLite, signedPortionBeginOffset, signedPortionEndOffset,
        DynamicUInt8ArrayLite::downCast(output), &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeData
  (Data& data, const uint8_t *input, size_t inputLength, size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent keyNameComponents[100];
  DataLite dataLite
    (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]),
     keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeData
       (dataLite, input, inputLength, signedPortionBeginOffset,
        signedPortionEndOffset)))
    throw runtime_error(ndn_getErrorString(error));

  data.set(dataLite);
}

Blob
Tlv0_3WireFormat::encodeControlParameters
  (const ControlParameters& controlParameters)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent strategyNameComponents[100];
  ControlParametersLite controlParametersLite
    (nameComponents,
     sizeof(nameComponents) / sizeof(nameComponents[0]), strategyNameComponents,
     sizeof(strategyNameComponents) / sizeof(strategyNameComponents[0]));
  controlParameters.get(controlParametersLite);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeControlParameters
       (controlParametersLite, DynamicUInt8ArrayLite::downCast(output),
        &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeControlParameters
  (ControlParameters& controlParameters, const uint8_t *input,
   size_t inputLength)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent strategyNameComponents[100];
  ControlParametersLite controlParametersLite
    (nameComponents,
     sizeof(nameComponents) / sizeof(nameComponents[0]), strategyNameComponents,
     sizeof(strategyNameComponents) / sizeof(strategyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeControlParameters
       (controlParametersLite, input, inputLength)))
    throw runtime_error(ndn_getErrorString(error));

  controlParameters.set(controlParametersLite);
}

Blob
Tlv0_3WireFormat::encodeControlResponse(const ControlResponse& controlResponse)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent strategyNameComponents[100];
  ControlResponseLite controlResponseLite
    (nameComponents,
     sizeof(nameComponents) / sizeof(nameComponents[0]), strategyNameComponents,
     sizeof(strategyNameComponents) / sizeof(strategyNameComponents[0]));
  controlResponse.get(controlResponseLite);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeControlResponse
       (controlResponseLite, DynamicUInt8ArrayLite::downCast(output),
        &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeControlResponse
  (ControlResponse& controlResponse, const uint8_t *input,
   size_t inputLength)
{
  struct ndn_NameComponent nameComponents[100];
  struct ndn_NameComponent strategyNameComponents[100];
  ControlResponseLite controlResponseLite
    (nameComponents,
     sizeof(nameComponents) / sizeof(nameComponents[0]), strategyNameComponents,
     sizeof(strategyNameComponents) / sizeof(strategyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeControlResponse
       (controlResponseLite, input, inputLength)))
    throw runtime_error(ndn_getErrorString(error));

  controlResponse.set(controlResponseLite);
}

Blob
Tlv0_3WireFormat::encodeSignatureInfo(const Signature& signature)
{
  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));
  signature.get(signatureLite);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeSignatureInfo
       (signatureLite, DynamicUInt8ArrayLite::downCast(output), &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

Blob
Tlv0_3WireFormat::encodeSignatureValue(const Signature& signature)
{
  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));
  signature.get(signatureLite);

  DynamicUInt8Vector output(300);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeSignatureValue
       (signatureLite, DynamicUInt8ArrayLite::downCast(output), &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

ptr_lib::shared_ptr<Signature>
Tlv0_3WireFormat::decodeSignatureInfoAndValue
  (const uint8_t *signatureInfo, size_t signatureInfoLength,
   const uint8_t *signatureValue, size_t signatureValueLength)
{
  struct ndn_NameComponent keyNameComponents[100];
  SignatureLite signatureLite
    (keyNameComponents, sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeSignatureInfoAndValue
       (signatureLite, signatureInfo, signatureInfoLength, signatureValue,
        signatureValueLength)))
    throw runtime_error(ndn_getErrorString(error));

  ptr_lib::shared_ptr<Signature> result;
  if (signatureLite.getType() == ndn_SignatureType_Sha256WithRsaSignature)
    result.reset(new Sha256WithRsaSignature());
  else if (signatureLite.getType() == ndn_SignatureType_Sha256WithEcdsaSignature)
    result.reset(new Sha256WithEcdsaSignature());
  else if (signatureLite.getType() == ndn_SignatureType_HmacWithSha256Signature)
    result.reset(new HmacWithSha256Signature());
  else if (signatureLite.getType() == ndn_SignatureType_DigestSha256Signature)
    result.reset(new DigestSha256Signature());
  else if (signatureLite.getType() == ndn_SignatureType_Generic)
    result.reset(new GenericSignature());
  else
    // We don't expect this to happen.
    throw runtime_error("signatureStruct.type has an unrecognized value");

  result->set(signatureLite);
  return result;
}

Blob
Tlv0_3WireFormat::encodeDelegationSet(const DelegationSet& delegationSet)
{
  DynamicUInt8Vector output(256);
  size_t encodingLength = 0;

  // Encode a series of Delegation.
  for (size_t i = 0; i < delegationSet.size(); ++i) {
    struct ndn_NameComponent nameComponents[100];
    DelegationSetLite::Delegation delegationLite
      (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));
    delegationSet.get(i).get(delegationLite);

    size_t delegationEncodingLength;
    ndn_Error error;
    if ((error = Tlv0_3WireFormatLite::encodeDelegationSet_Delegation
         (delegationLite, DynamicUInt8ArrayLite::downCast(output), encodingLength,
          &delegationEncodingLength)))
      throw runtime_error(ndn_getErrorString(error));

    encodingLength += delegationEncodingLength;
  }

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeDelegationSet
  (DelegationSet& delegationSet, const uint8_t *input, size_t inputLength)
{
  delegationSet.clear();

  // Decode a series of Delegation
  size_t offset = 0;
  while (offset < inputLength) {
    struct ndn_NameComponent nameComponents[100];
    DelegationSetLite::Delegation delegationLite
      (nameComponents, sizeof(nameComponents) / sizeof(nameComponents[0]));

    size_t encodingLength;
    ndn_Error error;
    if ((error = Tlv0_3WireFormatLite::decodeDelegationSet_Delegation
         (delegationLite, input + offset, inputLength - offset, &encodingLength)))
      throw runtime_error(ndn_getErrorString(error));

    offset += encodingLength;
    delegationSet.addUnsorted
      (ptr_lib::make_shared<DelegationSet::Delegation>(delegationLite));
  }
}

Blob
Tlv0_3WireFormat::encodeEncryptedContentV2
  (const EncryptedContent& encryptedContent)
{
  struct ndn_NameComponent keyNameComponents[100];
  EncryptedContentLite encryptedContentLite
    (keyNameComponents,
     sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));
  encryptedContent.get(encryptedContentLite);

  DynamicUInt8Vector output(256);
  ndn_Error error;
  size_t encodingLength;
  if ((error = Tlv0_3WireFormatLite::encodeEncryptedContentV2
       (encryptedContentLite, DynamicUInt8ArrayLite::downCast(output),
        &encodingLength)))
    throw runtime_error(ndn_getErrorString(error));

  return output.finish(encodingLength);
}

void
Tlv0_3WireFormat::decodeEncryptedContentV2
  (EncryptedContent& encryptedContent, const uint8_t *input,
   size_t inputLength)
{
  struct ndn_NameComponent keyNameComponents[100];
  EncryptedContentLite encryptedContentLite
    (keyNameComponents,
     sizeof(keyNameComponents) / sizeof(keyNameComponents[0]));

  ndn_Error error;
  if ((error = Tlv0_3WireFormatLite::decodeEncryptedContentV2
       (encryptedContentLite, input, inputLength)))
    throw runtime_error(ndn_getErrorString(error));

  encryptedContent.set(encryptedContentLite);
}

Tlv0_3WireFormat* Tlv0_3WireFormat::instance_ = 0;

}

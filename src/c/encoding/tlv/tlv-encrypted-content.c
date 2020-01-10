/**
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

#include "tlv-key-locator.h"
#include "tlv-name.h"
#include "tlv-encrypted-content.h"

/**
 * This private function is called by ndn_TlvEncoder_writeNestedTlv to write the TLVs
 * in the body of the EncryptedContent v1 value.
 * @param context This is the ndn_EncryptedContent struct pointer which was
 * passed to writeTlv.
 * @param encoder the ndn_TlvEncoder which is calling this.
 * @return 0 for success, else an error code.
 */
static ndn_Error
encodeEncryptedContentValue(const void *context, struct ndn_TlvEncoder *encoder)
{
  struct ndn_EncryptedContent *encryptedContent =
    (struct ndn_EncryptedContent *)context;
  ndn_Error error;

  if ((error = ndn_TlvEncoder_writeNestedTlv
       (encoder, ndn_Tlv_KeyLocator, ndn_encodeTlvKeyLocatorValue,
        &encryptedContent->keyLocator, 0)))
    return error;
  if ((error = ndn_TlvEncoder_writeNonNegativeIntegerTlv
       (encoder, ndn_Tlv_Encrypt_EncryptionAlgorithm,
        encryptedContent->algorithmType)))
    return error;
  if ((error = ndn_TlvEncoder_writeOptionalBlobTlv
       (encoder, ndn_Tlv_Encrypt_InitialVector, &encryptedContent->initialVector)))
    return error;
  if ((error = ndn_TlvEncoder_writeBlobTlv
       (encoder, ndn_Tlv_Encrypt_EncryptedPayload, &encryptedContent->payload)))
    return error;

  return NDN_ERROR_success;
}

ndn_Error
ndn_encodeTlvEncryptedContent
  (const struct ndn_EncryptedContent *encryptedContent,
   struct ndn_TlvEncoder *encoder)
{
  return ndn_TlvEncoder_writeNestedTlv
    (encoder, ndn_Tlv_Encrypt_EncryptedContent, encodeEncryptedContentValue,
     encryptedContent, 0);
}

ndn_Error
ndn_decodeTlvEncryptedContent
  (struct ndn_EncryptedContent *encryptedContent, struct ndn_TlvDecoder *decoder)
{
  ndn_Error error;
  size_t endOffset;
  uint64_t algorithmType;

  if ((error = ndn_TlvDecoder_readNestedTlvsStart
       (decoder, ndn_Tlv_Encrypt_EncryptedContent, &endOffset)))
    return error;

  ndn_EncryptedContent_clear(encryptedContent);

  if ((error = ndn_decodeTlvKeyLocator
       (ndn_Tlv_KeyLocator, &encryptedContent->keyLocator, decoder)))
    return error;

  if ((error = ndn_TlvDecoder_readNonNegativeIntegerTlv
       (decoder, ndn_Tlv_Encrypt_EncryptionAlgorithm, &algorithmType)))
    return error;
  encryptedContent->algorithmType = algorithmType;

  if ((error = ndn_TlvDecoder_readOptionalBlobTlv
       (decoder, ndn_Tlv_Encrypt_InitialVector, endOffset,
        &encryptedContent->initialVector)))
    return error;
  if ((error = ndn_TlvDecoder_readBlobTlv
       (decoder, ndn_Tlv_Encrypt_EncryptedPayload, &encryptedContent->payload)))
    return error;

  if ((error = ndn_TlvDecoder_finishNestedTlvs(decoder, endOffset)))
    return error;

  return NDN_ERROR_success;
}

/**
 * This private function is called by ndn_TlvEncoder_writeNestedTlv to write the
 * TLVs in the body of the EncryptedContent v2 value.
 * @param context This is the ndn_EncryptedContent struct pointer which was
 * passed to writeTlv.
 * @param encoder the ndn_TlvEncoder which is calling this.
 * @return 0 for success, else an error code.
 */
static ndn_Error
encodeEncryptedContentV2Value(const void *context, struct ndn_TlvEncoder *encoder)
{
  struct ndn_EncryptedContent *encryptedContent =
    (struct ndn_EncryptedContent *)context;
  size_t dummyBeginOffset, dummyEndOffset;
  ndn_Error error;

  if ((error = ndn_TlvEncoder_writeBlobTlv
       (encoder, ndn_Tlv_Encrypt_EncryptedPayload, &encryptedContent->payload)))
    return error;
  if ((error = ndn_TlvEncoder_writeOptionalBlobTlv
       (encoder, ndn_Tlv_Encrypt_InitialVector, &encryptedContent->initialVector)))
    return error;
  if ((error = ndn_TlvEncoder_writeOptionalBlobTlv
       (encoder, ndn_Tlv_Encrypt_EncryptedPayloadKey,
        &encryptedContent->payloadKey)))
    return error;
  if (encryptedContent->keyLocator.type == ndn_KeyLocatorType_KEYNAME) {
    if ((error = ndn_encodeTlvName
         (&encryptedContent->keyLocator.keyName, &dummyBeginOffset,
          &dummyEndOffset, encoder)))
      return error;
  }

  return NDN_ERROR_success;
}

ndn_Error
ndn_encodeTlvEncryptedContentV2
  (const struct ndn_EncryptedContent *encryptedContent,
   struct ndn_TlvEncoder *encoder)
{
  return ndn_TlvEncoder_writeNestedTlv
    (encoder, ndn_Tlv_Encrypt_EncryptedContent, encodeEncryptedContentV2Value,
     encryptedContent, 0);
}

ndn_Error
ndn_decodeTlvEncryptedContentV2
  (struct ndn_EncryptedContent *encryptedContent, struct ndn_TlvDecoder *decoder)
{
  ndn_Error error;
  size_t endOffset;
  int gotExpectedType;
  size_t dummyBeginOffset, dummyEndOffset;

  if ((error = ndn_TlvDecoder_readNestedTlvsStart
       (decoder, ndn_Tlv_Encrypt_EncryptedContent, &endOffset)))
    return error;

  ndn_EncryptedContent_clear(encryptedContent);

  if ((error = ndn_TlvDecoder_readBlobTlv
       (decoder, ndn_Tlv_Encrypt_EncryptedPayload, &encryptedContent->payload)))
    return error;
  if ((error = ndn_TlvDecoder_readOptionalBlobTlv
       (decoder, ndn_Tlv_Encrypt_InitialVector, endOffset,
        &encryptedContent->initialVector)))
    return error;
  if ((error = ndn_TlvDecoder_readOptionalBlobTlv
       (decoder, ndn_Tlv_Encrypt_EncryptedPayloadKey, endOffset,
        &encryptedContent->payloadKey)))
    return error;

  if ((error = ndn_TlvDecoder_peekType
       (decoder, ndn_Tlv_Name, endOffset, &gotExpectedType)))
    return error;
  if (gotExpectedType) {
    if ((error = ndn_decodeTlvName
         (&encryptedContent->keyLocator.keyName, &dummyBeginOffset,
          &dummyEndOffset, decoder)))
      return error;
    encryptedContent->keyLocator.type = ndn_KeyLocatorType_KEYNAME;
  }

  if ((error = ndn_TlvDecoder_finishNestedTlvs(decoder, endOffset)))
    return error;

  return NDN_ERROR_success;
}

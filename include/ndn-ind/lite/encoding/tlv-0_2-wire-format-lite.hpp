/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/lite/encoding/tlv-0_2-wire-format-lite.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Remove unused methods. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2015-2020 Regents of the University of California.
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

#ifndef NDN_TLV_0_2_WIRE_FORMAT_LITE_HPP
#define NDN_TLV_0_2_WIRE_FORMAT_LITE_HPP

#include "tlv-0_3-wire-format-lite.hpp"

namespace ndn_ind {

/**
 * A Tlv0_2WireFormatLite implements implement encoding and decoding using
 * NDN-TLV version 0.2. These methods call the ones for version version 0.3
 * except where the format is different for version 0.2.
 */
class ndn_ind_dll Tlv0_2WireFormatLite {
public:
  /**
   * Encode name as NDN-TLV.
   * @param name The name object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeName
    (const NameLite& name, size_t* signedPortionBeginOffset,
     size_t* signedPortionEndOffset, DynamicUInt8ArrayLite& output,
     size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeName
      (name, signedPortionBeginOffset, signedPortionEndOffset, output,
       encodingLength);
  }

  /**
   * Decode input as a name in NDN-TLV and set the fields of the name
   * object.
   * @param name The name object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeName
    (NameLite& name, const uint8_t* input, size_t inputLength,
     size_t* signedPortionBeginOffset, size_t* signedPortionEndOffset)
  {
    return Tlv0_3WireFormatLite::decodeName
      (name, input, inputLength, signedPortionBeginOffset, signedPortionEndOffset);
  }

  /**
   * Encode interest as NDN-TLV.
   * @param interest The interest object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeInterest
    (const InterestLite& interest, size_t* signedPortionBeginOffset,
     size_t* signedPortionEndOffset, DynamicUInt8ArrayLite& output,
     size_t* encodingLength);

  /**
   * Decode input as an interest in NDN-TLV and set the fields of the interest
   * object.
   * @param interest The Interest object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeInterest
    (InterestLite& interest, const uint8_t* input, size_t inputLength,
     size_t* signedPortionBeginOffset, size_t* signedPortionEndOffset);

  /**
   * Encode the data packet as NDN-TLV.
   * @param data The data object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. If you are not encoding in order to sign,
   * you can ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end of
   * the signed portion. If you are not encoding in order to sign, you can ignore
   * this returned value.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeData
    (const DataLite& data, size_t* signedPortionBeginOffset,
     size_t* signedPortionEndOffset, DynamicUInt8ArrayLite& output,
     size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeData
      (data, signedPortionBeginOffset, signedPortionEndOffset, output,
       encodingLength);
  }

  /**
   * Decode input as a data packet in NDN-TLV and set the fields in the data object.
   * @param data The data object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param signedPortionBeginOffset Return the offset in the input buffer of the
   * beginning of the signed portion. If you are not decoding in order to verify,
   * you can ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the end
   * of the signed portion. If you are not decoding in order to verify, you can
   * ignore this returned value.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeData
    (DataLite& data, const uint8_t* input, size_t inputLength,
     size_t* signedPortionBeginOffset, size_t* signedPortionEndOffset)
  {
    return Tlv0_3WireFormatLite::decodeData
      (data, input, inputLength, signedPortionBeginOffset, signedPortionEndOffset);
  }

  /**
   * Encode controlParameters as an NDN-TLV ControlParameters.
   * @param controlParameters The control parameters object to encode.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeControlParameters
    (const ControlParametersLite& controlParameters,
     DynamicUInt8ArrayLite& output, size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeControlParameters
      (controlParameters, output, encodingLength);
  }

  /**
   * Decode input as a TLV ControlParameters and set the fields in the
   * controlParameters object.
   * @param controlParameters The control parameters object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeControlParameters
    (ControlParametersLite& controlParameters, const uint8_t* input,
     size_t inputLength)
  {
    return Tlv0_3WireFormatLite::decodeControlParameters
      (controlParameters, input, inputLength);
  }

  /**
   * Encode controlResponse as an NDN-TLV ControlResponse.
   * @param controlResponse The control parameters object to encode.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeControlResponse
    (const ControlResponseLite& controlResponse,
     DynamicUInt8ArrayLite& output, size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeControlResponse
      (controlResponse, output, encodingLength);
  }

  /**
   * Decode input as a TLV ControlResponse and set the fields in the
   * controlResponse object.
   * @param controlResponse The control parameters object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeControlResponse
    (ControlResponseLite& controlResponse, const uint8_t* input,
     size_t inputLength)
  {
    return Tlv0_3WireFormatLite::decodeControlResponse
      (controlResponse, input, inputLength);
  }

  /**
   * Encode signature as an NDN-TLV SignatureInfo.
   * @param signature The signature object to encode.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeSignatureInfo
    (const SignatureLite& signature, DynamicUInt8ArrayLite& output,
     size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeSignatureInfo
      (signature, output, encodingLength);
  }

  /**
   * Encode the signatureValue in the Signature object as an NDN-TLV
   * SignatureValue (the signature bits).
   * @param signature The signature object with the signature bits.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeSignatureValue
    (const SignatureLite& signature, DynamicUInt8ArrayLite& output,
     size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeSignatureValue
      (signature, output, encodingLength);
  }

  /**
   * Decode signatureInfo as an NDN-TLV signature info and signatureValue as the
   * related SignatureValue, and set the fields in the signature object.
   * @param signature The signature object whose fields are updated.
   * @param signatureInfo A pointer to the signature info input buffer to decode.
   * @param signatureInfoLength The number of bytes in signatureInfo.
   * @param signatureValue A pointer to the signature value input buffer to decode.
   * @param signatureValueLength The number of bytes in signatureValue.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeSignatureInfoAndValue
    (SignatureLite& signature, const uint8_t *signatureInfo,
     size_t signatureInfoLength, const uint8_t *signatureValue,
     size_t signatureValueLength)
  {
    return Tlv0_3WireFormatLite::decodeSignatureInfoAndValue
      (signature, signatureInfo, signatureInfoLength, signatureValue,
       signatureValueLength);
  }

  /**
   * Decode input as a TLV LpPacket and set the fields in the lpPacket object.
   * @param lpPacket The LpPacketLite object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeLpPacket
    (LpPacketLite& lpPacket, const uint8_t* input, size_t inputLength)
  {
    return Tlv0_3WireFormatLite::decodeLpPacket
      (lpPacket, input, inputLength);
  }

  /**
   * Encode delegation as an NDN-TLV Delegation.
   * @param delegation The delegation object to encode.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param offset The offset into the output buffer to begin encoding. This is
   * provided so that a DelegationSet can be encoded as as series of Delegation.
   * @param encodingLength Set encodingLength to the length of the encoded output,
   * starting from offset.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeDelegationSet_Delegation
    (const DelegationSetLite::Delegation& delegation,
     DynamicUInt8ArrayLite& output, size_t offset, size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeDelegationSet_Delegation
      (delegation, output, offset, encodingLength);
  }

  /**
   * Decode input as an NDN-TLV Delegation and set the fields in the delegation
   * object.
   * @param delegation The delegation object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param encodingLength Set encodingLength to the length of the decoded value.
   * This is provided so that a DelegationSet can be decoded as as series of
   * Delegation.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeDelegationSet_Delegation
    (DelegationSetLite::Delegation& delegation, const uint8_t* input,
     size_t inputLength, size_t *encodingLength)
  {
    return Tlv0_3WireFormatLite::decodeDelegationSet_Delegation
      (delegation, input, inputLength, encodingLength);
  }

  /**
   * Encode the EncryptedContent v2 (used in Name-based Access Control v2) in
   * NDN-TLV.
   * See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .
   * @param encryptedContent The encrypted content object to encode.
   * @param output A DynamicUInt8ArrayLite object which receives the encoded
   * output.  If the output's reallocFunction is null, its array must be large
   * enough to receive the entire encoding.
   * @param encodingLength Set encodingLength to the length of the encoded output.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  encodeEncryptedContentV2
    (const EncryptedContentLite& encryptedContent,
     DynamicUInt8ArrayLite& output, size_t* encodingLength)
  {
    return Tlv0_3WireFormatLite::encodeEncryptedContentV2
      (encryptedContent, output, encodingLength);
  }

  /**
   * Decode input as an an EncryptedContent v2 (used in Name-based Access
   * Control v2) in NDN-TLV and set the fields of the encryptedContent object.
   * See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .
   * @param encryptedContent The encrypted content object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @return 0 for success, else an error code.
   */
  static ndn_Error
  decodeEncryptedContentV2
    (EncryptedContentLite& encryptedContent, const uint8_t* input,
     size_t inputLength)
  {
    return Tlv0_3WireFormatLite::decodeEncryptedContentV2
      (encryptedContent, input, inputLength);
  }
};

}

#endif

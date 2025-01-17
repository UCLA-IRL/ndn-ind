/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/encoding/tlv-0_3-wire-format.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
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

#ifndef NDN_TLV_0_3_WIRE_FORMAT_HPP
#define NDN_TLV_0_3_WIRE_FORMAT_HPP

#include "wire-format.hpp"

namespace ndn_ind {

/**
 * A Tlv0_3WireFormat extends WireFormat to override its virtual methods to
 * implement encoding and decoding using NDN-TLV version 0.3.  To always use
 * the preferred version NDN-TLV, you should use the class TlvWireFormat.
 */
class ndn_ind_dll Tlv0_3WireFormat : public WireFormat {
public:
  /**
   * Encode name in NDN-TLV and return the encoding.
   * @param name The Name object to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeName(const Name& name);

  /**
   * Decode input as a name in NDN-TLV and set the fields of the Name object.
   * @param name The Name object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   */
  virtual void
  decodeName(Name& name, const uint8_t *input, size_t inputLength);

  /**
   * Encode interest in NDN-TLV and return the encoding.
   * @param interest The Interest object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeInterest
    (const Interest& interest, size_t *signedPortionBeginOffset,
     size_t *signedPortionEndOffset);

  /**
   * Decode input as an interest in NDN-TLV and set the fields of the interest object.
   * @param interest The Interest object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param signedPortionBeginOffset Return the offset in the encoding of the
   * beginning of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can call
   * decodeInterest(Interest& interest, const uint8_t *input, size_t inputLength)
   * to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end
   * of the signed portion. The signed portion starts from the first
   * name component and ends just before the final name component (which is
   * assumed to be a signature for a signed interest).
   * If you are not decoding in order to verify, you can call
   * decodeInterest(Interest& interest, const uint8_t *input, size_t inputLength)
   * to ignore this returned value.
   */
  virtual void
  decodeInterest
    (Interest& interest, const uint8_t *input, size_t inputLength,
     size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset);

  /**
   * Encode data with NDN-TLV and return the encoding.
   * @param data The Data object to encode.
   * @param signedPortionBeginOffset Return the offset in the encoding of the beginning of the signed portion.
   * If you are not encoding in order to sign, you can call encodeData(const Data& data) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the encoding of the end of the signed portion.
   * If you are not encoding in order to sign, you can call encodeData(const Data& data) to ignore this returned value.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeData
    (const Data& data, size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset);

  /**
   * Decode input as a data packet in NDN-TLV and set the fields in the data object.
   * @param data The Data object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   * @param signedPortionBeginOffset Return the offset in the input buffer of the beginning of the signed portion.
   * If you are not decoding in order to verify, you can call
   * decodeData(Data& data, const uint8_t *input, size_t inputLength) to ignore this returned value.
   * @param signedPortionEndOffset Return the offset in the input buffer of the end of the signed portion.
   * If you are not decoding in order to verify, you can call
   * decodeData(Data& data, const uint8_t *input, size_t inputLength) to ignore this returned value.
   */
  virtual void
  decodeData
    (Data& data, const uint8_t *input, size_t inputLength, size_t *signedPortionBeginOffset, size_t *signedPortionEndOffset);

  /**
   * Encode controlParameters as NDN-TLV and return the encoding.
   * @param controlParameters The ControlParameters object to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeControlParameters(const ControlParameters& controlParameters);

  /**
   * Decode input as an NDN-TLV ControlParameters and set the fields of the
   * controlParameters object.
   * @param controlParameters The ControlParameters object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   */
  virtual void
  decodeControlParameters
    (ControlParameters& controlParameters, const uint8_t *input,
     size_t inputLength);

  /**
   * Encode controlResponse as NDN-TLV and return the encoding.
   * @param controlResponse The ControlResponse object to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeControlResponse(const ControlResponse& controlResponse);

  /**
   * Decode input as an NDN-TLV ControlResponse and set the fields of the
   * controlResponse object.
   * @param controlResponse The ControlResponse object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   */
  virtual void
  decodeControlResponse
    (ControlResponse& controlResponse, const uint8_t *input,
     size_t inputLength);

  /**
   * Encode signature as an NDN-TLV SignatureInfo and return the encoding.
   * @param signature An object of a subclass of Signature to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeSignatureInfo(const Signature& signature);

  /**
   * Encode the signatureValue in the Signature object as an NDN-TLV
   * SignatureValue (the signature bits) and return the encoding.
   * @param signature An object of a subclass of Signature with the signature
   * value to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeSignatureValue(const Signature& signature);

  /**
   * Decode signatureInfo as a signature info and signatureValue as the related
   * SignatureValue, and return a new object which is a subclass of Signature.
   * @param signatureInfo A pointer to the signature info input buffer to decode.
   * @param signatureInfoLength The number of bytes in signatureInfo.
   * @param signatureValue A pointer to the signature value input buffer to decode.
   * @param signatureValueLength The number of bytes in signatureValue.
   * @return A new object which is a subclass of Signature.
   */
  virtual ptr_lib::shared_ptr<Signature>
  decodeSignatureInfoAndValue
    (const uint8_t *signatureInfo, size_t signatureInfoLength,
     const uint8_t *signatureValue, size_t signatureValueLength);

  /**
   * Encode delegationSet as a sequence of NDN-TLV Delegation, and return the
   * encoding. Note that the sequence of Delegation does not have an outer TLV
   * type and length because it is intended to use the type and length of a Data
   * packet's Content.
   * @param delegationSet The DelegationSet object to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeDelegationSet(const DelegationSet& delegationSet);

  /**
   * Decode input as a sequence of NDN-TLV Delegation and set the fields of the
   * delegationSet object. Note that the sequence of Delegation does not have an
   * outer TLV type and length because it is intended to use the type and length
   * of a Data packet's Content. This ignores any elements after the sequence
   * of Delegation and before inputLength.
   * @param delegationSet The DelegationSet object whose fields are updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   */
  virtual void
  decodeDelegationSet
    (DelegationSet& delegationSet, const uint8_t *input, size_t inputLength);

  /**
   * Encode the EncryptedContent v2 (used in Name-based Access Control v2) in
   * NDN-TLV and return the encoding.
   * See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .
   * @param encryptedContent The EncryptedContent object to encode.
   * @return A Blob containing the encoding.
   */
  virtual Blob
  encodeEncryptedContentV2(const EncryptedContent& encryptedContent);

  /**
   * Decode input as an an EncryptedContent v2 (used in Name-based Access
   * Control v2) in NDN-TLV and set the fields of the encryptedContent object.
   * See https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst .
   * @param encryptedContent The EncryptedContent object whose fields are
   * updated.
   * @param input A pointer to the input buffer to decode.
   * @param inputLength The number of bytes in input.
   */
  virtual void
  decodeEncryptedContentV2
    (EncryptedContent& encryptedContent, const uint8_t *input,
     size_t inputLength);

  /**
   * Get a singleton instance of a Tlv0_3WireFormat.  To always use the
   * preferred version NDN-TLV, you should use TlvWireFormat::get().
   * @return A pointer to the singleton instance.
   */
  static Tlv0_3WireFormat*
  get()
  {
    if (!instance_)
      instance_ = new Tlv0_3WireFormat();

    return instance_;
  }

private:
  static Tlv0_3WireFormat* instance_;
};

}

#endif

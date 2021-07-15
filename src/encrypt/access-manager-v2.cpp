/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/encrypt/access-manager-v2.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/access-manager.cpp
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

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/encrypt/encryptor-v2.hpp>
#include <ndn-ind/lite/security/rsa-public-key-lite.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/encrypt/access-manager-v2.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn_ind::func_lib;

INIT_LOGGER("ndn.AccessManagerV2");

namespace ndn_ind {


void
AccessManagerV2::Impl::initializeForGck(const Name& dataset)
{
  // The NAC identity is: <identity>/NAC/<dataset>
  nacIdentityName_ = Name(identity_->getName())
    .append(EncryptorV2::getNAME_COMPONENT_NAC()).append(dataset);

  if (gckAlgorithmType_ == ndn_EncryptAlgorithmType_ChaCha20Poly1305)
    gckBits_.resize(ndn_CHACHA20_KEY_LENGTH);
  else if (gckAlgorithmType_ == ndn_EncryptAlgorithmType_AesCbc)
    gckBits_.resize(ndn_AES_256_KEY_LENGTH);
  else
    throw std::runtime_error("AccessManagerV2: Unsupported content key algorithm type");

  gckLatestPrefix_ = Name(nacIdentityName_)
    .append(EncryptorV2::getNAME_COMPONENT_GCK())
    .append(EncryptorV2::getNAME_COMPONENT_LATEST());

  refreshGck();

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<Impl>& parent)
    : parent_(parent)
    {}

    void
    onInterest
      (const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
      if (parent_->gckLatestPrefix_.isPrefixOf(interest->getName())) {
        parent_->publishGckLatestData(face);
        return;
      }

      // Serve from storage.
      ptr_lib::shared_ptr<Data> data = parent_->storage_.find(*interest);
      if (data) {
        _LOG_TRACE("Serving " << data->getName() << " from InMemoryStorage");
        try {
          face.putData(*data);
        } catch (const std::exception& ex) {
          _LOG_ERROR("AccessManagerV2: Error in Face.putData: " << ex.what());
        }
      }
      else {
        _LOG_TRACE("Didn't find data for " << interest->getName());
        // TODO: Send NACK?
      }
    }

    void
    onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
      _LOG_ERROR("AccessManagerV2: Failed to register prefix: " << *prefix);
    }

     ptr_lib::shared_ptr<Impl> parent_;
  };

  // We make a shared_ptr object since it needs to exist after we return, and
  // pass shared_from_this() to keep a pointer to this Impl.
  ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
    (shared_from_this());
  Name gckPrefix = Name(nacIdentityName_)
    .append(EncryptorV2::getNAME_COMPONENT_GCK());
  kdkRegisteredPrefixId_ = face_->registerPrefix
    (gckPrefix,
     bind(&Callbacks::onInterest, callbacks, _1, _2, _3, _4, _5),
     bind(&Callbacks::onRegisterFailed, callbacks, _1));
}

void
AccessManagerV2::Impl::initializeForKdk(const Name& dataset)
{
  // The NAC identity is: <identity>/NAC/<dataset>
  nacIdentityName_ = Name(identity_->getName())
    .append(EncryptorV2::getNAME_COMPONENT_NAC()).append(dataset);
  // Generate the NAC key.
  ptr_lib::shared_ptr<PibIdentity> nacIdentity = keyChain_->createIdentityV2
    (nacIdentityName_, RsaKeyParams());
  nacKey_ = nacIdentity->getDefaultKey();
  if (nacKey_->getKeyType() != KEY_TYPE_RSA) {
    _LOG_TRACE
      ("Cannot re-use existing KEK/KDK pair, as it is not an RSA key, regenerating");
    nacKey_ = keyChain_->createKey(*nacIdentity, RsaKeyParams());
  }
  Name::Component nacKeyId = nacKey_->getName().get(-1);

  Name kekPrefix = Name(nacKey_->getIdentityName())
    .append(EncryptorV2::getNAME_COMPONENT_KEK());

  Data kekData(*nacKey_->getDefaultCertificate());
  kekData.setName(Name(kekPrefix).append(nacKeyId));
  kekData.getMetaInfo().setFreshnessPeriod(DEFAULT_KEK_FRESHNESS_PERIOD);
  keyChain_->sign(kekData, SigningInfo(identity_));
  // A KEK looks like a certificate, but doesn't have a ValidityPeriod.
  storage_.insert(kekData);

  // Prepare the callbacks.
  class Callbacks {
  public:
    Callbacks(const ptr_lib::shared_ptr<Impl>& parent)
    : parent_(parent)
    {}

    void
    serveFromStorage
      (const ptr_lib::shared_ptr<const Name>& prefix,
       const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
       uint64_t interestFilterId,
       const ptr_lib::shared_ptr<const InterestFilter>& filter)
    {
      ptr_lib::shared_ptr<Data> data = parent_->storage_.find(*interest);
      if (data) {
        _LOG_TRACE("Serving " << data->getName() << " from InMemoryStorage");
        try {
          face.putData(*data);
        } catch (const std::exception& ex) {
          _LOG_ERROR("AccessManagerV2: Error in Face.putData: " << ex.what());
        }
      }
      else {
        _LOG_TRACE("Didn't find data for " << interest->getName());
        // TODO: Send NACK?
      }
    }

    void
    onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
    {
      _LOG_ERROR("AccessManagerV2: Failed to register prefix: " << *prefix);
    }

     ptr_lib::shared_ptr<Impl> parent_;
  };

  // We make a shared_ptr object since it needs to exist after we return, and
  // pass shared_from_this() to keep a pointer to this Impl.
  ptr_lib::shared_ptr<Callbacks> callbacks = ptr_lib::make_shared<Callbacks>
    (shared_from_this());
  kekRegisteredPrefixId_ = face_->registerPrefix
    (kekPrefix,
     bind(&Callbacks::serveFromStorage, callbacks, _1, _2, _3, _4, _5),
     bind(&Callbacks::onRegisterFailed, callbacks, _1));

  Name kdkPrefix = Name(nacKey_->getIdentityName())
    .append(EncryptorV2::getNAME_COMPONENT_KDK()).append(nacKeyId);
  kdkRegisteredPrefixId_ = face_->registerPrefix
    (kdkPrefix,
     bind(&Callbacks::serveFromStorage, callbacks, _1, _2, _3, _4, _5),
     bind(&Callbacks::onRegisterFailed, callbacks, _1));
}

void
AccessManagerV2::Impl::shutdown()
{
  face_->unsetInterestFilter(kekRegisteredPrefixId_);
  face_->unsetInterestFilter(kdkRegisteredPrefixId_);
}

void
AccessManagerV2::Impl::refreshGck()
{
  if (gckBits_.size() == 0)
    throw runtime_error("To use GCK, call the AccessManagerV2 constructor with a groupContentKeyAlgorithmType");

  gckName_ = Name(nacIdentityName_);
  gckName_.append(EncryptorV2::getNAME_COMPONENT_GCK());
  // The version is the ID of the GCK.
  gckName_.appendVersion((uint64_t)ndn_getNowMilliseconds());

  _LOG_TRACE("Generating new GCK: " << gckName_);
  ndn_Error error;
  if ((error = CryptoLite::generateRandomBytes(&gckBits_[0], gckBits_.size())))
    throw runtime_error(ndn_getErrorString(error));
}

ptr_lib::shared_ptr<Data>
AccessManagerV2::Impl::addMemberForGck(const CertificateV2& memberCertificate)
{
  RsaPublicKeyLite memberKey;
  if (memberKey.decode(memberCertificate.getPublicKey()) != NDN_ERROR_success)
    throw runtime_error("RsaPublicKeyLite: Error decoding public key");

  // TODO: use RSA_size, etc. to get the proper size of the output buffer.
  ptr_lib::shared_ptr<vector<uint8_t> > encryptedData(new vector<uint8_t>(1000));
  size_t encryptedDataLength;
  ndn_Error error;
  if ((error = memberKey.encrypt
#if 0 // See https://github.com/operantnetworks/ndn-ind/issues/13
       (&gckBits_[0], gckBits_.size(), ndn_EncryptAlgorithmType_RsaOaep,
#else
       (&gckBits_[0], gckBits_.size(), ndn_EncryptAlgorithmType_RsaPkcs,
#endif
        &encryptedData->front(), encryptedDataLength)))
    throw runtime_error("RsaAlgorithm: Error encrypting with public key");
  encryptedData->resize(encryptedDataLength);
  EncryptedContent encryptedContent;
  encryptedContent.setPayload(Blob(encryptedData, false));

  Name gckDataName(gckName_);
  gckDataName
    .append(EncryptorV2::getNAME_COMPONENT_ENCRYPTED_BY())
    .append(memberCertificate.getKeyName());
  ptr_lib::shared_ptr<Data> gckData = ptr_lib::make_shared<Data>(gckDataName);
  gckData->setContent(encryptedContent.wireEncodeV2());
  // FreshnessPeriod can serve as a soft access control for revoking access.
  gckData->getMetaInfo().setFreshnessPeriod(DEFAULT_KDK_FRESHNESS_PERIOD);
  keyChain_->sign(*gckData, SigningInfo(identity_));

  _LOG_TRACE("Ready to serve GCK Data packet " << gckData->getName());
  storage_.insert(*gckData);

  return gckData;
}

ptr_lib::shared_ptr<Data>
AccessManagerV2::Impl::addMemberForKdk(const CertificateV2& memberCertificate)
{
  Name kdkName(nacKey_->getIdentityName());
  kdkName
    .append(EncryptorV2::getNAME_COMPONENT_KDK())
    .append(nacKey_->getName().get(-1)) // key-id
    .append(EncryptorV2::getNAME_COMPONENT_ENCRYPTED_BY())
    .append(memberCertificate.getKeyName());

  const size_t secretLength = 32;
  uint8_t secret[secretLength];
  ndn_Error error;
  if ((error = CryptoLite::generateRandomBytes(secret, secretLength)))
    throw runtime_error(ndn_getErrorString(error));
  // To be compatible with OpenSSL which uses a null-terminated string,
  // replace each 0 with 1. And to be compatible with the Java security
  // library which interprets the secret as a char array converted to UTF8,
  // limit each byte to the ASCII range 1 to 127.
  for (int i = 0; i < secretLength; ++i) {
    if (secret[i] == 0)
      secret[i] = 1;

    secret[i] &= 0x7f;
  }

  ptr_lib::shared_ptr<SafeBag> kdkSafeBag = keyChain_->exportSafeBag
    (*nacKey_->getDefaultCertificate(), secret, secretLength);

  RsaPublicKeyLite memberKey;
  if (memberKey.decode(memberCertificate.getPublicKey()) != NDN_ERROR_success)
    throw runtime_error("RsaAlgorithm: Error decoding public key");

  // TODO: use RSA_size, etc. to get the proper size of the output buffer.
  ptr_lib::shared_ptr<vector<uint8_t> > encryptedData(new vector<uint8_t>(1000));
  size_t encryptedDataLength;
  if ((error = memberKey.encrypt
       (secret, secretLength, ndn_EncryptAlgorithmType_RsaOaep,
        &encryptedData->front(), encryptedDataLength)))
    throw runtime_error("AccessManagerV2: Error encrypting with public key");
  encryptedData->resize(encryptedDataLength);
  EncryptedContent encryptedContent;
  encryptedContent.setPayload(kdkSafeBag->wireEncode());
  encryptedContent.setPayloadKey(Blob(encryptedData, false));

  ptr_lib::shared_ptr<Data> kdkData = ptr_lib::make_shared<Data>(kdkName);
  kdkData->setContent(encryptedContent.wireEncodeV2());
  // FreshnessPeriod can serve as a soft access control for revoking access.
  kdkData->getMetaInfo().setFreshnessPeriod(DEFAULT_KDK_FRESHNESS_PERIOD);
  keyChain_->sign(*kdkData, SigningInfo(identity_));

  storage_.insert(*kdkData);

  return kdkData;
}

void
AccessManagerV2::Impl::publishGckLatestData(Face& face)
{
  Data data(Name(gckLatestPrefix_)
            .append(Name::Component::fromVersion((uint64_t)ndn_getNowMilliseconds())));
  data.getMetaInfo().setFreshnessPeriod(seconds(1));
  data.setContent(gckName_.wireEncode());
  keyChain_->sign(data, SigningInfo(identity_));

  _LOG_TRACE("Publish GCK _latest Data packet: " << data.getName() << ", contents: " << gckName_);
  face.putData(data);
}

}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/pib/detail/pib-key-impl.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/detail/key-impl.cpp
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

#include <ndn-ind/security/security-exception.hpp>
#include <ndn-ind/security/certificate/public-key.hpp>
#include <ndn-ind/security/pib/pib-impl.hpp>
#include <ndn-ind/security/pib/pib-key.hpp>
#include "pib-key-impl.hpp"

using namespace std;

namespace ndn_ind {

PibKeyImpl::PibKeyImpl
  (const Name& keyName, const uint8_t* keyEncoding, size_t keyEncodingLength,
   const ptr_lib::shared_ptr<PibImpl>& pibImpl)
: identityName_(PibKey::extractIdentityFromKeyName(keyName)),
  keyName_(keyName),
  keyEncoding_(keyEncoding, keyEncodingLength),
  certificates_(keyName, pibImpl),
  pibImpl_(pibImpl)
{
  if (!pibImpl)
    throw invalid_argument("The pibImpl is null");

  try {
    PublicKey publicKey(keyEncoding_);
    keyType_ = publicKey.getKeyType();
  } catch (UnrecognizedKeyFormatException&) {
    throw invalid_argument("Invalid key encoding");
  }

  pibImpl_->addKey
    (identityName_, keyName_, keyEncoding, keyEncodingLength);
}

PibKeyImpl::PibKeyImpl
  (const Name& keyName, const ptr_lib::shared_ptr<PibImpl>& pibImpl)
: identityName_(PibKey::extractIdentityFromKeyName(keyName)),
  keyName_(keyName),
  certificates_(keyName, pibImpl),
  pibImpl_(pibImpl)
{
  if (!pibImpl)
    throw runtime_error("The pibImpl is null");

  keyEncoding_ = pibImpl_->getKeyBits(keyName_);

  PublicKey publicKey(keyEncoding_);
  keyType_ = publicKey.getKeyType();
}

void
PibKeyImpl::addCertificate(const CertificateV2& certificate)
{
  // BOOST_ASSERT(certificates_.isConsistent());
  certificates_.add(certificate);
}

void
PibKeyImpl::removeCertificate(const Name& certificateName)
{
  // BOOST_ASSERT(certificates_.isConsistent());

  if (defaultCertificate_ && defaultCertificate_->getName() == certificateName)
    defaultCertificate_.reset();

  certificates_.remove(certificateName);
}

ptr_lib::shared_ptr<CertificateV2>
PibKeyImpl::getCertificate(const Name& certificateName)
{
  // BOOST_ASSERT(certificates_.isConsistent());
  return certificates_.get(certificateName);
}

ptr_lib::shared_ptr<CertificateV2>&
PibKeyImpl::setDefaultCertificate(const Name& certificateName)
{
  // BOOST_ASSERT(certificates_.isConsistent());

  defaultCertificate_ = certificates_.get(certificateName);
  pibImpl_->setDefaultCertificateOfKey(keyName_, certificateName);
  return defaultCertificate_;
}

ptr_lib::shared_ptr<CertificateV2>&
PibKeyImpl::getDefaultCertificate()
{
  // BOOST_ASSERT(certificates_.isConsistent());

  if (!defaultCertificate_)
    defaultCertificate_ = pibImpl_->getDefaultCertificateOfKey(keyName_);

  // BOOST_ASSERT(pibImpl_->getDefaultCertificateOfKey(keyName_)->wireEncode() == defaultCertificate_->wireEncode());

  return defaultCertificate_;
}

}

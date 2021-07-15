/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/pib/detail/pib-identity-impl.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/detail/identity-impl.cpp
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

#include <ndn-ind/security/pib/pib-impl.hpp>
#include "pib-identity-impl.hpp"

using namespace std;

namespace ndn_ind {

PibIdentityImpl::PibIdentityImpl
  (const Name& identityName, const ptr_lib::shared_ptr<PibImpl>& pibImpl,
   bool needInit)
: identityName_(identityName),
  keys_(identityName, pibImpl),
  pibImpl_(pibImpl)
{
  if (!pibImpl)
    throw invalid_argument("The pibImpl is null");

  if (needInit)
    pibImpl_->addIdentity(identityName_);
  else {
    if (!pibImpl_->hasIdentity(identityName_))
      throw Pib::Error("Identity " + identityName_.toUri() + " does not exist");
  }
}

ptr_lib::shared_ptr<PibKey>
PibIdentityImpl::addKey
  (const uint8_t* key, size_t keyLength, const Name& keyName)
{
  // BOOST_ASSERT(keys_.isConsistent());

  return keys_.add(key, keyLength, keyName);
}

void
PibIdentityImpl::removeKey(const Name& keyName)
{
  // BOOST_ASSERT(keys_.isConsistent());

  if (defaultKey_ && defaultKey_->getName() == keyName)
    defaultKey_.reset();

  keys_.remove(keyName);
}

ptr_lib::shared_ptr<PibKey>
PibIdentityImpl::getKey(const Name& keyName)
{
  // BOOST_ASSERT(keys_.isConsistent());

  return keys_.get(keyName);
}

ptr_lib::shared_ptr<PibKey>&
PibIdentityImpl::setDefaultKey(const Name& keyName)
{
  // BOOST_ASSERT(keys_.isConsistent());

  defaultKey_ = keys_.get(keyName);
  pibImpl_->setDefaultKeyOfIdentity(identityName_, keyName);
  return defaultKey_;
}

ptr_lib::shared_ptr<PibKey>&
PibIdentityImpl::setDefaultKey
  (const uint8_t* key, size_t keyLength, const Name& keyName)
{
  addKey(key, keyLength, keyName);
  return setDefaultKey(keyName);
}

ptr_lib::shared_ptr<PibKey>&
PibIdentityImpl::getDefaultKey()
{
  // BOOST_ASSERT(keys_.isConsistent());

  if (!defaultKey_)
    defaultKey_ = keys_.get(pibImpl_->getDefaultKeyOfIdentity(identityName_));

  // BOOST_ASSERT(pibImpl_->getDefaultKeyOfIdentity(identityName_) == defaultKey_.getName());

  return defaultKey_;
}

}

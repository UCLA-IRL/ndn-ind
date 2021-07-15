/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/validator-fixture.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/validator-fixture.hpp
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

#ifndef NDN_VALIDATOR_FIXTURE_HPP
#define NDN_VALIDATOR_FIXTURE_HPP

#include <ndn-ind/security/v2/validator.hpp>
#include <ndn-ind/security/v2/certificate-fetcher-from-network.hpp>
#include "identity-management-fixture.hpp"

/**
 * ValidatorFixture extends IdentityManagementFixture to use the given policy
 * and to set up a test face to answer Interests.
 */
class ValidatorFixture : public IdentityManagementFixture
{
public:
  /**
   * Create a ValidatorFixture to use the given policy. Set the default
   * face_.processInterest_ to use the cache_ to respond to expressInterest. To
   * change this behavior, you can set face_.processInterest_ to your callback,
   * or to null to always time out.
   * @param policy The ValidationPolicy used by validator_.
   */
  ValidatorFixture(const ndn_ind::ptr_lib::shared_ptr<ndn_ind::ValidationPolicy>& policy);

  /**
   * TestFace extends Face to instantly simulate a call to expressInterest.
   * See expressInterest for details.
   */
  class TestFace : public ndn_ind::Face {
  public:
    typedef ndn_ind::func_lib::function<void
      (const ndn_ind::Interest& interest, const ndn_ind::OnData& onData,
       const ndn_ind::OnTimeout& onTimeout, const ndn_ind::OnNetworkNack& onNetworkNack)>
      ProcessInterest;

    TestFace()
    : Face("localhost")
    {}

    /**
     * If processInterest_ is not null, call
     * processInterest_(interest, onData, onTimeout, onNetworkNack) which must
     * call one of the callbacks to simulate the response. Otherwise, just call
     * onTimeout(interest) to simulate a timeout. This adds the interest to
     * sentInterests_ .
     */
    virtual uint64_t
    expressInterest
      (const ndn_ind::Interest& interest, const ndn_ind::OnData& onData,
       const ndn_ind::OnTimeout& onTimeout, const ndn_ind::OnNetworkNack& onNetworkNack,
       ndn_ind::WireFormat& wireFormat = *ndn_ind::WireFormat::getDefaultWireFormat());

    ProcessInterest processInterest_;
    std::vector<ndn_ind::Interest> sentInterests_;
  };

  void
  processInterestFromCache
    (const ndn_ind::Interest& interest, const ndn_ind::OnData& onData,
     const ndn_ind::OnTimeout& onTimeout, const ndn_ind::OnNetworkNack& onNetworkNack);

  TestFace face_;
  ndn_ind::Validator validator_;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::ValidationPolicy> policy_;
  ndn_ind::CertificateCacheV2 cache_;
};

class HierarchicalValidatorFixture : public ValidatorFixture {
public:
  HierarchicalValidatorFixture
    (const ndn_ind::ptr_lib::shared_ptr<ndn_ind::ValidationPolicy>& policy)
  : ValidatorFixture(policy)
  {
    identity_ = addIdentity("/Security/V2/ValidatorFixture");
    subIdentity_ = addSubCertificate("/Security/V2/ValidatorFixture/Sub1", identity_);
    subSelfSignedIdentity_ = addIdentity("/Security/V2/ValidatorFixture/Sub1/Sub2");
    otherIdentity_ = addIdentity("/Security/V2/OtherIdentity");

    validator_.loadAnchor
      ("", ndn_ind::CertificateV2(*identity_->getDefaultKey()->getDefaultCertificate()));

    cache_.insert(*identity_->getDefaultKey()->getDefaultCertificate());
    cache_.insert(*subIdentity_->getDefaultKey()->getDefaultCertificate());
    cache_.insert(*subSelfSignedIdentity_->getDefaultKey()->getDefaultCertificate());
    cache_.insert(*otherIdentity_->getDefaultKey()->getDefaultCertificate());
  }

  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity> identity_;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity> subIdentity_;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity> subSelfSignedIdentity_;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity> otherIdentity_;
};

#endif

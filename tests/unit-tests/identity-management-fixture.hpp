/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/identity-management-fixture.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/identity-management-fixture.hpp
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

#ifndef NDN_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NDN_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include <set>
#include <ndn-ind/security/key-chain.hpp>

class IdentityManagementFixture
{
public:
  IdentityManagementFixture()
  : keyChain_("pib-memory:", "tpm-memory:")
  {
  }

  ~IdentityManagementFixture();

  bool
  saveCertificateToFile(const ndn_ind::Data& data, const std::string& filePath);

  /**
   * Add an identity for the identityName.
   * @param identityName The name of the identity.
   * @param params (optional) The key parameters if a key needs to be generated
   * for the identity. If omitted, use getDefaultKeyParams().
   * @return The created PibIdentity instance.
   */
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity>
  addIdentity
    (const ndn_ind::Name& identityName,
     const ndn_ind::KeyParams& params = ndn_ind::KeyChain::getDefaultKeyParams());

  /**
   *  Save the identity's certificate to a file.
   *  @param identity The PibIdentity.
   *  @param filePath The file path, which should be writable.
   *  @return True if successful.
   */
  bool
  saveCertificate(ndn_ind::PibIdentity identity, const std::string& filePath);

  /**
   * Issue a certificate for subIdentityName signed by issuer. If the identity
   * does not exist, it is created. A new key is generated as the default key
   * for the identity. A default certificate for the key is signed by the
   * issuer using its default certificate.
   * @param subIdentityName The name to issue the certificate for.
   * @param issuer The identity of the signer.
   * @param params (optional) The key parameters if a key needs to be generated
   * for the identity. If omitted, use getDefaultKeyParams().
   * @return The sub identity.
   */
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity>
  addSubCertificate
    (const ndn_ind::Name& subIdentityName,
     const ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibIdentity>& issuer,
     const ndn_ind::KeyParams& params = ndn_ind::KeyChain::getDefaultKeyParams());

  /**
   * Add a self-signed certificate made from the key and issuer ID.
   * @param key The key for the certificate.
   * @param issuerId The issuer ID name component for the certificate name.
   * @return The new certificate.
   */
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2>
  addCertificate
    (ndn_ind::ptr_lib::shared_ptr<ndn_ind::PibKey>& key, const std::string& issuerId);

  ndn_ind::KeyChain keyChain_;

private:
  std::set<ndn_ind::Name> identityNames_;
  std::set<std::string> certificateFiles_;
};


#endif

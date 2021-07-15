/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/pib-data-fixture.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/pib-data-fixture.hpp
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

#ifndef NDN_PIB_DATA_FIXTURE_HPP
#define NDN_PIB_DATA_FIXTURE_HPP

#include <ndn-ind/security/pib/pib-impl.hpp>

class PibDataFixture
{
public:
  PibDataFixture();

  ndn_ind::PibImpl *pib;

  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id1Key1Cert1;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id1Key1Cert2;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id1Key2Cert1;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id1Key2Cert2;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id2Key1Cert1;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id2Key1Cert2;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id2Key2Cert1;
  ndn_ind::ptr_lib::shared_ptr<ndn_ind::CertificateV2> id2Key2Cert2;

  ndn_ind::Name id1;
  ndn_ind::Name id2;

  ndn_ind::Name id1Key1Name;
  ndn_ind::Name id1Key2Name;
  ndn_ind::Name id2Key1Name;
  ndn_ind::Name id2Key2Name;

  ndn_ind::Blob id1Key1;
  ndn_ind::Blob id1Key2;
  ndn_ind::Blob id2Key1;
  ndn_ind::Blob id2Key2;
};


#endif

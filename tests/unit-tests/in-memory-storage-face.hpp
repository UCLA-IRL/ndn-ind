/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/in-memory-storage-face.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
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

#ifndef NDN_IN_MEMORY_STORAGE_FACE_HPP
#define NDN_IN_MEMORY_STORAGE_FACE_HPP

#include <ndn-ind/face.hpp>
#include <ndn-ind/in-memory-storage/in-memory-storage-retaining.hpp>
#include "../../src/impl/interest-filter-table.hpp"
#include "../../src/impl/delayed-call-table.hpp"

/**
 * InMemoryStorageFace extends Face to hold an InMemoryStorageRetaining and
 * use it in expressInterest to instantly reply to an Interest. It also allows
 * calls to registerPrefix to remember an OnInterestCallback. This also keeps a
 * local DelayedCallTable (to use for callLater) so that you can call its
 * setNowOffset_ for testing.
 */
class InMemoryStorageFace : public ndn_ind::Face
{
public:
  InMemoryStorageFace(ndn_ind::InMemoryStorageRetaining* storage)
  : Face("localhost"), storage_(storage)
  {
  }

  virtual uint64_t
  expressInterest
    (const ndn_ind::Interest& interest, const ndn_ind::OnData& onData,
     const ndn_ind::OnTimeout& onTimeout, const ndn_ind::OnNetworkNack& onNetworkNack,
     ndn_ind::WireFormat& wireFormat = *ndn_ind::WireFormat::getDefaultWireFormat());

  virtual uint64_t
  registerPrefix
    (const ndn_ind::Name& prefix, const ndn_ind::OnInterestCallback& onInterest,
     const ndn_ind::OnRegisterFailed& onRegisterFailed,
     const ndn_ind::OnRegisterSuccess& onRegisterSuccess,
     const ndn_ind::RegistrationOptions& registrationOptions = ndn_ind::RegistrationOptions(),
     ndn_ind::WireFormat& wireFormat = *ndn_ind::WireFormat::getDefaultWireFormat());

  virtual void
  putData
    (const ndn_ind::Data& data,
     ndn_ind::WireFormat& wireFormat = *ndn_ind::WireFormat::getDefaultWireFormat());

  virtual void
  callLater
    (std::chrono::nanoseconds delay, const ndn_ind::Face::Callback& callback);

  virtual void
  processEvents();

  /**
   * For each entry from calls to registerPrefix where the Interest matches the
   * prefix, call its OnInterest callback.
   * @param interest The Interest to receive and possibly call the
   * OnInterest callback.
   */
  void
  receive(const ndn_ind::ptr_lib::shared_ptr<ndn_ind::Interest> interest);

  std::vector<ndn_ind::ptr_lib::shared_ptr<ndn_ind::Interest> > sentInterests_;
  std::vector<ndn_ind::ptr_lib::shared_ptr<ndn_ind::Data> > sentData_;
  // Use delayedCallTable_ here so that we can call setNowOffset_().
  ndn_ind::DelayedCallTable delayedCallTable_;

private:
  ndn_ind::InterestFilterTable interestFilterTable_;
  ndn_ind::InMemoryStorageRetaining* storage_;
};

#endif

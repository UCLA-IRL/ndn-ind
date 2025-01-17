/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/security/v2/validation-policy-from-pib.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
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

#ifndef NDN_VALIDATION_POLICY_FROM_PIB_HPP
#define NDN_VALIDATION_POLICY_FROM_PIB_HPP

#include "../pib/pib.hpp"
#include "validation-policy.hpp"

namespace ndn_ind {

/**
 * ValidationPolicyFromPib extends ValidationPolicy to implement a validator
 * policy that validates a packet using the default certificate of the key in
 * the PIB that is named by the packet's KeyLocator.
 */
class ndn_ind_dll ValidationPolicyFromPib : public ValidationPolicy {
public:
  /**
   * Create a ValidationPolicyFromPib to use the given PIB.
   * @param pib The PIB with certificates.
   */
  ValidationPolicyFromPib(Pib& pib)
  : pib_(pib)
  {
  }

  virtual void
  checkPolicy
    (const Data& data, const ptr_lib::shared_ptr<ValidationState>& state,
     const ValidationContinuation& continueValidation);

  virtual void
  checkPolicy
    (const Interest& interest, const ptr_lib::shared_ptr<ValidationState>& state,
     const ValidationContinuation& continueValidation);

private:
  void
  checkPolicyHelper
    (const Name& keyName, const ptr_lib::shared_ptr<ValidationState>& state,
     const ValidationContinuation& continueValidation);

  Pib& pib_;
};

}

#endif

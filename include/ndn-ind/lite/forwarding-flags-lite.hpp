/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/lite/forwarding-flags-lite.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Support ndn_ind_dll.
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

#ifndef NDN_FORWARDING_FLAGS_LITE_HPP
#define NDN_FORWARDING_FLAGS_LITE_HPP

#include "registration-options-lite.hpp"

namespace ndn_ind {

/**
 * @deprecated Use RegistrationOptionsLite.
 */
class ndn_ind_dll ForwardingFlagsLite : public RegistrationOptionsLite {
public:
  /**
   * Create a ForwardingFlagsLite with "childInherit" set and all other flags
   * cleared.
   */
  DEPRECATED_IN_NDN_IND ForwardingFlagsLite() {}

  /**
   * Downcast the reference to the ndn_RegistrationOptions struct to a
   * ForwardingFlagsLite.
   * @param registrationOptions A reference to the ndn_RegistrationOptions struct.
   * @return The same reference as ForwardingFlagsLite.
   */
  static ForwardingFlagsLite&
  DEPRECATED_IN_NDN_IND downCast(ndn_RegistrationOptions& registrationOptions)
  {
    return *(ForwardingFlagsLite*)&registrationOptions;
  }

  static const ForwardingFlagsLite&
  DEPRECATED_IN_NDN_IND downCast(const ndn_RegistrationOptions& registrationOptions)
  {
    return *(ForwardingFlagsLite*)&registrationOptions;
  }
};

}

#endif

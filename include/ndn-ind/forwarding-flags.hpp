/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/forwarding-flags.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2013-2020 Regents of the University of California.
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

#ifndef NDN_FORWARDING_FLAGS_HPP
#define NDN_FORWARDING_FLAGS_HPP

#include "registration-options.hpp"

namespace ndn_ind {

/**
 * @deprecated Use RegistrationOptions.
 */
class ndn_ind_dll ForwardingFlags : public RegistrationOptions {
public:
  /**
   * Create a new ForwardingFlags with "childInherit" set and all other flags cleared.
   * @deprecated Use RegistrationOptions.
   */
  DEPRECATED_IN_NDN_IND ForwardingFlags() {}
};

}

#endif

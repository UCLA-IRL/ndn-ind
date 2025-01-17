/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/encoding/tlv-0_1_1-wire-format.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
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

#ifndef NDN_TLV_0_1_1_WIRE_FORMAT_HPP
#define NDN_TLV_0_1_1_WIRE_FORMAT_HPP

#include "tlv-0_2-wire-format.hpp"

namespace ndn_ind {

/**
 * A Tlv0_1_1WireFormat extends Tlv0_2WireFormat so that it is an alias in case
 * any applications use Tlv0_1_1WireFormat directly.  These two wire formats are
 * the same except that Tlv0_2WireFormat adds support for the name component
 * type ImplicitSha256Digest.
 */
class ndn_ind_dll Tlv0_1_1WireFormat : public Tlv0_2WireFormat {
public:
  /**
   * Get a singleton instance of a Tlv0_1_1WireFormat.
   * @return A pointer to the singleton instance.
   */
  static Tlv0_1_1WireFormat*
  get()
  {
    if (!instance_)
      instance_ = new Tlv0_1_1WireFormat();

    return instance_;
  }

private:
  static Tlv0_1_1WireFormat* instance_;
};

}

#endif

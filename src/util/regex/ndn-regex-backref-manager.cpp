/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/util/regex/ndn-regex-backref-manager.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
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

#include "ndn-regex-matcher-base.hpp"
// Only compile if we set NDN_IND_HAVE_REGEX_LIB in ndn-regex-matcher-base.hpp.
#if NDN_IND_HAVE_REGEX_LIB

#include <stdexcept>
#include "ndn-regex-backref-manager.hpp"

using namespace std;

namespace ndn_ind {

ptr_lib::shared_ptr<NdnRegexMatcherBase>
NdnRegexBackrefManager::getBackref(size_t i) const
{
  ptr_lib::shared_ptr<NdnRegexMatcherBase> backref = backrefs_[i].lock();
  if (!backref)
    throw runtime_error("getBackref: lock returned a null object");
  return backref;
}

}

#endif // NDN_IND_HAVE_REGEX_LIB

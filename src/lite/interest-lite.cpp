/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/lite/interest-lite.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
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

#include "../c/interest.h"
#include <ndn-ind/lite/interest-lite.hpp>

namespace ndn_ind {

InterestLite::InterestLite
  (ndn_NameComponent *nameComponents, size_t maxNameComponents,
   ndn_ExcludeEntry *excludeEntries, size_t maxExcludeEntries,
   ndn_NameComponent *keyNameComponents, size_t maxKeyNameComponents)
{
  ndn_Interest_initialize
  (this, nameComponents, maxNameComponents, excludeEntries, maxExcludeEntries,
   keyNameComponents, maxKeyNameComponents);
}

bool
InterestLite::getDefaultCanBePrefix()
{
  return ndn_Interest_getDefaultCanBePrefix() != 0;
}

void
InterestLite::setDefaultCanBePrefix(bool defaultCanBePrefix)
{
  ndn_Interest_setDefaultCanBePrefix(defaultCanBePrefix ? 1 : 0);
}

bool
InterestLite::getCanBePrefix() const
{
  return ndn_Interest_getCanBePrefix(this) != 0;
}

bool
InterestLite::getMustBeFresh() const
{
  return ndn_Interest_getMustBeFresh(this) != 0;
}

bool
InterestLite::hasApplicationParameters() const
{
  return ndn_Interest_hasApplicationParameters(this) != 0;
}

InterestLite&
InterestLite::setCanBePrefix(bool canBePrefix)
{
  ndn_Interest_setCanBePrefix(this, canBePrefix ? 1 : 0);
  return *this;
}

InterestLite&
InterestLite::setMustBeFresh(bool mustBeFresh)
{
  ndn_Interest_setMustBeFresh(this, mustBeFresh ? 1 : 0);
  return *this;
}

ndn_Error
InterestLite::set(const InterestLite& other)
{
  return ndn_Interest_setFromInterest(this, &other);
}

}

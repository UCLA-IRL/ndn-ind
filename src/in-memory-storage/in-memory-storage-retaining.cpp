/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/in-memory-storage/in-memory-storage-retaining.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/ims/in-memory-storage-persistent.cpp
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

#include <ndn-ind/in-memory-storage/in-memory-storage-retaining.hpp>

using namespace std;

namespace ndn_ind {

ptr_lib::shared_ptr<Data>
InMemoryStorageRetaining::find(const Name& name)
{
  for (map<Name, ptr_lib::shared_ptr<Data> >::iterator i = cache_.begin();
       i != cache_.end(); ++i) {
    if (name.isPrefixOf(i->first))
      return i->second;
  }

  return ptr_lib::shared_ptr<Data>();
}

void
InMemoryStorageRetaining::remove(const Name& prefix)
{
  // The Name keys are in order.
  map<Name, ptr_lib::shared_ptr<Data> >::const_iterator it = cache_.lower_bound(prefix);
  while (it != cache_.end() && prefix.isPrefixOf(it->first))
    cache_.erase(it++);
}

}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/impl/delayed-call-table.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2016-2020 Regents of the University of California.
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

#include <algorithm>
#include "../c/util/time.h"
#include "delayed-call-table.hpp"

using namespace std;
using namespace std::chrono;

namespace ndn_ind {

void
DelayedCallTable::callLater
  (nanoseconds delay, const Face::Callback& callback)
{
  ptr_lib::shared_ptr<Entry> entry(new Entry(delay, callback));
  // Insert into table_, sorted on getCallTime().
  table_.insert
    (lower_bound(table_.begin(), table_.end(), entry, entryCompare_), entry);
}

void
DelayedCallTable::callTimedOut()
{
  // nowOffset_ is only used for testing.
  auto now = system_clock::now() + duration_cast<system_clock::duration>(nowOffset_);
  // table_ is sorted on _callTime, so we only need to process the timed-out
  // entries at the front, then quit.
  while (table_.size() > 0 && table_.front()->getCallTime() <= now) {
    ptr_lib::shared_ptr<Entry> entry = table_.front();
    table_.erase(table_.begin());
    entry->callCallback();
  }
}

DelayedCallTable::Entry::Entry
  (nanoseconds delay, const Face::Callback& callback)
  : callback_(callback),
    callTime_(system_clock::now() + duration_cast<system_clock::duration>(delay))
{
}

}

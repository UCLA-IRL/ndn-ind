/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
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

#ifndef NDN_DELAYED_CALL_TABLE_HPP
#define NDN_DELAYED_CALL_TABLE_HPP

#include <deque>
#include <ndn-ind/face.hpp>

namespace ndn {

class DelayedCallTable {
public:
  DelayedCallTable()
  : nowOffsetMilliseconds_(0)
  {}

  /**
   * Call callback() after the given delay. This adds to the delayed call
   * table which is used by callTimedOut().
   * @param delay The delay.
   * @param callback This calls callback() after the delay.
   */
  void
  callLater(std::chrono::nanoseconds delay, const Face::Callback& callback);

  /**
   * Call and remove timed-out callback entries. Since callLater does a sorted
   * insert into the delayed call table, the check for timed-out entries is
   * quick and does not require searching the entire table.
   */
  void
  callTimedOut();

  /**
   * Set the offset when insert() and refresh() get the current time, which
   * should only be used for testing.
   * @param nowOffsetMilliseconds The offset in milliseconds.
   */
  void
  setNowOffsetMilliseconds_(Milliseconds nowOffsetMilliseconds)
  {
    nowOffsetMilliseconds_ = nowOffsetMilliseconds;
  }

private:
  class Entry {
  public:
    /**
     * Create a new DelayedCallTable::Entry and set the call time based on the
     * current time and the delay.
     * @param delay The delay.
     * @param callback This calls callback() after the delay.
     */
    Entry(std::chrono::nanoseconds delay, const Face::Callback& callback);

    /**
     * Get the time at which the callback should be called.
     * @return The call time.
     */
    std::chrono::system_clock::time_point
    getCallTime() const { return callTime_; }

    /**
     * Call the callback given to the constructor. This does not catch
     * exceptions.
     */
    void
    callCallback() const { callback_(); }

    /**
     * Compare shared_ptrs to Entry based only on callTime_.
     */
    class Compare {
    public:
      bool
      operator()
        (const ptr_lib::shared_ptr<const Entry>& x,
         const ptr_lib::shared_ptr<const Entry>& y) const
      {
        return x->callTime_ < y->callTime_;
      }
    };

  private:
    const Face::Callback callback_;
    std::chrono::system_clock::time_point callTime_;
  };

  // Use a deque so we can efficiently remove from the front.
  std::deque<ptr_lib::shared_ptr<Entry> > table_;
  Entry::Compare entryCompare_;
  Milliseconds nowOffsetMilliseconds_;
};

}

#endif

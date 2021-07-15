/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/util/scheduler.hpp
 * Original repository: https://github.com/named-data/ndn-cxx
 *
 * Summary of Changes: Use ndn-ind includes and namespace. Use std::chrono and shared_ptr.
 *   Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (c) 2013-2020 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST_ASIO.
#include "../ndn-ind-config.h"
#ifdef NDN_IND_HAVE_BOOST_ASIO

#ifndef NDN_UTIL_SCHEDULER_HPP
#define NDN_UTIL_SCHEDULER_HPP

#include <memory>
#include "impl/asio-fwd.hpp"
#include "impl/cancel-handle.hpp"
#include "impl/monotonic_steady_clock.hpp"

#include <boost/system/error_code.hpp>
#include <boost/noncopyable.hpp>
#include <set>

namespace ndn_ind {

namespace scheduler {

class SteadyTimer;
class Scheduler;
class EventInfo;

/** \brief Function to be invoked when a scheduled event expires
 */
using EventCallback = std::function<void()>;

/** \brief A handle of scheduled event.
 *
 *  \code
 *  EventId eid = scheduler.schedule(10_ms, [] { doSomething(); });
 *  eid.cancel(); // cancel the event
 *  \endcode
 *
 *  \note Canceling an expired (executed) or canceled event has no effect.
 *  \warning Canceling an event after the scheduler has been destructed may trigger undefined
 *           behavior.
 */
class ndn_ind_dll EventId : public CancelHandle
{
public:
  /** \brief Constructs an empty EventId
   */
  EventId() noexcept = default;

  /** \brief Determine whether the event is valid.
   *  \retval true The event is valid.
   *  \retval false This EventId is empty, or the event is expired or cancelled.
   */
  explicit
  operator bool() const noexcept;

  /** \brief Determine whether this and other refer to the same event, or are both
   *         empty/expired/cancelled.
   */
  bool
  operator==(const EventId& other) const noexcept;

  bool
  operator!=(const EventId& other) const noexcept
  {
    return !this->operator==(other);
  }

  /** \brief Clear this EventId without canceling.
   *  \post !(*this)
   */
  void
  reset() noexcept;

private:
  EventId(Scheduler& sched, std::weak_ptr<EventInfo> info);

private:
  std::weak_ptr<EventInfo> m_info;

  friend class Scheduler;
  friend std::ostream& operator<<(std::ostream& os, const EventId& eventId);
};

std::ostream&
operator<<(std::ostream& os, const EventId& eventId);

/** \brief A scoped handle of scheduled event.
 *
 *  Upon destruction of this handle, the event is canceled automatically.
 *  Most commonly, the application keeps a ScopedEventId as a class member field, so that it can
 *  cleanup its event when the class instance is destructed.
 *
 *  \code
 *  {
 *    ScopedEventId eid = scheduler.schedule(10_ms, [] { doSomething(); });
 *  } // eid goes out of scope, canceling the event
 *  \endcode
 *
 *  \note Canceling an expired (executed) or canceled event has no effect.
 *  \warning Canceling an event after the scheduler has been destructed may trigger undefined
 *           behavior.
 */
class ndn_ind_dll ScopedEventId : public ScopedCancelHandle
{
public:
  using ScopedCancelHandle::ScopedCancelHandle;

  ScopedEventId() noexcept = default;
};

/** \brief Generic time-based scheduler
 */
class ndn_ind_dll Scheduler : boost::noncopyable
{
public:
  explicit
  Scheduler(boost::asio::io_service& ioService);

  ~Scheduler();

  /** \brief Schedule a one-time event after the specified delay
   *  \return EventId that can be used to cancel the scheduled event
   */
  EventId
  schedule(std::chrono::nanoseconds after, EventCallback callback);

  /** \brief Cancel all scheduled events
   */
  void
  cancelAllEvents();

private:
  void
  cancelImpl(const std::shared_ptr<EventInfo>& info);

  /** \brief Schedule the next event on the internal timer
   */
  void
  scheduleNext();

  /** \brief Execute expired events
   *
   *  If an event callback throws, the exception is propagated to the thread running the io_service.
   *  In case there are other expired events, they will be processed in the next invocation.
   */
  void
  executeEvent(const boost::system::error_code& code);

private:
  class EventQueueCompare
  {
  public:
    bool
    operator()(const std::shared_ptr<EventInfo>& a, const std::shared_ptr<EventInfo>& b) const noexcept;
  };

  using EventQueue = std::multiset<std::shared_ptr<EventInfo>, EventQueueCompare>;
  EventQueue m_queue;

  std::unique_ptr<SteadyTimer> m_timer;
  bool m_isEventExecuting = false;

  friend EventId;
  friend EventInfo;
};

} // namespace scheduler

} // namespace ndn_ind

#endif // NDN_UTIL_SCHEDULER_HPP

#endif // NDN_IND_HAVE_BOOST_ASIO

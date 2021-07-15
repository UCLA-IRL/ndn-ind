/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/threadsafe-face.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
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

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST_ASIO.
#include <ndn-ind/ndn-ind-config.h>
#ifdef NDN_IND_HAVE_BOOST_ASIO

#include <boost/bind.hpp>
#include <boost/move/make_unique.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>
#include <ndn-ind/transport/async-tcp-transport.hpp>
#include <ndn-ind/transport/async-unix-transport.hpp>
#include <ndn-ind/threadsafe-face.hpp>
#include "node.hpp"

using namespace std;
using namespace std::chrono;

namespace ndn_ind {

ptr_lib::shared_ptr<Transport>
ThreadsafeFace::getDefaultTransport(boost::asio::io_service& ioService)
{
  if (getUnixSocketFilePathForLocalhost() == "")
    return ptr_lib::make_shared<AsyncTcpTransport>(ioService);
  else
    return ptr_lib::make_shared<AsyncUnixTransport>(ioService);
}

ptr_lib::shared_ptr<Transport::ConnectionInfo>
ThreadsafeFace::getDefaultConnectionInfo()
{
  string filePath = getUnixSocketFilePathForLocalhost();
  if (filePath == "")
    return ptr_lib::make_shared<AsyncTcpTransport::ConnectionInfo>("localhost");
  else
    return ptr_lib::shared_ptr<AsyncUnixTransport::ConnectionInfo>
      (new AsyncUnixTransport::ConnectionInfo(filePath.c_str()));
}

ThreadsafeFace::ThreadsafeFace
  (boost::asio::io_service& ioService,
   const ptr_lib::shared_ptr<Transport>& transport,
   const ptr_lib::shared_ptr<const Transport::ConnectionInfo>& connectionInfo)
  : Face(transport, connectionInfo), ioService_(ioService)
{
}


ThreadsafeFace::ThreadsafeFace
  (boost::asio::io_service& ioService, const char *host, unsigned short port)
  : Face(ptr_lib::make_shared<AsyncTcpTransport>(ioService),
         ptr_lib::make_shared<AsyncTcpTransport::ConnectionInfo>(host, port)),
    ioService_(ioService)
{
}

ThreadsafeFace::ThreadsafeFace(boost::asio::io_service& ioService)
  : Face(getDefaultTransport(ioService), getDefaultConnectionInfo()),
    ioService_(ioService)
{
}

ThreadsafeFace::ThreadsafeFace()
    // Pass in a default transport. We will reset it below.
  : Face(ptr_lib::make_shared<TcpTransport>(),
         ptr_lib::make_shared<TcpTransport::ConnectionInfo>("unused")),
    internalIoService_(boost::movelib::make_unique<boost::asio::io_service>()),
    ioService_(*internalIoService_)
{
  // Now reset the Node using the internalIoService_ .
  delete node_;
  node_ = new Node
    (getDefaultTransport(ioService_), getDefaultConnectionInfo());
}

uint64_t
ThreadsafeFace::expressInterest
  (const Interest& interest, const OnData& onData, const OnTimeout& onTimeout,
   const OnNetworkNack& onNetworkNack, WireFormat& wireFormat)
{
  // Node.lastEntryId_ uses atomic_uint64_t, so this call is thread safe.
  uint64_t pendingInterestId = node_->getNextEntryId();

  // This copies the interest as required by Node.expressInterest.
  ioService_.dispatch
    (boost::bind
     (&Node::expressInterest, node_, pendingInterestId,
      ptr_lib::make_shared<const Interest>(interest), onData, onTimeout,
      onNetworkNack, boost::ref(wireFormat), this));

  return pendingInterestId;
}

uint64_t
ThreadsafeFace::expressInterest
  (const Name& name, const Interest *interestTemplate, const OnData& onData,
   const OnTimeout& onTimeout, const OnNetworkNack& onNetworkNack,
   WireFormat& wireFormat)
{
  // Node.lastEntryId_ uses atomic_uint64_t, so this call is thread safe.
  uint64_t pendingInterestId = node_->getNextEntryId();

  // This copies the name object as required by Node.expressInterest.
  ioService_.dispatch
    (boost::bind
     (&Node::expressInterest, node_, pendingInterestId,
      getInterestCopy(name, interestTemplate), onData, onTimeout, onNetworkNack,
      boost::ref(wireFormat), this));

  return pendingInterestId;
}

void
ThreadsafeFace::removePendingInterest(uint64_t pendingInterestId)
{
  ioService_.dispatch
    (boost::bind(&Node::removePendingInterest, node_, pendingInterestId));
}

uint64_t
ThreadsafeFace::registerPrefix
  (const Name& prefix, const OnInterestCallback& onInterest,
   const OnRegisterFailed& onRegisterFailed,
   const OnRegisterSuccess& onRegisterSuccess,
   const RegistrationOptions& registrationOptions, WireFormat& wireFormat)
{
  // Node.lastEntryId_ uses atomic_uint64_t, so this call is thread safe.
  uint64_t registeredPrefixId = node_->getNextEntryId();

  // This copies the prefix object as required by Node.registerPrefix.
  ioService_.dispatch
    (boost::bind
     (&Node::registerPrefix, node_, registeredPrefixId,
      ptr_lib::make_shared<const Name>(prefix), onInterest, onRegisterFailed,
      onRegisterSuccess, registrationOptions, boost::ref(wireFormat), this));

  return registeredPrefixId;
}

void
ThreadsafeFace::removeRegisteredPrefix(uint64_t registeredPrefixId)
{
  ioService_.dispatch
    (boost::bind(&Node::removeRegisteredPrefix, node_, registeredPrefixId));
}

uint64_t
ThreadsafeFace::setInterestFilter
  (const InterestFilter& filter, const OnInterestCallback& onInterest)
{
  // Node.lastEntryId_ uses atomic_uint64_t, so this call is thread safe.
  uint64_t interestFilterId = node_->getNextEntryId();

  //This copies the filter as required by Node.setInterestFilter.
  ioService_.dispatch
    (boost::bind
     (&Node::setInterestFilter, node_, interestFilterId,
      ptr_lib::make_shared<const InterestFilter>(filter), onInterest, this));

  return interestFilterId;
}

uint64_t
ThreadsafeFace::setInterestFilter
  (const Name& prefix, const OnInterestCallback& onInterest)
{
  // Node.lastEntryId_ uses atomic_uint64_t, so this call is thread safe.
  uint64_t interestFilterId = node_->getNextEntryId();

  // This copies the prefix object as required by Node.setInterestFilter.
  // We could just call setInterestFilter(InterestFilter(prefix), onInterest),
  // but that would make yet another copy of prefix, which we want to avoid.
  ioService_.dispatch
    (boost::bind
     (&Node::setInterestFilter, node_, interestFilterId,
      ptr_lib::make_shared<const InterestFilter>(prefix), onInterest, this));

  return interestFilterId;
}

void
ThreadsafeFace::unsetInterestFilter(uint64_t interestFilterId)
{
  ioService_.dispatch
    (boost::bind(&Node::unsetInterestFilter, node_, interestFilterId));
}

void
ThreadsafeFace::putData(const Data& data, WireFormat& wireFormat)
{
  // Check the encoding size here so that the error message happens before
  // dispatch. The encoding should be cached in the Data object.
  Blob encoding = data.wireEncode(wireFormat);
  if (encoding.size() > getMaxNdnPacketSize())
    throw runtime_error
      ("The encoded Data packet size exceeds the maximum limit getMaxNdnPacketSize()");

  ioService_.dispatch
    (boost::bind(&Node::putData, node_, data, &wireFormat));
}

void
ThreadsafeFace::putNack(const Interest& interest, const NetworkNack& networkNack)
{
  // Check the encoding size here so that the error message happens before
  // dispatch. The encoding should be cached in the Data object.
  Blob encoding = Node::encodeLpNack(interest, networkNack);
  if (encoding.size() > getMaxNdnPacketSize())
    throw runtime_error
      ("The encoded Nack packet size exceeds the maximum limit getMaxNdnPacketSize()");

  ioService_.dispatch
    (boost::bind(&Node::putNack, node_, interest, networkNack));
}

void
ThreadsafeFace::send(const uint8_t *encoding, size_t encodingLength)
{
  ioService_.dispatch
    (boost::bind(&Node::send, node_, encoding, encodingLength));
}

void
ThreadsafeFace::shutdown()
{
  ioService_.dispatch(boost::bind(&Node::shutdown, node_));
}

/**
 * After the delay, async_wait calls this to call the original caller's callback.
 * @param errorCode The error code from async_wait.
 * @param callback The original caller's callback.
 * @param timer This is not used, but passed in the function object to keep
 * the timer object alive until this is called.
 */
static void
waitHandler
  (const boost::system::error_code& errorCode, const Face::Callback& callback,
   ptr_lib::shared_ptr<boost::asio::deadline_timer> timer)
{
  if (errorCode != boost::system::errc::success)
    // Don't expect this to happen.
    return;

  callback();
}

void
ThreadsafeFace::callLater
  (nanoseconds delay, const Callback& callback)
{
  ptr_lib::shared_ptr<boost::asio::deadline_timer> timer
    (new boost::asio::deadline_timer
     (ioService_,
      boost::posix_time::milliseconds(duration_cast<milliseconds>(delay).count())));

  // Pass the timer to waitHandler to keep it alive.
  timer->async_wait(boost::bind(&waitHandler, _1, callback, timer));
}

}

#endif // NDN_IND_HAVE_BOOST_ASIO

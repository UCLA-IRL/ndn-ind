/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Pollere, Inc.
 * @author: Pollere, Inc. <info@pollere.net>
 *
 * This works is derived from previous work listed below:
 *
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/threadsafe-face.hpp
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

#ifndef NDN_ASYNC_FACE_HPP
#define NDN_ASYNC_FACE_HPP

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST_ASIO.
#include "ndn-ind-config.h"
#ifdef NDN_IND_HAVE_BOOST_ASIO

#include <boost/asio.hpp>
#include <boost/move/make_unique.hpp>
#include <boost/move/unique_ptr.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>
#include <ndn-ind/transport/async-tcp-transport.hpp>
#include <ndn-ind/transport/async-unix-transport.hpp>
#include "face.hpp"

namespace ndn_ind {

using namespace std;
using namespace std::chrono;

/**
 * An AsyncFace extends Face to use a Boost asio io_service to process events
 * and schedule communication calls. It is *not* threadsafe.
 */
class AsyncFace : public Face {
public:
  /**
   * Create a new Face for communication with an NDN hub with the given
   * Transport object and connectionInfo.
   * @param ioService The asio io_service. It is the responsibility of the
   * application to start and stop the service.
   * @param transport A shared_ptr to a Transport object used for communication.
   * If you do not want to call processEvents, then the transport should be an
   * async transport like AsyncTcpTransport, in which case the transport should
   * use the same ioService.
   * @param transport A shared_ptr to a Transport::ConnectionInfo to be used to
   * connect to the transport.
   */
  AsyncFace
    (boost::asio::io_service& ioService,
     const ptr_lib::shared_ptr<Transport>& transport,
     const ptr_lib::shared_ptr<const Transport::ConnectionInfo>& connectionInfo)
    : Face(transport, connectionInfo), ioService_(ioService)
  {
  }

  /**
   * Create a new AsyncFace for communication with an NDN hub at host:port
   * using the an AsyncTcpTransport. With this constructor, you do not need to
   * call processEvents since the ioService does all processing.
   * @param ioService The asio io_service. It is the responsibility of the
   * application to start and stop the service.
   * @param host The host of the NDN hub.
   * @param port (optional) The port of the NDN hub. If omitted, use 6363.
   */
  AsyncFace(boost::asio::io_service& ioService, const char *host, unsigned short port = 6363)
    : Face(ptr_lib::make_shared<AsyncTcpTransport>(ioService),
           ptr_lib::make_shared<AsyncTcpTransport::ConnectionInfo>(host, port)),
      ioService_(ioService)
  {
  }

  /**
   * Create a new Face for communication with an NDN hub using a default
   * connection as follows. If the forwarder's Unix socket file exists, then
   * connect using AsyncUnixTransport. Otherwise, connect to "localhost" on port
   * 6363 using AsyncTcpTransport. With this constructor, you do not need to
   * call processEvents since the ioService does all processing.
   * @param ioService The asio io_service. It is the responsibility of the
   * application to start and stop the service.
   */
  AsyncFace(boost::asio::io_service& ioService)
    : Face(getDefaultTransport(ioService), getDefaultConnectionInfo()),
      ioService_(ioService)
  {
  }

  /**
   * Create a new Face for communication with an NDN hub using a default
   * connection as follows. If the forwarder's Unix socket file exists, then
   * connect using AsyncUnixTransport. Otherwise, connect to "localhost" on port
   * 6363 using AsyncTcpTransport. This creates a default asio io_service. You
   * can access it with getIoService(), which you should use to start the
   * service. With this constructor, you do not need to call processEvents since
   * the ioService does all processing.
   */
  AsyncFace()
    : AsyncFace(getDefaultIoService())
  {
  }

  /**
   * Get the asio io_service that was given to or created by the constructor.
   * @return The asio io_service.
   */
  boost::asio::io_service&
  getIoService() { return ioService_; }

  static boost::asio::io_service&
  getDefaultIoService()
  {
    static boost::asio::io_service* ios{};
    if (ios == nullptr) {
      ios = new boost::asio::io_service;
    }
    return *ios;
  }

  void
  callLater(nanoseconds delay, const Callback& callback) override final
  {
    ptr_lib::shared_ptr<boost::asio::deadline_timer> timer
      (new boost::asio::deadline_timer(ioService_,
        boost::posix_time::milliseconds(duration_cast<milliseconds>(delay).count())));

    // Pass the timer to waitHandler to keep it alive.
    timer->async_wait([callback, timer](const auto& err) {
      if (err == boost::system::errc::success) callback(); });
  }

private:
  static ptr_lib::shared_ptr<Transport>
  getDefaultTransport(boost::asio::io_service& ioService)
  {
    if (getUnixSocketFilePathForLocalhost() == "") {
      return ptr_lib::make_shared<AsyncTcpTransport>(ioService);
    }
    return ptr_lib::make_shared<AsyncUnixTransport>(ioService);
  }

  static ptr_lib::shared_ptr<Transport::ConnectionInfo>
  getDefaultConnectionInfo()
  {
    string filePath = getUnixSocketFilePathForLocalhost();
    if (filePath == "") {
      return ptr_lib::make_shared<AsyncTcpTransport::ConnectionInfo>("localhost");
    }
    return ptr_lib::make_shared<AsyncUnixTransport::ConnectionInfo>(filePath.c_str());
  }

  boost::asio::io_service& ioService_;
};

}

#endif // NDN_IND_HAVE_BOOST_ASIO
#endif // NDN_ASYNC_FACE_HPP

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-ind/transport/unix-transport.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Add readRawPackets. Support ndn_ind_dll.
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

#ifndef NDN_UNIX_TRANSPORT_HPP
#define NDN_UNIX_TRANSPORT_HPP

 // Only compile if we have Unix socket support.
#include <ndn-ind/ndn-ind-config.h>
#if NDN_IND_HAVE_UNISTD_H

#include <string>
#include "../common.hpp"
#include "transport.hpp"

struct ndn_UnixTransport;

namespace ndn_ind {

class DynamicUInt8Vector;

/**
 * UnixTransport extends the Transport interface to implement communication over
 * a Unix socket.
 */
class ndn_ind_dll UnixTransport : public Transport {
public:
  /**
   * A UnixTransport::ConnectionInfo extends Transport::ConnectionInfo to hold
   * the file path of the Unix socket.
   */
  class ndn_ind_dll ConnectionInfo : public Transport::ConnectionInfo {
  public:
    /**
     * Create a ConnectionInfo with the given filePath.
     * @param filePath The file path of the Unix socket to connect to.
     */
    ConnectionInfo(const char *filePath)
    : filePath_(filePath)
    {
    }

    /**
     * Get the file path given to the constructor.
     * @return A string reference for the file path.
     */
    const std::string&
    getFilePath() const { return filePath_; }

    virtual
    ~ConnectionInfo();

  private:
    std::string filePath_;
  };

  /**
   * Create a UnixTransport.
   * @param readRawPackets (optional) If true, then call
   * elementListener->onReceivedElement for each received packet as-is. If
   * false or omitted, then use the ndn_TlvStructureDecoder to ensure that
   * elementListener->onReceivedElement is called once for a whole TLV packet.
   */
  UnixTransport(bool readRawPackets = false);

  /**
   * Determine whether this transport connecting according to connectionInfo is
   * to a node on the current machine. Unix transports are always local.
   * @param connectionInfo This is ignored.
   * @return True because Unix transports are always local.
   */
  virtual bool
  isLocal(const Transport::ConnectionInfo& connectionInfo);

  /**
   * Override to return false since connect does not need to use the onConnected
   * callback.
   * @return False.
   */
  virtual bool
  isAsync();

  /**
   * Connect according to the info in ConnectionInfo, and processEvents() will
   * use elementListener.
   * @param connectionInfo A reference to a UnixTransport::ConnectionInfo.
   * @param elementListener Not a shared_ptr because we assume that it will
   * remain valid during the life of this object.
   * @param onConnected This calls onConnected() when the connection is
   * established.
   */
  virtual void
  connect
    (const Transport::ConnectionInfo& connectionInfo,
     ElementListener& elementListener, const OnConnected& onConnected);

  /**
   * Send data to the host
   * @param data A pointer to the buffer of data to send.
   * @param dataLength The number of bytes in data.
   */
  virtual void
  send(const uint8_t *data, size_t dataLength);

  /**
   * Process any data to receive.  For each element received, call
   * elementListener.onReceivedElement. This is non-blocking and will return
   * immediately if there is no data to receive. You should normally not call
   * this directly since it is called by Face.processEvents.
   * @throws This may throw an exception for reading data or in the callback for
   * processing the data.  If you call this from an main event loop, you may
   * want to catch and log/disregard all exceptions.
   */
  virtual void
  processEvents();

  virtual bool
  getIsConnected();

  /**
   * Close the connection to the host.
   */
  virtual void
  close();

private:
  ptr_lib::shared_ptr<struct ndn_UnixTransport> transport_;
  ptr_lib::shared_ptr<DynamicUInt8Vector> elementBuffer_;
  bool isConnected_;
};

}

#endif // NDN_IND_HAVE_UNISTD_H

#endif

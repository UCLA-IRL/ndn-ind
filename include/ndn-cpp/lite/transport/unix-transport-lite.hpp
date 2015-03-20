/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2015 Regents of the University of California.
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

#ifndef NDN_UNIX_TRANSPORT_LITE_HPP
#define NDN_UNIX_TRANSPORT_LITE_HPP

#include "../../c/errors.h"
#include "../../c/transport/transport-types.h"

namespace ndn {

class UnixTransportLite : private ndn_UnixTransport {
public:
  /**
   * Create an UnixTransport with default values for no connection yet and to use
   * the given buffer for the ElementReader. Note that the ElementReader is not
   * valid until you call connect.
   * @param buffer the allocated buffer used by ElementReader. If reallocFunction
   * is 0, this should be large enough to save a full element, perhaps
   * MAX_NDN_PACKET_SIZE bytes.
   * @param bufferLength the length of the buffer.
   * @param reallocFunction see ndn_DynamicUInt8Array_ensureLength. This may be 0.
   */
  UnixTransportLite
    (uint8_t* buffer, size_t bufferLength, ndn_ReallocFunction reallocFunction);

  /**
   * Connect with a Unix Socket to the socket filePath.
   * @param filePath The file path of the Unix socket to connect to.
   * @param elementListener The ElementListener used by processEvents, which
   * remain valid during the life of this object or until replaced by the next
   * call to connect.
   * @return 0 for success, else an error code.
   */
  ndn_Error
  connect(char* filePath, ndn_ElementListener& elementListener);

  /**
   * Send data to the socket.
   * @param data A pointer to the buffer of data to send.
   * @param dataLength The number of bytes in data.
   * @return 0 for success, else an error code.
   */
  ndn_Error
  send(const uint8_t* data, size_t dataLength);

  /**
   * Close the socket.
   * @return 0 for success, else an error code.
   */
  ndn_Error 
  close();

  /**
   * Upcast the reference to the ndn_UnixTransport struct to a UnixTransportLite.
   * @param transport A reference to the ndn_UnixTransport struct.
   * @return The same reference as UnixTransportLite.
   */
  static UnixTransportLite&
  upCast(ndn_UnixTransport& transport) { return *(UnixTransportLite*)&transport; }

  static const UnixTransportLite&
  upCast(const ndn_UnixTransport& transport) { return *(UnixTransportLite*)&transport; }
};

}

#endif

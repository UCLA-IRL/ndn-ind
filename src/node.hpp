/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/node.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono. Put element-listener.hpp in API.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2013-2020 Regents of the University of California.
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

#ifndef NDN_NODE_HPP
#define NDN_NODE_HPP

#include <map>
#include <ndn-ind/ndn-ind-config.h>
#if NDN_IND_HAVE_BOOST_ATOMIC
#include <boost/atomic.hpp>
#endif
#include <ndn-ind/common.hpp>
#include <ndn-ind/interest.hpp>
#include <ndn-ind/data.hpp>
#include <ndn-ind/interest-filter.hpp>
#include <ndn-ind/face.hpp>
#include "util/command-interest-generator.hpp"
#include "impl/delayed-call-table.hpp"
#include "impl/interest-filter-table.hpp"
#include "impl/pending-interest-table.hpp"
#include "impl/registered-prefix-table.hpp"

struct ndn_Interest;

namespace ndn_ind {

class KeyChain;

class Node : public ElementListener {
public:
  /**
   * Create a new Node for communication with an NDN hub with the given Transport object and connectionInfo.
   * @param transport A shared_ptr to a Transport object used for communication.
   * @param transport A shared_ptr to a Transport::ConnectionInfo to be used to connect to the transport.
   */
  Node(const ptr_lib::shared_ptr<Transport>& transport, const ptr_lib::shared_ptr<const Transport::ConnectionInfo>& connectionInfo);

  /**
   * Enable or disable Interest loopback.
   * @param interestLoopbackEnabled If True, enable Interest loopback,
   * otherwise disable it.
   */
  void
  setInterestLoopbackEnabled(bool interestLoopbackEnabled)
  {
    interestLoopbackEnabled_ = interestLoopbackEnabled;
  }

  /**
   * Send the Interest through the transport, read the entire response and call
   * onData, onTimeout or onNetworkNack as described below.
   * @param pendingInterestId The getNextEntryId() for the pending interest ID
   * which Face got so it could return it to the caller.
   * @param interestCopy The Interest which is NOT copied for this internal Node
   * method. The Face expressInterest is responsible for making a copy and
   * passing a shared_ptr for Node to use.
   * @param onData  When a matching data packet is received, this calls
   * onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. This copies the
   * function object, so you may need to use func_lib::ref() as appropriate.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout(interest) where interest is the interest
   * given to expressInterest. If onTimeout is an empty OnTimeout(), this does
   * not use it. This copies the function object, so you may need to use
   * func_lib::ref() as appropriate.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack(interest, networkNack) and does not call onTimeout. However,
   * if a network Nack is received and onNetworkNack is an empty OnNetworkNack(),
   * do nothing and wait for the interest to time out. This copies the function
   * object, so you may need to use func_lib::ref() as appropriate.
   * @param wireFormat A WireFormat object used to encode the message.
   * @param face The face which has the callLater method, used for interest
   * timeouts. The callLater method may be overridden in a subclass of Face.
   * @throws runtime_error If the encoded interest size exceeds
   * getMaxNdnPacketSize().
   */
  void
  expressInterest
    (uint64_t pendingInterestId,
     const ptr_lib::shared_ptr<const Interest>& interestCopy,
     const OnData& onData, const OnTimeout& onTimeout,
     const OnNetworkNack& onNetworkNack, WireFormat& wireFormat, Face* face);

  /**
   * Remove the pending interest entry with the pendingInterestId from the pending interest table.
   * This does not affect another pending interest with a different pendingInterestId, even if it has the same interest name.
   * If there is no entry with the pendingInterestId, do nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  void
  removePendingInterest(uint64_t pendingInterestId)
  {
    pendingInterestTable_.removePendingInterest(pendingInterestId);
  }

  /**
   * Append a timestamp component and a random value component to interest's
   * name. Then use the keyChain and certificateName to sign the interest. If
   * the interest lifetime is not set, this sets it.
   * @param interest The interest whose name is append with components.
   * @param keyChain The KeyChain object for signing interests.
   * @param certificateName The certificate name for signing interests.
   * @param wireFormat A WireFormat object used to encode the SignatureInfo and
   * to encode interest name for signing.
   */
  void
  makeCommandInterest
    (Interest& interest, KeyChain& keyChain, const Name& certificateName,
     WireFormat& wireFormat)
  {
    commandInterestGenerator_.generate
      (interest, keyChain, certificateName, wireFormat);
  }

  /**
   * Register prefix with the connected NDN hub and call onInterest when a matching interest is received.
   * @param registeredPrefixId The getNextEntryId() for the registered prefix ID
   * which Face got so it could return it to the caller.
   * @param prefixCopy The Name for the prefix to register,  which is NOT copied
   * for this internal Node method. The Face registerPrefix is responsible for
   * making a copy and passing a shared_ptr for Node to use.
   * @param onInterest (optional) If not an empty OnInterestCallback(), this
   * creates an interest filter from prefix so that when an Interest is received
   * which matches the filter, this calls the function object
   * onInterest(prefix, interest, face, interestFilterId, filter).
   * This copies the function object, so you may need to use func_lib::ref() as
   * appropriate. If onInterest is an empty OnInterestCallback(), it is ignored
   * and you must call setInterestFilter.
   * @param onRegisterFailed A function object to call if failed to retrieve the connected hub’s ID or failed to register the prefix.
   * This calls onRegisterFailed(prefix) where prefix is the prefix given to registerPrefix.
   * @param onRegisterSuccess A function object to call when registerPrefix
   * receives a success message from the forwarder. This calls
   * onRegisterSuccess(prefix, registeredPrefixId) where  prefix and
   * registeredPrefixId are the values given to registerPrefix. If
   * onRegisterSuccess is an empty OnRegisterSuccess(), this does not use it.
   * @param registrationOptions The registration options for finer control of
   * how to forward an interest and other options.
   * @param wireFormat A WireFormat object used to encode the message.
   * @param commandKeyChain The KeyChain object for signing interests.
   * @param commandCertificateName The certificate name for signing interests.
   * @param face The face which is passed to the onInterest callback. If
   * onInterest is null, this is ignored.
   */
  void
  registerPrefix
    (uint64_t registeredPrefixId,
     const ptr_lib::shared_ptr<const Name>& prefixCopy,
     const OnInterestCallback& onInterest,
     const OnRegisterFailed& onRegisterFailed,
     const OnRegisterSuccess& onRegisterSuccess,
     const RegistrationOptions& registrationOptions,
     WireFormat& wireFormat, KeyChain& commandKeyChain,
     const Name& commandCertificateName, Face* face);

  /**
   * This is the same as registerPrefix above except get the commandKeyChain and
   * commandCertificateName directly from face.
   */
  void
  registerPrefix
    (uint64_t registeredPrefixId,
     const ptr_lib::shared_ptr<const Name>& prefixCopy,
     const OnInterestCallback& onInterest,
     const OnRegisterFailed& onRegisterFailed,
     const OnRegisterSuccess& onRegisterSuccess,
     const RegistrationOptions& registrationOptions,
     WireFormat& wireFormat, Face* face)
  {
    registerPrefix
      (registeredPrefixId, prefixCopy, onInterest, onRegisterFailed,
       onRegisterSuccess, registrationOptions, wireFormat,
       *face->getCommandKeyChain(),
       face->getCommandCertificateName(), face);
  }

  /**
   * Remove the registered prefix entry with the registeredPrefixId from the
   * registered prefix table. This does not affect another registered prefix
   * with a different registeredPrefixId, even if it has the same prefix name.
   * If there is no entry with the registeredPrefixId, do nothing. If an
   * interest filter was automatically created by registerPrefix, also remove it.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  void
  removeRegisteredPrefix(uint64_t registeredPrefixId)
  {
    registeredPrefixTable_.removeRegisteredPrefix(registeredPrefixId);
  }

  /**
   * Add an entry to the local interest filter table to call the onInterest
   * callback for a matching incoming Interest. This method only modifies the
   * library's local callback table and does not register the prefix with the
   * forwarder. It will always succeed. To register a prefix with the forwarder,
   * use registerPrefix.
   * @param interestFilterId The getNextEntryId() for the interest filter ID
   * which Face got so it could return it to the caller.
   * @param filterCopy The InterestFilter with a prefix and optional regex filter
   * used to match the name of an incoming Interest, which is NOT copied for
   * this internal Node method. The Face setInterestFilter is responsible for
   * making a copy and passing a shared_ptr for Node to use.
   * @param onInterest When an Interest is received which matches the filter,
   * this calls
   * onInterest(prefix, interest, face, interestFilterId, filter).
   * @param face The face which is passed to the onInterest callback.
   */
  void
  setInterestFilter
    (uint64_t interestFilterId,
     const ptr_lib::shared_ptr<const InterestFilter>& filterCopy,
     const OnInterestCallback& onInterest, Face* face)
  {
    interestFilterTable_.setInterestFilter
      (interestFilterId, filterCopy, onInterest, face);
  }

  /**
   * Remove the interest filter entry which has the interestFilterId from the
   * interest filter table. This does not affect another interest filter with
   * a different interestFilterId, even if it has the same prefix name.
   * If there is no entry with the interestFilterId, do nothing.
   * @param interestFilterId The ID returned from setInterestFilter.
   */
  void
  unsetInterestFilter(uint64_t interestFilterId)
  {
    interestFilterTable_.unsetInterestFilter(interestFilterId);
  }

  /**
   * The OnInterestCallback calls this to put a Data packet which satisfies an
   * Interest.
   * @param data The Data packet which satisfies the interest.
   * @param wireFormat A WireFormat object used to encode the Data packet.
   * @throws runtime_error If the encoded Data packet size exceeds
   * getMaxNdnPacketSize().
   */
  void
  putData(const Data& data, WireFormat* wireFormat);

  /**
   * The OnInterest callback can call this to put a Nack for the received Interest.
   * @param interest The Interest to put in the Nack packet.
   * @param networkNack The NetworkNack with the reason code. For example,
   * NetworkNack().setReason(ndn_NetworkNackReason_NO_ROUTE).
   * @throws runtime_error If the encoded Nack packet size exceeds
   * getMaxNdnPacketSize().
   */
  void
  putNack(const Interest& interest, const NetworkNack& networkNack);

  /**
   * Send the encoded packet out through the face.
   * @param encoding The array of bytes for the encoded packet to send.
   * @param encodingLength The number of bytes in the encoding array.
   * @throws runtime_error If the encoded Data packet size exceeds
   * getMaxNdnPacketSize().
   */
  void
  send(const uint8_t *encoding, size_t encodingLength);

  /**
   * Process any packets to receive and call callbacks such as onData,
   * onInterest or onTimeout. This returns immediately if there is no data to
   * receive. This blocks while calling the callbacks. You should repeatedly
   * call this from an event loop, with calls to sleep as needed so that the
   * loop doesn’t use 100% of the CPU. Since processEvents modifies the pending
   * interest table, your application should make sure that it calls
   * processEvents in the same thread as expressInterest (which also modifies
   * the pending interest table).
   * @throws This may throw an exception for reading data or in the callback for processing the data.  If you
   * call this from an main event loop, you may want to catch and log/disregard all exceptions.
   */
  void
  processEvents();

  const ptr_lib::shared_ptr<Transport>&
  getTransport() { return transport_; }

  const ptr_lib::shared_ptr<const Transport::ConnectionInfo>&
  getConnectionInfo() { return connectionInfo_; }

  void
  onReceivedElement(const uint8_t *element, size_t elementLength);

  /**
   * Check if the face is local based on the current connection through the
   * Transport; some Transport may cause network I/O (e.g. an IP host name lookup).
   * @return True if the face is local, false if not.
   */
  bool
  isLocal() { return transport_->isLocal(*connectionInfo_); }

  void
  shutdown();

  /**
   * Get the practical limit of the size of a network-layer packet. If a packet
   * is larger than this, the library or application MAY drop it. This is a
   * static inline method wrapping a const, so you can to use as a constant, e.g.:
   * uint8_t buffer[Face::getMaxNdnPacketSize()].
   * @return The maximum NDN packet size.
   */
  static size_t
  getMaxNdnPacketSize() { return MAX_NDN_PACKET_SIZE; }

  /**
   * Call callback() after the given delay. This adds to delayedCallTable_ which
   * is used by processEvents().
   * @param delay The delay.
   * @param callback This calls callback() after the delay.
   */
  void
  callLater(std::chrono::nanoseconds delay, const Face::Callback& callback)
  {
    delayedCallTable_.callLater(delay, callback);
  }

  /**
   * Get the next unique entry ID for the pending interest table, interest
   * filter table, etc. This uses an atomic_uint64_t to be thread safe. Most
   * entry IDs are for the pending interest table (there usually are not many
   * interest filter table entries) so we use a common pool to only have to do
   * the thread safe operation in one method which is called by Face.
   * @return The next entry ID.
   */
  uint64_t
  getNextEntryId();

  /**
   * Encode the interest into an NDN-TLV LpPacket as a NACK with the reason code
   * in the networkNack object.
   * TODO: Generalize this and move to WireFormat.encodeLpPacket.
   * @param interest The Interest to put in the LpPacket fragment.
   * @param networkNack The NetworkNack with the reason code.
   * @return A Blob containing the encoding.
   */
  static Blob
  encodeLpNack(const Interest& interest, const NetworkNack& networkNack);

private:
  enum ConnectStatus {
    ConnectStatus_UNCONNECTED = 1,
    ConnectStatus_CONNECT_REQUESTED = 2,
    ConnectStatus_CONNECT_COMPLETE = 3
  };

  /**
   * A RegisterResponse receives the response Data packet from the register
   * prefix interest sent to the connected NDN hub.  If this gets a bad response
   * or a timeout, call onRegisterFailed.
   * This class is a function object for the callbacks.
   */
  class RegisterResponse {
  public:
    class Info;
    RegisterResponse
      (ptr_lib::shared_ptr<RegisterResponse::Info> info, Node& parent)
    : info_(info), parent_(parent)
    {
    }

    /**
     * We received the response.
     * @param interest
     * @param data
     */
    void
    operator()(const ptr_lib::shared_ptr<const Interest>& interest,
               const ptr_lib::shared_ptr<Data>& responseData);

    /**
     * We timed out waiting for the response.
     * @param interest
     */
    void
    operator()(const ptr_lib::shared_ptr<const Interest>& timedOutInterest);

    class Info {
    public:
      Info(const ptr_lib::shared_ptr<const Name>& prefix,
           const OnRegisterFailed& onRegisterFailed,
           const OnRegisterSuccess& onRegisterSuccess,
           uint64_t registeredPrefixId, const OnInterestCallback& onInterest,
           Face* face)
      : prefix_(prefix), onRegisterFailed_(onRegisterFailed),
        onRegisterSuccess_(onRegisterSuccess),
        registeredPrefixId_(registeredPrefixId), onInterest_(onInterest),
        face_(face)
      {
      }

      ptr_lib::shared_ptr<const Name> prefix_;
      const OnRegisterFailed onRegisterFailed_;
      const OnRegisterSuccess onRegisterSuccess_;
      uint64_t registeredPrefixId_;
      const OnInterestCallback onInterest_;
      Face* face_;
    };

  private:
    ptr_lib::shared_ptr<Info> info_;
    Node& parent_;
  };

  /**
   * Do the work of expressInterest once we know we are connected. Add the
   * entry to the PIT, encode and send the interest. If Interest loopback is
   * enabled, then also call dispatchInterest.
   * @param pendingInterestId The getNextEntryId() for the pending interest ID
   * which Face got so it could return it to the caller.
   * @param interestCopy The Interest to send, which has already been copied and put
   * in a shared_ptr.
   * @param onData  When a matching data packet is received, this calls
   * onData(interest, data) where interest is the interest given to
   * expressInterest and data is the received Data object. This copies the
   * function object, so you may need to use func_lib::ref() as appropriate.
   * @param onTimeout If the interest times out according to the interest
   * lifetime, this calls onTimeout(interest) where interest is the interest
   * given to expressInterest. If onTimeout is an empty OnTimeout(), this does
   * not use it. This copies the function object, so you may need to use
   * func_lib::ref() as appropriate.
   * @param onNetworkNack When a network Nack packet for the interest is
   * received and onNetworkNack is not null, this calls
   * onNetworkNack(interest, networkNack) and does not call onTimeout. However,
   * if a network Nack is received and onNetworkNack is an empty OnNetworkNack(),
   * do nothing and wait for the interest to time out. This copies the function
   * object, so you may need to use func_lib::ref() as appropriate.
   * @param wireFormat A WireFormat object used to encode the message.
   * @param face The face which has the callLater method, used for interest
   * timeouts. The callLater method may be overridden in a subclass of Face.
   * @throws runtime_error If the encoded interest size exceeds
   * getMaxNdnPacketSize().
   */
  void
  expressInterestHelper
    (uint64_t pendingInterestId,
     const ptr_lib::shared_ptr<const Interest>& interestCopy,
     const OnData& onData, const OnTimeout& onTimeout,
     const OnNetworkNack& onNetworkNack, WireFormat* wireFormat, Face* face);

  /**
   * This is used in callLater for when the pending interest expires. If the
   * pendingInterest is still in the pendingInterestTable_, remove it and call
   * its onTimeout callback.
   * @param pendingInterest The pending interest to check.
   */
  void
  processInterestTimeout(ptr_lib::shared_ptr<PendingInterestTable::Entry> pendingInterest);

  /**
   * Do the work of registerPrefix to register with NFD.
   * @param registeredPrefixId The getNextEntryId() which registerPrefix got so
   * it could return it to the caller. If this is 0, then don't add to
   * registeredPrefixTable_ (assuming it has already been done).
   * @param prefix
   * @param onInterest
   * @param onRegisterFailed
   * @param onRegisterSuccess
   * @param registrationOptions
   * @param commandKeyChain
   * @param commandCertificateName
   * @param face
   */
  void
  nfdRegisterPrefix
    (uint64_t registeredPrefixId, const ptr_lib::shared_ptr<const Name>& prefix,
     const OnInterestCallback& onInterest,
     const OnRegisterFailed& onRegisterFailed,
     const OnRegisterSuccess& onRegisterSuccess,
     const RegistrationOptions& registrationOptions,
     KeyChain& commandKeyChain, const Name& commandCertificateName,
     WireFormat& wireFormat, Face* face);

  /**
   * This is called by Transport::connect from expressInterest.
   */
  void
  onConnected();

  /**
   * Call the OnInterest callback for all entries in the interestFilterTable_
   * that match the interest.
   * @param interest The Interest to match.
   */
  void
  dispatchInterest(const ptr_lib::shared_ptr<const Interest>& interest);

  /**
   * Extract entries from the pendingInterestTable_ which match data, and call
   * each OnData callback.
   * @param data The Data packet to match.
   */
  void
  satisfyPendingInterests(const ptr_lib::shared_ptr<Data>& data);

  /**
   * Extract entries from the pendingInterestTable_ which match data, and call
   * each OnData callback.
   * @param data The Data packet to match. If this needs to call OnData, this
   * makes a copy.
   * @return True if the data matched an entry in the pendingInterestTable_.
   */
  bool
  satisfyPendingInterests(const Data& data);

  // Disable the copy constructor and assignment operator.
  Node(const Node& other);
  Node& operator=(const Node& other);

  ptr_lib::shared_ptr<Transport> transport_;
  ptr_lib::shared_ptr<const Transport::ConnectionInfo> connectionInfo_;
  PendingInterestTable pendingInterestTable_;
  RegisteredPrefixTable registeredPrefixTable_;
  InterestFilterTable interestFilterTable_;
  DelayedCallTable delayedCallTable_;
  std::vector<Face::Callback> onConnectedCallbacks_;
  CommandInterestGenerator commandInterestGenerator_;
  Name timeoutPrefix_;
  ConnectStatus connectStatus_;
  bool interestLoopbackEnabled_;
  Blob nonceTemplate_;
#if NDN_IND_HAVE_BOOST_ATOMIC
  // ThreadsafeFace accesses lastEntryId_ outside of a thread safe dispatch, so
  // use atomic_uint64_t to be thread safe.
  boost::atomic_uint64_t lastEntryId_;
#else
  // Not using Boost asio to dispatch, so we can use a normal uint64_t.
  uint64_t lastEntryId_;
#endif
};

}

#endif

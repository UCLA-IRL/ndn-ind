/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_NODE_HPP
#define NDN_NODE_HPP

#include <ndn-cpp/common.hpp>
#include <ndn-cpp/interest.hpp>
#include <ndn-cpp/data.hpp>
#include <ndn-cpp/forwarding-flags.hpp>
#include <ndn-cpp/face.hpp>
#include "util/nfd-command-interest-generator.hpp"
#include "encoding/element-listener.hpp"

struct ndn_Interest;

namespace ndn {

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
   * Send the Interest through the transport, read the entire response and call onData(interest, data).
   * @param interest A reference to the Interest.  This copies the Interest.
   * @param onData A function object to call when a matching data packet is received.  This copies the function object, so you may need to
   * use func_lib::ref() as appropriate.
   * @param onTimeout A function object to call if the interest times out.  If onTimeout is an empty OnTimeout(), this does not use it.
   * This copies the function object, so you may need to use func_lib::ref() as appropriate.
   * @param wireFormat A WireFormat object used to encode the message.
   * @return The pending interest ID which can be used with removePendingInterest.
   */
  uint64_t 
  expressInterest(const Interest& interest, const OnData& onData, const OnTimeout& onTimeout, WireFormat& wireFormat);
  
  /**
   * Remove the pending interest entry with the pendingInterestId from the pending interest table.
   * This does not affect another pending interest with a different pendingInterestId, even if it has the same interest name.
   * If there is no entry with the pendingInterestId, do nothing.
   * @param pendingInterestId The ID returned from expressInterest.
   */
  void
  removePendingInterest(uint64_t pendingInterestId);
  
  /**
   * Append a timestamp component and a random value component to interest's
   * name. Then use the keyChain and certificateName from setCommandSigningInfo
   * to sign the interest. If the interest lifetime is not set, this sets it.
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
   * @param prefix A reference to a Name for the prefix to register.  This copies the Name.
   * @param onInterest A function object to call when a matching interest is received.  This copies the function object, so you may need to
   * use func_lib::ref() as appropriate.
   * @param onRegisterFailed A function object to call if failed to retrieve the connected hub’s ID or failed to register the prefix.
   * This calls onRegisterFailed(prefix) where prefix is the prefix given to registerPrefix.
   * @param flags The flags for finer control of which interests are forwarded to the application.
   * @param wireFormat A WireFormat object used to encode the message.
   * @param commandKeyChain The KeyChain object for signing interests.  If null,
   * assume we are connected to a legacy NDNx forwarder.
   * @param commandCertificateName The certificate name for signing interests.
   * @return The registered prefix ID which can be used with removeRegisteredPrefix.
   */
  uint64_t 
  registerPrefix
    (const Name& prefix, const OnInterest& onInterest, 
     const OnRegisterFailed& onRegisterFailed, const ForwardingFlags& flags,
     WireFormat& wireFormat, KeyChain& commandKeyChain, 
     const Name& commandCertificateName);

  /**
   * Remove the registered prefix entry with the registeredPrefixId from the registered prefix table.  
   * This does not affect another registered prefix with a different registeredPrefixId, even if it has the same prefix name.
   * If there is no entry with the registeredPrefixId, do nothing.
   * @param registeredPrefixId The ID returned from registerPrefix.
   */
  void
  removeRegisteredPrefix(uint64_t registeredPrefixId);

  /**
   * Process any packets to receive and call callbacks such as onData, 
   * onInterest or onTimeout. This returns immediately if there is no data to 
   * receive. This blocks while calling the callbacks. You should repeatedly 
   * call this from an event loop, with calls to sleep as needed so that the 
   * loop doesn’t use 100% of the CPU. Since processEvents modifies the pending 
   * interest table, your application should make sure that it calls 
   * processEvents in the same thread as expressInterest (which also modifies 
   * the pending interest table).
   * @throw This may throw an exception for reading data or in the callback for processing the data.  If you
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
  
  void 
  shutdown();

private:
  class PendingInterest {
  public:
    /**
     * Create a new PendingInterest and set the timeoutTime_ based on the current time and the interest lifetime.
     * @param pendingInterestId A unique ID for this entry, which you should get with getNextPendingInteresId().
     * @param interest A shared_ptr for the interest.
     * @param onData A function object to call when a matching data packet is received.
     * @param onTimeout A function object to call if the interest times out.  If onTimeout is an empty OnTimeout(), this does not use it.
     */
    PendingInterest
      (uint64_t pendingInterestId, const ptr_lib::shared_ptr<const Interest>& interest, const OnData& onData, 
       const OnTimeout& onTimeout);
    
    /**
     * Return the next unique pending interest ID.
     */
    static uint64_t 
    getNextPendingInterestId()
    {
      return ++lastPendingInterestId_;
    }
    
    /**
     * Return the pendingInterestId given to the constructor.
     */
    uint64_t 
    getPendingInterestId() { return pendingInterestId_; }
    
    const ptr_lib::shared_ptr<const Interest>& 
    getInterest() { return interest_; }
    
    const OnData& 
    getOnData() { return onData_; }
    
    /**
     * Check if this interest is timed out.
     * @param nowMilliseconds The current time in milliseconds from ndn_getNowMilliseconds.
     * @return true if this interest timed out, otherwise false.
     */
    bool 
    isTimedOut(MillisecondsSince1970 nowMilliseconds)
    {
      return timeoutTimeMilliseconds_ >= 0.0 && nowMilliseconds >= timeoutTimeMilliseconds_;
    }

    /**
     * Call onTimeout_ (if defined).  This ignores exceptions from the onTimeout_.
     */
    void 
    callTimeout();
    
  private:
    ptr_lib::shared_ptr<const Interest> interest_;  
    static uint64_t lastPendingInterestId_; /**< A class variable used to get the next unique ID. */
    uint64_t pendingInterestId_;            /**< A unique identifier for this entry so it can be deleted */
    const OnData onData_;
    const OnTimeout onTimeout_;
    MillisecondsSince1970 timeoutTimeMilliseconds_; /**< The time when the interest times out in milliseconds according to ndn_getNowMilliseconds, or -1 for no timeout. */
  };

  class RegisteredPrefix {
  public:
    /**
     * Create a new RegisteredPrefix.
     * @param registeredPrefixId A unique ID for this entry, which you should get with getNextRegisteredPrefixId().
     * @param prefix A shared_ptr for the prefix.
     * @param onInterest A function object to call when a matching data packet is received.
     */
    RegisteredPrefix(uint64_t registeredPrefixId, const ptr_lib::shared_ptr<const Name>& prefix, const OnInterest& onInterest)
    : registeredPrefixId_(registeredPrefixId), prefix_(prefix), onInterest_(onInterest)
    {
    }
    
    /**
     * Return the next unique entry ID.
     */
    static uint64_t 
    getNextRegisteredPrefixId()
    {
      return ++lastRegisteredPrefixId_;
    }
    
    /**
     * Return the registeredPrefixId given to the constructor.
     */
    uint64_t 
    getRegisteredPrefixId() { return registeredPrefixId_; }
    
    const ptr_lib::shared_ptr<const Name>& 
    getPrefix() { return prefix_; }
    
    const OnInterest& 
    getOnInterest() { return onInterest_; }
    
  private:
    static uint64_t lastRegisteredPrefixId_; /**< A class variable used to get the next unique ID. */
    uint64_t registeredPrefixId_;            /**< A unique identifier for this entry so it can be deleted */
    ptr_lib::shared_ptr<const Name> prefix_;
    const OnInterest onInterest_;
  };
  
  /**
   * An NdndIdFetcher receives the Data packet with the publisher public key digest for the connected NDN hub.
   * This class is a function object for the callbacks. It only holds a pointer to an Info object, so it is OK to copy the pointer.
   */
  class NdndIdFetcher {
  public:
    class Info;
    NdndIdFetcher(ptr_lib::shared_ptr<NdndIdFetcher::Info> info)
    : info_(info)
    {      
    }
    
    /**
     * We received the ndnd ID.
     * @param interest
     * @param data
     */
    void 
    operator()(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& ndndIdData);

    /**
     * We timed out fetching the ndnd ID.
     * @param interest
     */
    void 
    operator()(const ptr_lib::shared_ptr<const Interest>& timedOutInterest);
    
    class Info {
    public:
      /**
       * 
       * @param node
       * @param registeredPrefixId The RegisteredPrefix::getNextRegisteredPrefixId() which registerPrefix got so it could return it to the caller.
       * @param prefix
       * @param onInterest
       * @param onRegisterFailed
       * @param flags
       * @param wireFormat
       */
      Info(Node *node, uint64_t registeredPrefixId, const Name& prefix, const OnInterest& onInterest, 
           const OnRegisterFailed& onRegisterFailed, const ForwardingFlags& flags, WireFormat& wireFormat)
      : node_(*node), registeredPrefixId_(registeredPrefixId), prefix_(new Name(prefix)), onInterest_(onInterest), onRegisterFailed_(onRegisterFailed), 
        flags_(flags), wireFormat_(wireFormat)
      {      
      }
      
      Node& node_;
      uint64_t registeredPrefixId_;
      ptr_lib::shared_ptr<const Name> prefix_;
      const OnInterest onInterest_;
      const OnRegisterFailed onRegisterFailed_;
      ForwardingFlags flags_;
      WireFormat& wireFormat_;
    };
    
  private:
    ptr_lib::shared_ptr<Info> info_;
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
    RegisterResponse(ptr_lib::shared_ptr<RegisterResponse::Info> info)
    : info_(info)
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
      Info(Node* node, const ptr_lib::shared_ptr<const Name>& prefix,
           const OnInterest& onInterest,
           const OnRegisterFailed& onRegisterFailed, 
           const ForwardingFlags& flags, WireFormat& wireFormat, 
           bool isNfdCommand)
      : node_(*node), prefix_(prefix), onInterest_(onInterest),
        onRegisterFailed_(onRegisterFailed), flags_(flags), 
        wireFormat_(wireFormat), isNfdCommand_(isNfdCommand)
      {      
      }
      
      Node& node_;
      ptr_lib::shared_ptr<const Name> prefix_;
      const OnInterest onInterest_;
      const OnRegisterFailed onRegisterFailed_;
      ForwardingFlags flags_;
      WireFormat& wireFormat_;
      bool isNfdCommand_;
    };
    
  private:
    ptr_lib::shared_ptr<Info> info_;
  };
  
  /**
   * Find all entries from pendingInterestTable_ where the name conforms to the 
   * entry's interest selectors, remove the entries from the table and add to
   * the entries vector.
   * @param name The name to find the interest for (from the incoming data packet).
   * @param entries Add matching entries from pendingInterestTable_.  The caller
   * should pass in a reference to an empty vector.
   */
  void 
  extractEntriesForExpressedInterest
    (const Name& name, 
     std::vector<ptr_lib::shared_ptr<PendingInterest> > &entries);
  
  /**
   * Find the first entry from the registeredPrefixTable_ where the entry prefix is the longest that matches name.
   * @param name The name to find the RegisteredPrefix for (from the incoming interest packet).
   * @return A pointer to the entry, or 0 if not found.
   */
  RegisteredPrefix*
  getEntryForRegisteredPrefix(const Name& name);

  /**
   * Do the work of registerPrefix to register with NDNx once we have an ndndId_.
   * @param registeredPrefixId The RegisteredPrefix::getNextRegisteredPrefixId()
   * which registerPrefix got so it could return it to the caller. If this
   * is 0, then don't add to registeredPrefixTable_ (assuming it has already
   * been done).  
   * @param prefix
   * @param onInterest
   * @param onRegisterFailed
   * @param flags
   * @param wireFormat
   */  
  void 
  registerPrefixHelper
    (uint64_t registeredPrefixId, const ptr_lib::shared_ptr<const Name>& prefix, 
     const OnInterest& onInterest, const OnRegisterFailed& onRegisterFailed, 
     const ForwardingFlags& flags, WireFormat& wireFormat);

  /**
   * Do the work of registerPrefix to register with NFD.
   * @param registeredPrefixId The RegisteredPrefix::getNextRegisteredPrefixId()
   * which registerPrefix got so it could return it to the caller. If this
   * is 0, then don't add to registeredPrefixTable_ (assuming it has already
   * been done).  
   * @param prefix
   * @param onInterest
   * @param onRegisterFailed
   * @param flags
   * @param commandKeyChain
   * @param commandCertificateName
   */
  void
  nfdRegisterPrefix
    (uint64_t registeredPrefixId, const ptr_lib::shared_ptr<const Name>& prefix, 
     const OnInterest& onInterest, const OnRegisterFailed& onRegisterFailed, 
     const ForwardingFlags& flags, KeyChain& commandKeyChain, 
     const Name& commandCertificateName, WireFormat& wireFormat);
  
  ptr_lib::shared_ptr<Transport> transport_;
  ptr_lib::shared_ptr<const Transport::ConnectionInfo> connectionInfo_;
  std::vector<ptr_lib::shared_ptr<PendingInterest> > pendingInterestTable_;
  std::vector<ptr_lib::shared_ptr<RegisteredPrefix> > registeredPrefixTable_;
  Interest ndndIdFetcherInterest_;
  Blob ndndId_;
  NfdCommandInterestGenerator commandInterestGenerator_;
};

}

#endif

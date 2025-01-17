/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/util/memory-content-cache.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Use std::chrono.
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

#include <algorithm>
#include "../c/util/time.h"
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/util/memory-content-cache.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn_ind::func_lib;

INIT_LOGGER("ndn.MemoryContentCache");

namespace ndn_ind {

MemoryContentCache::Impl::Impl
  (Face* face, nanoseconds cleanupInterval)
: face_(face), cleanupInterval_(cleanupInterval),
  nextCleanupTime_(system_clock::now() + duration_cast<system_clock::duration>(cleanupInterval)),
  isDoingCleanup_(false), minimumCacheLifetime_(0)
{
}

void
MemoryContentCache::Impl::initialize()
{
  storePendingInterestCallback_ = bind
    (&MemoryContentCache::Impl::storePendingInterestCallback, shared_from_this(),
     _1, _2, _3, _4, _5);
}

void
MemoryContentCache::Impl::registerPrefix
  (const Name& prefix, const OnRegisterFailed& onRegisterFailed,
   const OnRegisterSuccess& onRegisterSuccess,
   const OnInterestCallback& onDataNotFound,
   const RegistrationOptions& registrationOptions, WireFormat& wireFormat)
{
  onDataNotFoundForPrefix_[prefix.toUri()] = onDataNotFound;
  uint64_t registeredPrefixId = face_->registerPrefix
    (prefix,
     bind(&MemoryContentCache::Impl::onInterest, shared_from_this(), _1, _2, _3, _4, _5),
     onRegisterFailed, onRegisterSuccess, registrationOptions, wireFormat);
  // Remember the registeredPrefixId so unregisterAll can remove it.
  registeredPrefixIdList_.push_back(registeredPrefixId);
}

void
MemoryContentCache::Impl::setInterestFilter
  (const InterestFilter& filter, const OnInterestCallback& onDataNotFound)
{
  onDataNotFoundForPrefix_[filter.getPrefix().toUri()] = onDataNotFound;
  uint64_t interestFilterId = face_->setInterestFilter
    (filter,
     bind(&MemoryContentCache::Impl::onInterest, shared_from_this(), _1, _2, _3, _4, _5));
  // Remember the interestFilterId so unregisterAll can remove it.
  interestFilterIdList_.push_back(interestFilterId);
}

void
MemoryContentCache::Impl::setInterestFilter
  (const Name& prefix, const OnInterestCallback& onDataNotFound)
{
  onDataNotFoundForPrefix_[prefix.toUri()] = onDataNotFound;
  uint64_t interestFilterId = face_->setInterestFilter
    (prefix,
     bind(&MemoryContentCache::Impl::onInterest, shared_from_this(), _1, _2, _3, _4, _5));
  // Remember the interestFilterId so unregisterAll can remove it.
  interestFilterIdList_.push_back(interestFilterId);
}

void
MemoryContentCache::Impl::unregisterAll()
{
  for (size_t i = 0; i < interestFilterIdList_.size(); ++i)
    face_->unsetInterestFilter(interestFilterIdList_[i]);
  interestFilterIdList_.clear();

  for (size_t i = 0; i < registeredPrefixIdList_.size(); ++i)
    face_->removeRegisteredPrefix(registeredPrefixIdList_[i]);
  registeredPrefixIdList_.clear();

  // Also clear each onDataNotFoundForPrefix given to registerPrefix.
  onDataNotFoundForPrefix_.clear();
}

void
MemoryContentCache::Impl::add(const Data& data)
{
  auto now = system_clock::now();
  doCleanup(now);

  if (data.getMetaInfo().getFreshnessPeriod().count() >= 0.0) {
    // The content will go stale, so use staleTimeCache_.
    ptr_lib::shared_ptr<const StaleTimeContent> content
      (new StaleTimeContent(data, now, minimumCacheLifetime_));
    // Insert into staleTimeCache_, sorted on content->cacheRemovalTime_.
    staleTimeCache_.insert
      (std::lower_bound(staleTimeCache_.begin(), staleTimeCache_.end(), content, contentCompare_),
       content);
  }
  else
    // The data does not go stale, so use noStaleTimeCache_.
    noStaleTimeCache_.push_back
      (ptr_lib::make_shared<const Content>(data));

  // Remove timed-out interests and check if the data packet matches any pending
  // interest.
  // Go backwards through the list so we can erase entries.
  for (int i = (int)pendingInterestTable_.size() - 1; i >= 0; --i) {
    if (pendingInterestTable_[i]->isTimedOut(now)) {
      pendingInterestTable_.erase(pendingInterestTable_.begin() + i);
      continue;
    }

    if (pendingInterestTable_[i]->getInterest()->matchesName(data.getName())) {
      try {
        // Send to the same transport from the original call to onInterest.
        // wireEncode returns the cached encoding if available.
        _LOG_TRACE("MemoryContentCache:  Reply w/ add Data " << data.getName());
        pendingInterestTable_[i]->getFace().send(*data.wireEncode());
      } catch (std::exception& e) {
        _LOG_DEBUG("Error in send: " << e.what());
        return;
      }

      // The pending interest is satisfied, so remove it.
      pendingInterestTable_.erase(pendingInterestTable_.begin() + i);
    }
  }
}

void
MemoryContentCache::Impl::storePendingInterest
  (const ptr_lib::shared_ptr<const Interest>& interest, Face& face)
{
  pendingInterestTable_.push_back(ptr_lib::shared_ptr<PendingInterest>
    (new PendingInterest(interest, face)));
}

void
MemoryContentCache::Impl::getPendingInterestsForName
  (const Name& name,
   vector<ptr_lib::shared_ptr<const PendingInterest> >& pendingInterests)
{
  pendingInterests.clear();

  // Remove timed-out interests as we add results.
  // Go backwards through the list so we can erase entries.
  auto now = system_clock::now();
  for (int i = (int)pendingInterestTable_.size() - 1; i >= 0; --i) {
    if (pendingInterestTable_[i]->isTimedOut(now)) {
      pendingInterestTable_.erase(pendingInterestTable_.begin() + i);
      continue;
    }

    if (pendingInterestTable_[i]->getInterest()->matchesName(name))
      pendingInterests.push_back(pendingInterestTable_[i]);
  }
}

void
MemoryContentCache::Impl::getPendingInterestsWithPrefix
  (const Name& prefix,
   vector<ptr_lib::shared_ptr<const PendingInterest> >& pendingInterests)
{
  pendingInterests.clear();

  // Remove timed-out interests as we add results.
  // Go backwards through the list so we can erase entries.
  auto now = system_clock::now();
  for (int i = (int)pendingInterestTable_.size() - 1; i >= 0; --i) {
    if (pendingInterestTable_[i]->isTimedOut(now)) {
      pendingInterestTable_.erase(pendingInterestTable_.begin() + i);
      continue;
    }

    if (prefix.isPrefixOf(pendingInterestTable_[i]->getInterest()->getName()))
      pendingInterests.push_back(pendingInterestTable_[i]);
  }
}

void
MemoryContentCache::Impl::onInterest
  (const ptr_lib::shared_ptr<const Name>& prefix,
   const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
   uint64_t interestFilterId,
   const ptr_lib::shared_ptr<const InterestFilter>& filter)
{
  _LOG_TRACE("MemoryContentCache:  Received Interest " << interest->toUri());

  auto now = system_clock::now();
  doCleanup(now);

  const Name::Component* selectedComponent = 0;
  Blob selectedEncoding;
  // We need to iterate over both arrays.
  size_t totalSize = staleTimeCache_.size() + noStaleTimeCache_.size();
  for (size_t i = 0; i < totalSize; ++i) {
    const Content* content;
    bool isFresh = true;
    if (i < staleTimeCache_.size()) {
      const StaleTimeContent *staleTimeContent = staleTimeCache_[i].get();
      content = staleTimeContent;
      isFresh = staleTimeContent->isFresh(now);
    }
    else
      // We have iterated over the first array. Get from the second.
      content = noStaleTimeCache_[i - staleTimeCache_.size()].get();

    if (interest->matchesName(content->getName()) &&
        !(interest->getMustBeFresh() && !isFresh)) {
      if (interest->getChildSelector() < 0) {
        // No child selector, so send the first match that we have found.
        _LOG_TRACE("MemoryContentCache:         Reply Data " << content->getName());
        face.send(*content->getDataEncoding());
        return;
      }
      else {
        // Update selectedEncoding based on the child selector.
        const Name::Component* component;
        if (content->getName().size() > interest->getName().size())
          component = &content->getName().get(interest->getName().size());
        else
          component = &emptyComponent_;

        bool gotBetterMatch = false;
        if (!selectedEncoding)
          // Save the first match.
          gotBetterMatch = true;
        else {
          if (interest->getChildSelector() == 0) {
            // Leftmost child.
            if (*component < *selectedComponent)
              gotBetterMatch = true;
          }
          else {
            // Rightmost child.
            if (*component > *selectedComponent)
              gotBetterMatch = true;
          }
        }

        if (gotBetterMatch) {
          selectedComponent = component;
          selectedEncoding = content->getDataEncoding();
        }
      }
    }
  }

  if (selectedEncoding) {
    // We found the leftmost or rightmost child.
    _LOG_TRACE("MemoryContentCache: Reply Data to Interest " << interest->toUri());
    face.send(*selectedEncoding);
  }
  else {
    _LOG_TRACE("MemoryContentCache: onDataNotFound for " << interest->toUri());
    // Call the onDataNotFound callback (if defined).
    map<string, OnInterestCallback>::iterator onDataNotFound =
      onDataNotFoundForPrefix_.find(prefix->toUri());
    if (onDataNotFound != onDataNotFoundForPrefix_.end() &&
        onDataNotFound->second) {
      try {
        onDataNotFound->second(prefix, interest, face, interestFilterId, filter);
      } catch (const std::exception& ex) {
        _LOG_ERROR("MemoryContentCache::operator(): Error in onDataNotFound: " << ex.what());
      } catch (...) {
        _LOG_ERROR("MemoryContentCache::operator(): Error in onDataNotFound.");
      }
    }
  }
}

void
MemoryContentCache::Impl::doCleanup(system_clock::time_point now)
{
  if (isDoingCleanup_)
    // The OnContentRemoved callback may have called add, which has called this
    // doCleanup function again, so wait to do cleanup until later.
    return;

  isDoingCleanup_ = true;

  ptr_lib::shared_ptr<ContentList> contentList;
  if (now >= nextCleanupTime_) {
    // staleTimeCache_ is sorted on cacheRemovalTime_, so we only need to
    // erase the stale entries at the front, then quit.
    while (staleTimeCache_.size() > 0 &&
           staleTimeCache_.front()->isPastRemovalTime(now)) {
      if (onContentRemoved_) {
        // Add to the list of removed content for the OnContentRemoved callback.
        // We make a separate list instead of calling the callback each time
        // because the callback might call add again to modify the staleTimeCache_.
        if (!contentList)
          contentList.reset(new ContentList());

        contentList->push_back(staleTimeCache_.front());
      }

      staleTimeCache_.erase(staleTimeCache_.begin());
    }

    nextCleanupTime_ = now + duration_cast<system_clock::duration>(cleanupInterval_);
  }

  if (onContentRemoved_ && contentList) {
    try {
      onContentRemoved_(contentList);
    } catch (const std::exception& ex) {
      _LOG_ERROR("MemoryContentCache::doCleanup(): Error in onContentRemoved: " << ex.what());
    } catch (...) {
      _LOG_ERROR("MemoryContentCache::doCleanup(): Error in onContentRemoved.");
    }
  }

  isDoingCleanup_ = false;
}

MemoryContentCache::Impl::StaleTimeContent::StaleTimeContent
  (const Data& data, system_clock::time_point now,
   nanoseconds minimumCacheLifetime)
// wireEncode returns the cached encoding if available.
: Content(data)
{
  cacheRemovalTime_ = now + duration_cast<system_clock::duration>
    (max(data.getMetaInfo().getFreshnessPeriod(), minimumCacheLifetime));
  freshnessExpiryTime_ = now + duration_cast<system_clock::duration>
    (data.getMetaInfo().getFreshnessPeriod());
}

MemoryContentCache::PendingInterest::PendingInterest
  (const ptr_lib::shared_ptr<const Interest>& interest, Face& face)
  : interest_(interest), face_(face), timeoutPeriodStart_(system_clock::now())
{
  // Set up timeoutTime_.
  auto interestLifetime = interest_->getInterestLifetime();
  if (interestLifetime.count() < 0)
    // The InterestLifetime is omitted, so use a default.
    interestLifetime = seconds(4);

  timeoutTime_ =
    timeoutPeriodStart_ + duration_cast<system_clock::duration>(interestLifetime);
}

}

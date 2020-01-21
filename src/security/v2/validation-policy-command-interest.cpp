/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2018-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validation-policy-command-interest.cpp
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

#include <ndn-ind/security/command-interest-signer.hpp>
#include <ndn-ind/security/v2/validation-policy-command-interest.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn::func_lib;

namespace ndn {

ValidationPolicyCommandInterest::ValidationPolicyCommandInterest
  (const ptr_lib::shared_ptr<ValidationPolicy>& innerPolicy, const Options& options)
// This copies the options.
: options_(options),
  nowOffsetMilliseconds_(0)
{
  if (!innerPolicy)
    throw invalid_argument("inner policy is missing");

  setInnerPolicy(innerPolicy);

  if (options_.gracePeriod_ < 0.0)
    options_.gracePeriod_ = 0.0;
}

void
ValidationPolicyCommandInterest::checkPolicy
  (const Data& data, const ptr_lib::shared_ptr<ValidationState>& state,
   const ValidationContinuation& continueValidation)
{
  getInnerPolicy().checkPolicy(data, state, continueValidation);
}

void
ValidationPolicyCommandInterest::checkPolicy
  (const Interest& interest, const ptr_lib::shared_ptr<ValidationState>& state,
   const ValidationContinuation& continueValidation)
{
  Name keyName;
  system_clock::time_point timestamp;
  if (!parseCommandInterest(interest, state, keyName, timestamp))
    return;

  if (!checkTimestamp(state, keyName, timestamp))
    return;

  getInnerPolicy().checkPolicy(interest, state, continueValidation);
}

void
ValidationPolicyCommandInterest::cleanUp()
{
  // nowOffsetMilliseconds_ is only used for testing.
  auto now = system_clock::now() + milliseconds((int64_t)nowOffsetMilliseconds_);
  auto expiring = now -  milliseconds((int64_t)options_.recordLifetime_);

  while ((container_.size() > 0 && container_[0]->lastRefreshed_ <= expiring) ||
         (options_.maxRecords_ >= 0 && container_.size() > options_.maxRecords_))
    container_.erase(container_.begin());
}

bool
ValidationPolicyCommandInterest::parseCommandInterest
  (const Interest& interest, const ptr_lib::shared_ptr<ValidationState>& state,
   Name& keyLocatorName, system_clock::time_point& timestamp)
{
  keyLocatorName = Name();
  timestamp = system_clock::time_point();

  const Name& name = interest.getName();
  if (name.size() < CommandInterestSigner::MINIMUM_SIZE) {
    state->fail(ValidationError(ValidationError::POLICY_ERROR,
      "Command interest name `" + interest.getName().toUri() + "` is too short"));
    return false;
  }

  timestamp = fromMillisecondsSince1970(name.get
    (CommandInterestSigner::POS_TIMESTAMP).toNumber());

  keyLocatorName = getKeyLocatorName(interest, *state);
  if (state->isOutcomeFailed())
    // Already failed.
    return false;

  return true;
}

bool
ValidationPolicyCommandInterest::checkTimestamp
  (const ptr_lib::shared_ptr<ValidationState>& state, const Name& keyName,
   system_clock::time_point timestamp)
{
  cleanUp();

  // nowOffsetMilliseconds_ is only used for testing.
  auto now = system_clock::now() + milliseconds((int64_t)nowOffsetMilliseconds_);
  if (timestamp < now - milliseconds((int64_t)options_.gracePeriod_) ||
      timestamp > now + milliseconds((int64_t)options_.gracePeriod_)) {
    state->fail(ValidationError(ValidationError::POLICY_ERROR,
      "Timestamp is outside the grace period for key " + keyName.toUri()));
    return false;
  }

  int index = findByKeyName(keyName);
  if (index >= 0) {
    if (timestamp <= container_[index]->timestamp_) {
      state->fail(ValidationError(ValidationError::POLICY_ERROR,
        "Timestamp is reordered for key " + keyName.toUri()));
      return false;
    }
  }

  InterestValidationState* interestState =
    dynamic_cast<InterestValidationState*>(state.get());
  interestState->addSuccessCallback
    (bind(&ValidationPolicyCommandInterest::insertNewRecord,
     this, _1, keyName, timestamp));

  return true;
}

void
ValidationPolicyCommandInterest::insertNewRecord
  (const Interest& interest, const Name& keyName,
   system_clock::time_point timestamp)
{
  // nowOffsetMilliseconds_ is only used for testing.
  auto now = system_clock::now() + milliseconds((int64_t)nowOffsetMilliseconds_);
  ptr_lib::shared_ptr<LastTimestampRecord> newRecord
    (new LastTimestampRecord(keyName, timestamp, now));

  int index = findByKeyName(keyName);
  if (index >= 0)
    // Remove the existing record so we can move it to the end.
    container_.erase(container_.begin() + index);

  container_.push_back(newRecord);
}

int
ValidationPolicyCommandInterest::findByKeyName(const Name& keyName)
{
  for (int i = 0; i < container_.size(); ++i) {
    if (container_[i]->keyName_.equals(keyName))
      return i;
  }

  return -1;
}

}

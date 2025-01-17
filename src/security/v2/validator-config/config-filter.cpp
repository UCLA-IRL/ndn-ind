/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/security/v2/validator-config/config-filter.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/validator-config/filter.cpp
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

#include "../../../util/regex/ndn-regex-matcher-base.hpp"
// Only compile if we set NDN_IND_HAVE_REGEX_LIB in ndn-regex-matcher-base.hpp.
#if NDN_IND_HAVE_REGEX_LIB

#include <ndn-ind/security/validator-config-error.hpp>
#include <ndn-ind/security/v2/validator-config/config-name-relation.hpp>
#include "../../../util/boost-info-parser.hpp"
#include "../../../util/regex/ndn-regex-top-matcher.hpp"
#include <ndn-ind/security/v2/validator-config/config-filter.hpp>

using namespace std;

namespace ndn_ind {

ConfigFilter::~ConfigFilter() {}

bool
ConfigFilter::match(bool isForInterest, const Name& packetName)
{
  if (isForInterest) {
    const int signedInterestMinSize = 2;

    if (packetName.size() < signedInterestMinSize)
      return false;

    return matchName(packetName.getPrefix(-signedInterestMinSize));
  }
  else
    // Data packet.
    return matchName(packetName);
}

ptr_lib::shared_ptr<ConfigFilter>
ConfigFilter::create(const BoostInfoTree& configSection)
{
  ptr_lib::shared_ptr<string> filterType = configSection.getFirstValue("type");
  if (!filterType)
    throw ValidatorConfigError("Expected <filter.type>");

  if (equalsIgnoreCase(*filterType, "name"))
    return createNameFilter(configSection);
  else
    throw ValidatorConfigError("Unsupported filter.type: " + *filterType);
}

ptr_lib::shared_ptr<ConfigFilter>
ConfigFilter::createNameFilter(const BoostInfoTree& configSection)
{
  ptr_lib::shared_ptr<string> nameUri = configSection.getFirstValue("name");
  if (nameUri) {
    // Get the filter.name.
    Name name(*nameUri);

    // Get the filter.relation.
    ptr_lib::shared_ptr<string> relationValue = configSection.getFirstValue("relation");
    if (!relationValue)
      throw ValidatorConfigError("Expected <filter.relation>");

    ConfigNameRelation::Relation relation =
      ConfigNameRelation::getNameRelationFromString(*relationValue);

    return ptr_lib::make_shared<ConfigRelationNameFilter>(name, relation);
  }

  ptr_lib::shared_ptr<string> regexString = configSection.getFirstValue("regex");
  if (regexString) {
    try {
      return ptr_lib::make_shared<ConfigRegexNameFilter>(*regexString);
    }
    catch (const std::exception& e) {
      throw ValidatorConfigError("Wrong filter.regex: " + *regexString);
    }
  }

  throw ValidatorConfigError("Wrong filter(name) properties");
}

bool
ConfigRelationNameFilter::matchName(const Name& packetName)
{
  return ConfigNameRelation::checkNameRelation(relation_, name_, packetName);
}

ConfigRegexNameFilter::ConfigRegexNameFilter(const string& regexString)
: regex_(new NdnRegexTopMatcher(regexString))
{
}

bool
ConfigRegexNameFilter::matchName(const Name& packetName)
{
  return regex_->match(packetName);
}

}

#endif // NDN_IND_HAVE_REGEX_LIB

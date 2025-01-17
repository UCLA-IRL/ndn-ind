/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/common.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes. Add support functions for std::chrono.
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

#include <sstream>
#include <cctype>
#include <algorithm>
#include <ndn-ind/common.hpp>
#include "c/util/time.h"

using namespace std;
using namespace std::chrono;

namespace ndn_ind {

void
toHex(const uint8_t* array, size_t arrayLength, std::ostringstream& result)
{
  if (arrayLength == 0)
    return;

  result.flags(ios::hex);
  for (size_t i = 0; i < arrayLength; ++i) {
    uint8_t x = array[i];
    if (x < 16)
      result << '0';
    result << (unsigned int)x;
  }
}

string
toHex(const uint8_t* array, size_t arrayLength)
{
  ostringstream result;
  toHex(array, arrayLength, result);
  return result.str();
}

static const char *WHITESPACE_CHARS = " \t\n\r";

/**
 * Modify str in place to erase whitespace on the left.
 * @param str The string to modify.
 */
static __inline void
trimLeft(string& str)
{
  size_t found = str.find_first_not_of(WHITESPACE_CHARS);
  if (found != string::npos) {
    if (found > 0)
      str.erase(0, found);
  }
  else
    // All whitespace
    str.clear();
}

/**
 * Modify str in place to erase whitespace on the right.
 * @param str The string to modify.
 */
static __inline void
trimRight(string& str)
{
  size_t found = str.find_last_not_of(WHITESPACE_CHARS);
  if (found != string::npos) {
    if (found + 1 < str.size())
      str.erase(found + 1);
  }
  else
    // All whitespace
    str.clear();
}

void
ndn_trim(string& str)
{
  trimLeft(str);
  trimRight(str);
}

static bool
charCompareCaseIgnore(char a, char b) { return(::tolower(a) == ::tolower(b)); }

bool
equalsIgnoreCase(const string& s1, const string& s2)
{
  return(s1.size() == s2.size() &&
         equal(s1.begin(), s1.end(), s2.begin(), charCompareCaseIgnore));
}

string
toIsoString
  (system_clock::time_point time, bool includeFraction)
{
  char isoString[25];
  ndn_Error error;
  if ((error = ndn_toIsoString
       (ndn_ind::toMillisecondsSince1970(time), includeFraction ? 1 : 0, isoString)))
    throw runtime_error(ndn_getErrorString(error));

  return isoString;
}

system_clock::time_point
fromIsoString(const string& isoString)
{
  ndn_MillisecondsSince1970 milliseconds;
  ndn_Error error;
  if ((error = ndn_fromIsoString(isoString.c_str(), &milliseconds)))
    throw runtime_error(ndn_getErrorString(error));

  return fromMillisecondsSince1970(milliseconds);
}

}

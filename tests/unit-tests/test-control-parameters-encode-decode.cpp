/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: tests/unit-tests/test-control-parameters-encode-decode.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx NamingConventions unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/test-name.cpp.
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

#include "gtest/gtest.h"
#include <ndn-ind/control-parameters.hpp>

using namespace std;
using namespace ndn_ind;

class TestControlParametersEncodeDecode : public ::testing::Test {
};

/**
 * Test encoding/decoding.
 */
TEST_F(TestControlParametersEncodeDecode, EncodeDecode)
{
  ControlParameters controlParameters;
  controlParameters.setName(Name("/test/control/parameters"));
  controlParameters.setFaceId(1);
  // encode
  Blob encoded = controlParameters.wireEncode();
  // decode
  ControlParameters decodedControlParameters;
  decodedControlParameters.wireDecode(encoded);
  // compare
  ASSERT_EQ(controlParameters.getName().toUri(),
     decodedControlParameters.getName().toUri());
  ASSERT_EQ(controlParameters.getFaceId(), decodedControlParameters.getFaceId());
  ASSERT_EQ(controlParameters.getForwardingFlags().getChildInherit(),
     decodedControlParameters.getForwardingFlags().getChildInherit()) <<
    "decoded forwarding flags childInherit is different";
  ASSERT_EQ(controlParameters.getForwardingFlags().getCapture(),
     decodedControlParameters.getForwardingFlags().getCapture()) <<
    "decoded forwarding flags capture is different";
}

/**
 * Test encoding/decoding with no name defined.
 */
TEST_F(TestControlParametersEncodeDecode, EncodeDecodeWithNoName)
{
  ControlParameters controlParameters;
  controlParameters.setStrategy(Name("/localhost/nfd/strategy/broadcast"));
  controlParameters.setUri("null://");
  // encode
  Blob encoded = controlParameters.wireEncode();
  // decode
  ControlParameters decodedControlParameters;
  decodedControlParameters.wireDecode(encoded);
  // compare
  ASSERT_EQ(controlParameters.getStrategy().toUri(),
     decodedControlParameters.getStrategy().toUri());
  ASSERT_EQ(controlParameters.getUri(), decodedControlParameters.getUri());
}

int
main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: examples/test-publish-async-nfd.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
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

#include <cstdlib>
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <ndn-ind/face.hpp>
#include <ndn-ind/security/key-chain.hpp>

using namespace std;
using namespace ndn_ind;

class Echo {
public:
  Echo(KeyChain &keyChain, const Name& certificateName)
  : keyChain_(keyChain), certificateName_(certificateName), responseCount_(0)
  {
  }

  // onInterest.
  void operator()
     (const ptr_lib::shared_ptr<const Name>& prefix,
      const ptr_lib::shared_ptr<const Interest>& interest, Face& face,
      uint64_t interestFilterId,
      const ptr_lib::shared_ptr<const InterestFilter>& filter)
  {
    ++responseCount_;

    // Make and sign a Data packet.
    Data data(interest->getName());
    string content(string("Echo ") + interest->getName().toUri());
    data.setContent((const uint8_t *)&content[0], content.size());
    keyChain_.sign(data, certificateName_);

    cout << "Sent content " << content << endl;
    face.putData(data);
  }

  // onRegisterFailed.
  void operator()(const ptr_lib::shared_ptr<const Name>& prefix)
  {
    ++responseCount_;
    cout << "Register failed for prefix " << prefix->toUri() << endl;
  }

  KeyChain keyChain_;
  Name certificateName_;
  int responseCount_;
};

static void
usage()
{
  cerr << "Usage: test-publish-async-nfd [options]\n"
       << "  -n name-prefix  If omitted, use /testecho\n"
       << "  -k              Keep responding. If omitted, quit after one response\n"
       << "  -?              Print this help" << endl;
}

int main(int argc, char** argv)
{
  Name namePrefix("/testecho");
  bool keepResponding = false;

  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    string value = (i + 1 < argc ? argv[i + 1] : "");

    if (arg == "-?") {
      usage();
      return 0;
    }
    else if (arg == "-n") {
      namePrefix = Name(value);
      ++i;
    }
    else if (arg == "-k")
      keepResponding = true;
    else {
      cerr << "Unrecognized option: " << arg << endl;
      usage();
      return 1;
    }
  }

  try {
    // The default Face will connect using a Unix socket, or to "localhost".
    Face face;

    // Use the system default key chain and certificate name to sign commands.
    KeyChain keyChain;
    face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName());

    // Also use the default certificate name to sign data packets.
    Echo echo(keyChain, keyChain.getDefaultCertificateName());
    cout << "Register prefix " << namePrefix.toUri() << endl;
    // TODO: After we remove the registerPrefix with the deprecated OnInterest,
    // we can remove the explicit cast to OnInterestCallback (needed for boost).
    face.registerPrefix(namePrefix, (const OnInterestCallback&)func_lib::ref(echo), func_lib::ref(echo));

    // The main event loop.
    // Wait forever to receive an interest for the prefix.
    // If !keepResponding, then quit after one response.
    while (keepResponding || echo.responseCount_ < 1) {
      face.processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}

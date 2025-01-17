/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: examples/test-get-async-threadsafe.cpp
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

/* This uses ThreadsafeFace to call expressInterest and show the content of the
 * fetched data packets. Because it uses ThreadsafeFace, the application doesn't
 * need to call processEvents. To run it, you must install Boost with asio.
 */

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST_ASIO.
#include <ndn-ind/ndn-ind-config.h>
#ifdef NDN_IND_HAVE_BOOST_ASIO

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <boost/asio.hpp>
#include <ndn-ind/threadsafe-face.hpp>

using namespace std;
using namespace ndn_ind;
using namespace ndn_ind::func_lib;

/**
 * Counter counts the number of calls to the onData or onTimeout callbacks.
 */
class Counter
{
public:
  /**
   * Create a Counter to call ioService.stop() after maxCallbackCount calls to
   * onData or onTimeout.
   */
  Counter(boost::asio::io_service& ioService, int maxCallbackCount)
  : ioService_(ioService),
    maxCallbackCount_(maxCallbackCount),
    callbackCount_(0)
  {
  }

  void onData(const ptr_lib::shared_ptr<const Interest>& interest, const ptr_lib::shared_ptr<Data>& data)
  {
    cout << "Got data packet with name " << data->getName().toUri() << endl;
    for (size_t i = 0; i < data->getContent().size(); ++i)
      cout << (*data->getContent())[i];
    cout << endl;

    if (++callbackCount_ >= maxCallbackCount_)
      // This will exit the program.
      ioService_.stop();
  }

  void onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
  {
    cout << "Time out for interest " << interest->getName().toUri() << endl;

    if (++callbackCount_ >= maxCallbackCount_)
      // This will exit the program.
      ioService_.stop();
  }

private:
  boost::asio::io_service& ioService_;
  int maxCallbackCount_;
  int callbackCount_;
};

int main(int argc, char** argv)
{
  try {
    // Silence the warning from Interest wire encode.
    Interest::setDefaultCanBePrefix(true);

    boost::asio::io_service ioService;
    ThreadsafeFace face(ioService, "memoria.ndn.ucla.edu");

    // Counter will stop the ioService after callbacks for all expressInterest.
    Counter counter(ioService, 3);

    // Try to fetch anything.
    Name name1("/");
    cout << "Express name " << name1.toUri() << endl;
    // Use bind to pass the counter object to the callbacks.
    face.expressInterest(name1, bind(&Counter::onData, &counter, _1, _2), bind(&Counter::onTimeout, &counter, _1));

    // Try to fetch using a known name.
    Name name2("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDU%8D%9DM");
    cout << "Express name " << name2.toUri() << endl;
    face.expressInterest(name2, bind(&Counter::onData, &counter, _1, _2), bind(&Counter::onTimeout, &counter, _1));

    // Expect this to time out.
    Name name3("/test/timeout");
    cout << "Express name " << name3.toUri() << endl;
    face.expressInterest(name3, bind(&Counter::onData, &counter, _1, _2), bind(&Counter::onTimeout, &counter, _1));

    // Keep ioService running until the Counter calls stop().
    boost::asio::io_service::work work(ioService);
    ioService.run();
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}

#else // NDN_IND_HAVE_BOOST_ASIO

#include <iostream>

using namespace std;

int main(int argc, char** argv)
{
  cout <<
    "This program uses Boost asio but it is not installed. Install Boost and ./configure again." << endl;
}

#endif // NDN_IND_HAVE_BOOST_ASIO

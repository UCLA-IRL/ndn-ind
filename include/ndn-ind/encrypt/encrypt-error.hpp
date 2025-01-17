/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/encrypt/encrypt-error.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2016-2020 Regents of the University of California.
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

#ifndef NDN_ENCRYPT_ERROR_HPP
#define NDN_ENCRYPT_ERROR_HPP

#include "../common.hpp"

namespace ndn_ind {

/**
 * EncryptError holds the ErrorCode enum and OnError callback definition for
 * errors from the encrypt library.
 */
class ndn_ind_dll EncryptError {
public:
  enum ErrorCode {
    KekRetrievalFailure  = 1,
    KekRetrievalTimeout  = 2,
    KekInvalidName       = 3,

    KdkRetrievalFailure  = 11,
    KdkRetrievalTimeout  = 12,
    KdkInvalidName       = 13,
    KdkDecryptionFailure = 14,

    CkRetrievalFailure   = 21,
    CkRetrievalTimeout   = 22,
    CkInvalidName        = 23,

    MissingRequiredKeyLocator    = 101,
    TpmKeyNotFound               = 102,
    EncryptionFailure            = 103,
    DecryptionFailure            = 104,
    MissingRequiredInitialVector = 110,

    General                      = 200,

    // @deprecated These codes are from the NAC library v1.
    Timeout                     = 1001,
    Validation                  = 1002,
    UnsupportedEncryptionScheme = 1032,
    InvalidEncryptedFormat      = 1033,
    NoDecryptKey                = 1034,
    DataRetrievalFailure        = 1036
  };

  /**
   * A method calls onError(errorCode, message) for an error.
   */
  typedef func_lib::function<void
    (ErrorCode errorCode, const std::string& message)> OnError;
};

}

#endif

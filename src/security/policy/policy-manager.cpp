/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2014-2019 Regents of the University of California.
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

#include "../../c/util/crypto.h"
#include "../../c/util/ndn_memory.h"
#include <ndn-ind/security/security-exception.hpp>
#include <ndn-ind/digest-sha256-signature.hpp>
#include <ndn-ind/sha256-with-ecdsa-signature.hpp>
#include <ndn-ind/sha256-with-rsa-signature.hpp>
#include <ndn-ind/security/verification-helpers.hpp>
#include <ndn-ind/security/policy/policy-manager.hpp>

using namespace std;

namespace ndn {

bool
PolicyManager::verifySignature
  (const Signature* signature, const SignedBlob& signedBlob,
   const Blob& publicKeyDer)
{
  if (dynamic_cast<const DigestSha256Signature *>(signature))
    return VerificationHelpers::verifyDigest
      (signedBlob.signedBuf(), signedBlob.signedSize(),
       signature->getSignature().buf(), signature->getSignature().size(),
       DIGEST_ALGORITHM_SHA256);
#if NDN_CPP_HAVE_LIBCRYPTO
  else if (dynamic_cast<const Sha256WithRsaSignature *>(signature) ||
           dynamic_cast<const Sha256WithEcdsaSignature *>(signature)) {
    if (publicKeyDer.isNull())
      return false;
    return VerificationHelpers::verifySignature
      (signedBlob.signedBuf(), signedBlob.signedSize(),
       signature->getSignature().buf(), signature->getSignature().size(),
       PublicKey(publicKeyDer), DIGEST_ALGORITHM_SHA256);
  }
  else
#endif
    throw SecurityException("PolicyManager::verify: Signature type is unknown");
}

}

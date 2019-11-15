/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/v2/certificate-storage.cpp
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

#include <ndn-ind/security/v2/certificate-storage.hpp>

using namespace std;

namespace ndn {

ptr_lib::shared_ptr<CertificateV2>
CertificateStorage::findTrustedCertificate
  (const Interest& interestForCertificate)
{
  ptr_lib::shared_ptr<CertificateV2> certificate =
    trustAnchors_.find(interestForCertificate);
  if (!!certificate)
    return certificate;

  certificate = verifiedCertificateCache_.find(interestForCertificate);
  return certificate;
}

bool
CertificateStorage::isCertificateKnown(const Name& certificatePrefix)
{
  return !!trustAnchors_.find(certificatePrefix) ||
         !!verifiedCertificateCache_.find(certificatePrefix) ||
         !!unverifiedCertificateCache_.find(certificatePrefix);
}

}

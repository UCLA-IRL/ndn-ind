/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/lite/util/blob-lite.cpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2015-2020 Regents of the University of California.
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

#include "../../c/util/blob.h"
#include <ndn-ind/lite/util/blob-lite.hpp>

namespace ndn_ind {

BlobLite::BlobLite()
{
  ndn_Blob_initialize(this, 0, 0);
}

BlobLite::BlobLite(const uint8_t* buf, size_t size)
{
  ndn_Blob_initialize(this, buf, size);
}

size_t
BlobLite::size() const
{
  return ndn_Blob_size(this);
}

bool
BlobLite::equals(const BlobLite& other) const
{
  return ndn_Blob_equals(this, &other) != 0;
}

size_t
BlobLite::hash(const uint8_t* buf, size_t size)
{
  // Imitate Java's ByteBuffer.hashCode().)
  size_t result = 1;
  for (size_t i = 0; i < size; ++i)
    result = 31 * result + (size_t)buf[i];

  return result;
}

}

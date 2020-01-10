/**
 * Copyright (C) 2018-2020 Regents of the University of California.
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

#include "congestion-mark.h"

const struct ndn_CongestionMark *
ndn_CongestionMark_getFirstHeader(const struct ndn_LpPacket *lpPacket)
{
  size_t i;
  for (i = 0; i < lpPacket->nHeaderFields; ++i) {
    const struct ndn_LpPacketHeaderField *field = &lpPacket->headerFields[i];
    if (field->type == ndn_LpPacketHeaderFieldType_CONGESTION_MARK)
      return &field->congestionMark;
  }

  return 0;
}

ndn_Error
ndn_CongestionMark_add
  (struct ndn_LpPacket *lpPacket, struct ndn_CongestionMark **congestionMark)
{
  ndn_Error error;
  struct ndn_LpPacketHeaderField *headerField;

  if ((error = ndn_LpPacket_addEmptyHeaderField(lpPacket, &headerField)))
    return error;
  headerField->type = ndn_LpPacketHeaderFieldType_CONGESTION_MARK;
  *congestionMark = &headerField->congestionMark;
  ndn_CongestionMark_initialize(*congestionMark);

  return NDN_ERROR_success;
}

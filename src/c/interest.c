/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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

#include "util/ndn_memory.h"
#include "interest.h"

ndn_Error
ndn_Exclude_appendAny(struct ndn_Exclude *self)
{
  if (self->nEntries >= self->maxEntries)
    return NDN_ERROR_read_an_entry_past_the_maximum_number_of_entries_allowed_in_the_exclude;
  ndn_ExcludeEntry_initialize
    (self->entries + self->nEntries, ndn_Exclude_ANY, 0, 0);
  ++self->nEntries;

  return NDN_ERROR_success;
}

ndn_Error
ndnExclude_appendComponent
  (struct ndn_Exclude *self, const uint8_t* component, size_t componentLength)
{
  if (self->nEntries >= self->maxEntries)
    return NDN_ERROR_read_an_entry_past_the_maximum_number_of_entries_allowed_in_the_exclude;
  ndn_ExcludeEntry_initialize
    (self->entries + self->nEntries, ndn_Exclude_COMPONENT, component,
     componentLength);
  ++self->nEntries;

  return NDN_ERROR_success;
}

int ndn_Exclude_compareComponents(struct ndn_NameComponent *component1, struct ndn_NameComponent *component2)
{
  if (component1->value.length < component2->value.length)
    return -1;
  if (component1->value.length > component2->value.length)
    return 1;

  // The components are equal length.  Just do a byte compare.
  return ndn_memcmp(component1->value.value, component2->value.value, component1->value.length);
}

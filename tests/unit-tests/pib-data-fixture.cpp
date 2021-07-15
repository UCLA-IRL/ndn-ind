/**
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/pib-data-fixture.cpp
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

#include "pib-data-fixture.hpp"

using namespace std;
using namespace ndn_ind;

const uint8_t ID1_KEY1_CERT1[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x01, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x01, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xc9, 0xc5, 0x2a, 0x06, 0x59, 0x5f, 0xbf, 0xf6, 0xe1, 0x92, 0x0c, 0x0d, 0xa0, 0xcc, 0x42,
  0x88, 0x33, 0x3b, 0x1b, 0xef, 0x2b, 0xaf, 0x9b, 0x5d, 0x12, 0x62, 0xda, 0xac, 0x43, 0xa9, 0x45,
  0x56, 0x6d, 0xab, 0x4e, 0xad, 0xb5, 0x09, 0xeb, 0x0c, 0xd1, 0x8d, 0x25, 0x58, 0x3f, 0xa3, 0xe7,
  0xed, 0xf9, 0xf8, 0x78, 0xf5, 0x6a, 0x4c, 0xe6, 0xd5, 0xe8, 0x2a, 0xfa, 0x79, 0x8f, 0x54, 0x5b,
  0xe2, 0x5c, 0x8b, 0xde, 0xb7, 0x86, 0xcd, 0x94, 0xa4, 0xfc, 0x72, 0xea, 0x37, 0xfa, 0x6a, 0xbd,
  0x05, 0x0d, 0x65, 0x90, 0xe5, 0x08, 0x64, 0xf9, 0xc5, 0xa8, 0x62, 0x70, 0x97, 0xdd, 0x10, 0x80,
  0x7a, 0x9f, 0xf6, 0x9a, 0x81, 0x17, 0xdf, 0x39, 0xce, 0xa6, 0xe0, 0xe2, 0xf4, 0x8c, 0xaf, 0x79,
  0xb6, 0xb9, 0x49, 0x1a, 0xc4, 0xdc, 0x69, 0x38, 0xbe, 0xc2, 0x6b, 0xae, 0x46, 0x18, 0xeb, 0x59,
  0x0a, 0x94, 0xee, 0xd5, 0x19, 0x98, 0x03, 0x45, 0x14, 0x60, 0x35, 0xbf, 0x60, 0x12, 0x83, 0x07,
  0x95, 0x8f, 0xa4, 0xd9, 0xe4, 0x92, 0xfb, 0x53, 0xd3, 0xe7, 0x33, 0x33, 0x69, 0x3d, 0xa5, 0x11,
  0xfd, 0xd5, 0xf0, 0x19, 0xef, 0xbb, 0x10, 0x1a, 0xc7, 0x6b, 0xda, 0x8a, 0xcc, 0x53, 0xc1, 0xed,
  0x0d, 0xf7, 0xf3, 0x0a, 0x4e, 0xf3, 0x0a, 0x50, 0xd4, 0xd7, 0x5d, 0xc1, 0xaa, 0x13, 0x36, 0x3f,
  0xc2, 0xc2, 0x00, 0xe7, 0xde, 0x43, 0x29, 0xcb, 0x20, 0x2e, 0x7b, 0xb3, 0xe5, 0x3c, 0x3a, 0xb8,
  0x2f, 0x8c, 0xa7, 0xe8, 0x83, 0xd4, 0x2a, 0xa9, 0x2c, 0x20, 0x8e, 0xe1, 0xb4, 0x9c, 0x6c, 0xa7,
  0x85, 0x3d, 0xd8, 0xfc, 0x0c, 0x68, 0x4d, 0x1d, 0x36, 0xfe, 0x3a, 0x7a, 0xda, 0x4c, 0x0e, 0xf4,
  0x8d, 0x58, 0x92, 0x8a, 0xcc, 0xd0, 0x31, 0x7f, 0x9d, 0x09, 0xa0, 0x69, 0xb2, 0x37, 0x98, 0x57,
  0x63, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x01, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x26, 0x37, 0x0c, 0x2e,
  0xb0, 0x89, 0xb6, 0xfe, 0x51, 0x7f, 0xab, 0x0b, 0xb4, 0x18, 0x42, 0x5c, 0xd1, 0x06, 0x7b, 0xf9,
  0xd3, 0xf3, 0xdd, 0xe6, 0xe9, 0xf2, 0xce, 0x66, 0x61, 0x6c, 0x96, 0x7f, 0xdf, 0xdf, 0x94, 0x36,
  0x08, 0x3c, 0xab, 0x45, 0x8d, 0x48, 0xfd, 0xa7, 0x74, 0x30, 0xb6, 0x7e, 0x71, 0xaa, 0xe8, 0xbd,
  0x57, 0xc3, 0x60, 0xa3, 0xdf, 0xd1, 0x11, 0x8d, 0x70, 0xc8, 0x4b, 0xcf, 0x86, 0xae, 0xe4, 0x59,
  0xcf, 0x59, 0x51, 0xa3, 0xeb, 0x5a, 0x48, 0xae, 0x26, 0x96, 0x29, 0x12, 0x75, 0x50, 0x4a, 0x24,
  0xeb, 0x7d, 0x05, 0x4a, 0x38, 0x2f, 0x84, 0x57, 0x12, 0xa5, 0x8c, 0xb0, 0x87, 0x70, 0x51, 0xf2,
  0xdb, 0x3f, 0xe8, 0xae, 0x75, 0xdc, 0x0c, 0xd5, 0x6e, 0xc7, 0xcd, 0xbd, 0x78, 0xdd, 0xa3, 0xf8,
  0x96, 0x6c, 0x14, 0xfe, 0xf0, 0xf4, 0x7d, 0x28, 0x8a, 0x60, 0x6b, 0xfa, 0xaa, 0xd8, 0x71, 0x53,
  0x94, 0x09, 0x4c, 0x79, 0x8f, 0x74, 0x2d, 0x26, 0x43, 0x0f, 0xf6, 0xd9, 0x9c, 0x01, 0x78, 0xa5,
  0xee, 0x2c, 0xc8, 0x2e, 0x63, 0xb6, 0x44, 0x8d, 0xd2, 0xaa, 0xa5, 0x0c, 0x48, 0x31, 0x74, 0xb1,
  0x1f, 0xa2, 0xa0, 0xe1, 0x80, 0xa8, 0x07, 0x9b, 0xff, 0xc1, 0x17, 0xd1, 0xaf, 0xbe, 0x6a, 0x7a,
  0x7a, 0xe4, 0x5e, 0xf1, 0x7e, 0xd0, 0x07, 0x27, 0xcd, 0x01, 0x2d, 0xa2, 0xb0, 0x70, 0xc5, 0x89,
  0x4e, 0x93, 0xce, 0xba, 0xc3, 0xa6, 0x56, 0x9a, 0x58, 0x97, 0xc6, 0xf2, 0x18, 0x31, 0x5c, 0x1e,
  0xd1, 0x98, 0x7f, 0x58, 0x1a, 0x82, 0x8a, 0xd7, 0x7b, 0xea, 0x84, 0xbe, 0x3d, 0x8c, 0x17, 0x41,
  0x19, 0xda, 0xf7, 0x44, 0x27, 0xff, 0x9e, 0x5c, 0x9d, 0x9b, 0x9b, 0x62, 0x08, 0x96, 0x50, 0xd5,
  0xe2, 0x48, 0x4b, 0xff, 0xc9, 0x0e, 0x94, 0xcc, 0xb0, 0xc1, 0xb6, 0x62
};

const uint8_t ID1_KEY1_CERT2[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x01, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x02, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xc9, 0xc5, 0x2a, 0x06, 0x59, 0x5f, 0xbf, 0xf6, 0xe1, 0x92, 0x0c, 0x0d, 0xa0, 0xcc, 0x42,
  0x88, 0x33, 0x3b, 0x1b, 0xef, 0x2b, 0xaf, 0x9b, 0x5d, 0x12, 0x62, 0xda, 0xac, 0x43, 0xa9, 0x45,
  0x56, 0x6d, 0xab, 0x4e, 0xad, 0xb5, 0x09, 0xeb, 0x0c, 0xd1, 0x8d, 0x25, 0x58, 0x3f, 0xa3, 0xe7,
  0xed, 0xf9, 0xf8, 0x78, 0xf5, 0x6a, 0x4c, 0xe6, 0xd5, 0xe8, 0x2a, 0xfa, 0x79, 0x8f, 0x54, 0x5b,
  0xe2, 0x5c, 0x8b, 0xde, 0xb7, 0x86, 0xcd, 0x94, 0xa4, 0xfc, 0x72, 0xea, 0x37, 0xfa, 0x6a, 0xbd,
  0x05, 0x0d, 0x65, 0x90, 0xe5, 0x08, 0x64, 0xf9, 0xc5, 0xa8, 0x62, 0x70, 0x97, 0xdd, 0x10, 0x80,
  0x7a, 0x9f, 0xf6, 0x9a, 0x81, 0x17, 0xdf, 0x39, 0xce, 0xa6, 0xe0, 0xe2, 0xf4, 0x8c, 0xaf, 0x79,
  0xb6, 0xb9, 0x49, 0x1a, 0xc4, 0xdc, 0x69, 0x38, 0xbe, 0xc2, 0x6b, 0xae, 0x46, 0x18, 0xeb, 0x59,
  0x0a, 0x94, 0xee, 0xd5, 0x19, 0x98, 0x03, 0x45, 0x14, 0x60, 0x35, 0xbf, 0x60, 0x12, 0x83, 0x07,
  0x95, 0x8f, 0xa4, 0xd9, 0xe4, 0x92, 0xfb, 0x53, 0xd3, 0xe7, 0x33, 0x33, 0x69, 0x3d, 0xa5, 0x11,
  0xfd, 0xd5, 0xf0, 0x19, 0xef, 0xbb, 0x10, 0x1a, 0xc7, 0x6b, 0xda, 0x8a, 0xcc, 0x53, 0xc1, 0xed,
  0x0d, 0xf7, 0xf3, 0x0a, 0x4e, 0xf3, 0x0a, 0x50, 0xd4, 0xd7, 0x5d, 0xc1, 0xaa, 0x13, 0x36, 0x3f,
  0xc2, 0xc2, 0x00, 0xe7, 0xde, 0x43, 0x29, 0xcb, 0x20, 0x2e, 0x7b, 0xb3, 0xe5, 0x3c, 0x3a, 0xb8,
  0x2f, 0x8c, 0xa7, 0xe8, 0x83, 0xd4, 0x2a, 0xa9, 0x2c, 0x20, 0x8e, 0xe1, 0xb4, 0x9c, 0x6c, 0xa7,
  0x85, 0x3d, 0xd8, 0xfc, 0x0c, 0x68, 0x4d, 0x1d, 0x36, 0xfe, 0x3a, 0x7a, 0xda, 0x4c, 0x0e, 0xf4,
  0x8d, 0x58, 0x92, 0x8a, 0xcc, 0xd0, 0x31, 0x7f, 0x9d, 0x09, 0xa0, 0x69, 0xb2, 0x37, 0x98, 0x57,
  0x63, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x01, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x59, 0x8a, 0x5f, 0xf2,
  0x11, 0xba, 0x9e, 0x93, 0xbf, 0x14, 0xb5, 0x5b, 0xf3, 0x07, 0xcb, 0x91, 0x34, 0x72, 0x23, 0x71,
  0x61, 0xfa, 0x27, 0xe1, 0x75, 0x06, 0x5f, 0xae, 0x29, 0xd7, 0x9f, 0xd4, 0xc1, 0x49, 0xf1, 0xf0,
  0xac, 0x2a, 0xfd, 0x4a, 0xe4, 0x67, 0x02, 0x7f, 0x70, 0xd1, 0x09, 0x87, 0xd4, 0x65, 0x7d, 0x17,
  0x4a, 0x42, 0xdb, 0x25, 0xab, 0x6e, 0xcf, 0x1b, 0x2a, 0x5b, 0x29, 0xc3, 0xe7, 0x28, 0x69, 0xc7,
  0x3b, 0x4a, 0xe0, 0xaf, 0xcf, 0x7b, 0xac, 0xac, 0xe1, 0x73, 0x7e, 0xeb, 0xb3, 0x79, 0x51, 0x2c,
  0x6d, 0xdc, 0xa2, 0xcf, 0xc7, 0x11, 0x68, 0xf2, 0xcb, 0x7d, 0x95, 0xee, 0x95, 0x5c, 0x7e, 0xb4,
  0x4c, 0x8e, 0x00, 0xa9, 0x29, 0x41, 0xb1, 0xe4, 0xfd, 0xb2, 0xa0, 0x8e, 0x9c, 0x9a, 0x1c, 0x95,
  0x4a, 0xdc, 0x4e, 0x31, 0xc7, 0xf6, 0xfa, 0x2f, 0x4c, 0x2d, 0x58, 0x8a, 0x83, 0x91, 0x2d, 0xc6,
  0xd1, 0x26, 0xf0, 0xfa, 0xaa, 0xe3, 0x26, 0x68, 0x60, 0x79, 0x8a, 0xe5, 0x1d, 0x22, 0x15, 0x01,
  0x49, 0xcc, 0x8a, 0x3f, 0x6e, 0x38, 0x8e, 0xf6, 0x60, 0x66, 0xe3, 0xbc, 0xc5, 0x80, 0x55, 0x51,
  0xca, 0xc7, 0x53, 0x1b, 0x5e, 0xa4, 0x17, 0xc4, 0xfd, 0x4a, 0x64, 0x22, 0x2f, 0x5b, 0x8e, 0xda,
  0xa7, 0x7a, 0xea, 0x8b, 0xd8, 0x0c, 0x85, 0xa1, 0xd8, 0x28, 0xcc, 0x12, 0x75, 0x08, 0xb0, 0x58,
  0x1d, 0xa0, 0x9c, 0x8c, 0x56, 0xae, 0x73, 0xd7, 0xc3, 0xa8, 0x86, 0xd4, 0x7f, 0x3a, 0xaa, 0x31,
  0xc6, 0xcd, 0x38, 0x4e, 0x1c, 0x6e, 0xfe, 0x09, 0xec, 0x07, 0x61, 0x93, 0x41, 0x26, 0x15, 0x70,
  0x82, 0x71, 0x64, 0xdf, 0xd3, 0x5d, 0x61, 0x07, 0x30, 0x2c, 0x7d, 0x06, 0xbc, 0x2e, 0x5d, 0x04,
  0xb5, 0xd8, 0x16, 0xc7, 0xa8, 0xe8, 0xc7, 0xa6, 0xfc, 0xdc, 0xf4, 0x7f
};

const uint8_t ID1_KEY2_CERT1[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x02, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x01, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xad, 0xf6, 0x81, 0xfc, 0x8d, 0xa2, 0x3f, 0x13, 0x1d, 0x63, 0x1c, 0x2b, 0x8b, 0xaa, 0xa4,
  0x55, 0x2c, 0xbf, 0xf7, 0x48, 0xd4, 0x01, 0xfe, 0x66, 0xa0, 0x4b, 0x2b, 0xf8, 0xfd, 0x19, 0x07,
  0xba, 0x75, 0x99, 0x2a, 0x8a, 0x19, 0x5f, 0xe1, 0xc4, 0xa6, 0xd4, 0xfb, 0xca, 0xc5, 0x7f, 0x2f,
  0xcc, 0x35, 0x2a, 0xa3, 0x7c, 0x8b, 0x52, 0x0a, 0x0e, 0x4d, 0xe1, 0xe0, 0x1f, 0xf9, 0x0d, 0x2e,
  0x09, 0x38, 0x44, 0x1d, 0x4e, 0x48, 0x23, 0xe7, 0xa4, 0xa8, 0xd3, 0x94, 0x30, 0x9e, 0x47, 0x12,
  0x04, 0xc7, 0x27, 0x37, 0xb4, 0x79, 0x71, 0x5a, 0xf3, 0xaf, 0x1e, 0xdc, 0x1f, 0x41, 0x4b, 0x42,
  0xe7, 0xbe, 0x94, 0xf1, 0x0c, 0x99, 0x4b, 0x3d, 0x9c, 0x4a, 0x3e, 0xd9, 0x50, 0xac, 0x04, 0x9c,
  0x78, 0x06, 0x0f, 0xd3, 0x1c, 0x94, 0x54, 0xa2, 0x8a, 0x9f, 0x2a, 0x92, 0x7a, 0x51, 0x7d, 0xa8,
  0x49, 0xc3, 0xf9, 0x9e, 0xb7, 0x6e, 0x00, 0xeb, 0xee, 0x29, 0x60, 0xea, 0xa7, 0x74, 0x2f, 0x7e,
  0x1e, 0xe0, 0x52, 0x87, 0x59, 0x6a, 0x1d, 0xae, 0x58, 0x05, 0x3b, 0x1b, 0x86, 0x07, 0x48, 0x03,
  0xf5, 0xc7, 0x95, 0x4a, 0xc8, 0x7e, 0x68, 0xa5, 0x04, 0xe5, 0x8d, 0xe7, 0x2d, 0x37, 0x6d, 0x98,
  0xc0, 0x95, 0x54, 0x39, 0xeb, 0xb8, 0x58, 0xff, 0x4d, 0xf8, 0xef, 0x9c, 0x39, 0xe0, 0xe1, 0xe0,
  0x01, 0xf4, 0x8b, 0xc7, 0x98, 0x08, 0xd6, 0x7e, 0x21, 0x4f, 0x70, 0x35, 0xba, 0xde, 0x94, 0x9c,
  0x35, 0x07, 0xab, 0x90, 0xcd, 0x0c, 0x83, 0x1f, 0x9e, 0x27, 0xfd, 0xf5, 0xff, 0x48, 0x78, 0xa2,
  0x74, 0xaa, 0x1f, 0x60, 0x0c, 0x92, 0x8b, 0x87, 0xc7, 0x05, 0x51, 0x58, 0xfd, 0xb2, 0xdd, 0x34,
  0x55, 0x2e, 0xbe, 0x71, 0x8b, 0xaa, 0xd3, 0x4b, 0x49, 0x46, 0x1e, 0xc5, 0x99, 0xce, 0x9e, 0x5e,
  0x31, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x02, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x0a, 0xdb, 0x21, 0xab,
  0xf6, 0xa6, 0x81, 0xb0, 0x95, 0xb6, 0x2c, 0x7b, 0x40, 0x9d, 0x9a, 0x15, 0xdd, 0x9b, 0xb1, 0x5f,
  0x20, 0xc9, 0x1c, 0xfb, 0x30, 0x90, 0x2c, 0x57, 0x11, 0x7f, 0x7d, 0x3d, 0x37, 0xdb, 0x8e, 0x80,
  0xee, 0x25, 0xe3, 0x6e, 0x90, 0x67, 0x7e, 0xef, 0x44, 0xc3, 0xc7, 0x50, 0xa6, 0xa8, 0x51, 0x39,
  0x60, 0xfc, 0x57, 0xb7, 0xed, 0xc0, 0x79, 0xd1, 0xa0, 0xcd, 0x89, 0x6b, 0x20, 0x89, 0xa0, 0x78,
  0x42, 0x12, 0xca, 0x0e, 0x41, 0x8a, 0x7a, 0xa0, 0x82, 0x3d, 0xb4, 0x1b, 0x32, 0xff, 0x1e, 0xc7,
  0xb5, 0xa6, 0x97, 0x3b, 0x26, 0x77, 0x7c, 0x49, 0x96, 0x1b, 0x32, 0x79, 0xa7, 0x0e, 0x73, 0x97,
  0x7e, 0xfd, 0xf4, 0x49, 0x95, 0xe8, 0x31, 0xe3, 0x09, 0x64, 0x16, 0xad, 0xfc, 0x30, 0x53, 0x1e,
  0x2c, 0x17, 0xe2, 0xf0, 0x54, 0x31, 0x24, 0x86, 0x1e, 0xeb, 0xb7, 0x3b, 0xdd, 0xfe, 0xcb, 0x2c,
  0x12, 0x9d, 0x84, 0xe9, 0x6d, 0x37, 0x49, 0xc6, 0x5a, 0xa9, 0x5e, 0x1b, 0x35, 0x67, 0x06, 0xf1,
  0x44, 0xb7, 0x95, 0xc1, 0x9d, 0x0a, 0xd7, 0xbf, 0x30, 0x1c, 0x4b, 0x55, 0x7a, 0xa8, 0x02, 0xb3,
  0xf9, 0xff, 0x3a, 0xb9, 0x69, 0x6f, 0x81, 0xbe, 0x26, 0x01, 0x7b, 0xda, 0x14, 0x39, 0x4a, 0xa9,
  0xf3, 0x51, 0xd8, 0xf0, 0x00, 0x6d, 0x34, 0xee, 0x99, 0xc8, 0x39, 0x18, 0xc0, 0x6c, 0x81, 0xa6,
  0xbb, 0xf0, 0x1e, 0xbc, 0x30, 0x22, 0x97, 0x9e, 0x8b, 0x25, 0xf1, 0xf4, 0x1b, 0x90, 0xb5, 0x66,
  0x0a, 0xfd, 0x66, 0x03, 0x93, 0xcc, 0xe1, 0x2e, 0xd9, 0x20, 0xf1, 0xe3, 0x01, 0x28, 0x16, 0xd6,
  0x9d, 0x74, 0x3d, 0xdd, 0xe1, 0x92, 0x72, 0xb1, 0xac, 0x84, 0x43, 0x50, 0x53, 0xc2, 0xf7, 0x6c,
  0xb9, 0x55, 0x93, 0x26, 0xcf, 0x45, 0x9c, 0xcc, 0xfb, 0xe1, 0x58, 0xef
};

const uint8_t ID1_KEY2_CERT2[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x02, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x02, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xad, 0xf6, 0x81, 0xfc, 0x8d, 0xa2, 0x3f, 0x13, 0x1d, 0x63, 0x1c, 0x2b, 0x8b, 0xaa, 0xa4,
  0x55, 0x2c, 0xbf, 0xf7, 0x48, 0xd4, 0x01, 0xfe, 0x66, 0xa0, 0x4b, 0x2b, 0xf8, 0xfd, 0x19, 0x07,
  0xba, 0x75, 0x99, 0x2a, 0x8a, 0x19, 0x5f, 0xe1, 0xc4, 0xa6, 0xd4, 0xfb, 0xca, 0xc5, 0x7f, 0x2f,
  0xcc, 0x35, 0x2a, 0xa3, 0x7c, 0x8b, 0x52, 0x0a, 0x0e, 0x4d, 0xe1, 0xe0, 0x1f, 0xf9, 0x0d, 0x2e,
  0x09, 0x38, 0x44, 0x1d, 0x4e, 0x48, 0x23, 0xe7, 0xa4, 0xa8, 0xd3, 0x94, 0x30, 0x9e, 0x47, 0x12,
  0x04, 0xc7, 0x27, 0x37, 0xb4, 0x79, 0x71, 0x5a, 0xf3, 0xaf, 0x1e, 0xdc, 0x1f, 0x41, 0x4b, 0x42,
  0xe7, 0xbe, 0x94, 0xf1, 0x0c, 0x99, 0x4b, 0x3d, 0x9c, 0x4a, 0x3e, 0xd9, 0x50, 0xac, 0x04, 0x9c,
  0x78, 0x06, 0x0f, 0xd3, 0x1c, 0x94, 0x54, 0xa2, 0x8a, 0x9f, 0x2a, 0x92, 0x7a, 0x51, 0x7d, 0xa8,
  0x49, 0xc3, 0xf9, 0x9e, 0xb7, 0x6e, 0x00, 0xeb, 0xee, 0x29, 0x60, 0xea, 0xa7, 0x74, 0x2f, 0x7e,
  0x1e, 0xe0, 0x52, 0x87, 0x59, 0x6a, 0x1d, 0xae, 0x58, 0x05, 0x3b, 0x1b, 0x86, 0x07, 0x48, 0x03,
  0xf5, 0xc7, 0x95, 0x4a, 0xc8, 0x7e, 0x68, 0xa5, 0x04, 0xe5, 0x8d, 0xe7, 0x2d, 0x37, 0x6d, 0x98,
  0xc0, 0x95, 0x54, 0x39, 0xeb, 0xb8, 0x58, 0xff, 0x4d, 0xf8, 0xef, 0x9c, 0x39, 0xe0, 0xe1, 0xe0,
  0x01, 0xf4, 0x8b, 0xc7, 0x98, 0x08, 0xd6, 0x7e, 0x21, 0x4f, 0x70, 0x35, 0xba, 0xde, 0x94, 0x9c,
  0x35, 0x07, 0xab, 0x90, 0xcd, 0x0c, 0x83, 0x1f, 0x9e, 0x27, 0xfd, 0xf5, 0xff, 0x48, 0x78, 0xa2,
  0x74, 0xaa, 0x1f, 0x60, 0x0c, 0x92, 0x8b, 0x87, 0xc7, 0x05, 0x51, 0x58, 0xfd, 0xb2, 0xdd, 0x34,
  0x55, 0x2e, 0xbe, 0x71, 0x8b, 0xaa, 0xd3, 0x4b, 0x49, 0x46, 0x1e, 0xc5, 0x99, 0xce, 0x9e, 0x5e,
  0x31, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x31, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x02, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x12, 0x36, 0x29, 0x78,
  0x9b, 0xf2, 0xee, 0xe8, 0xeb, 0x61, 0x5a, 0xdd, 0x30, 0x21, 0xa1, 0x9c, 0x59, 0xb3, 0x3a, 0x4f,
  0xd2, 0xef, 0x60, 0x16, 0x5c, 0x0b, 0x4a, 0x14, 0x5d, 0xc6, 0xd2, 0x58, 0x39, 0x25, 0x7d, 0xd6,
  0x58, 0x00, 0x92, 0x74, 0x51, 0x47, 0xda, 0x33, 0x59, 0xeb, 0xd9, 0x80, 0x45, 0xf8, 0xd6, 0xba,
  0x4f, 0xb0, 0x67, 0xfd, 0x87, 0x74, 0x7c, 0x2b, 0xb7, 0xd9, 0x7a, 0x15, 0xa5, 0x26, 0x02, 0x4b,
  0x80, 0x23, 0xc1, 0x8c, 0x14, 0x4c, 0x69, 0x5c, 0x14, 0x0c, 0xa3, 0x9a, 0xb2, 0x09, 0xc0, 0x8a,
  0xbf, 0x70, 0xaf, 0xc5, 0x89, 0xfa, 0x98, 0xf1, 0xc2, 0xed, 0x02, 0x3b, 0x11, 0x17, 0xbb, 0xd7,
  0x0c, 0x13, 0xb1, 0xad, 0x96, 0x2f, 0x27, 0xfe, 0x14, 0x94, 0x2e, 0x4e, 0x0e, 0x20, 0xd6, 0x70,
  0x4c, 0xda, 0xf0, 0x01, 0x73, 0xfa, 0x69, 0x07, 0xe3, 0x79, 0xa1, 0x9a, 0x8d, 0xba, 0xbb, 0x7f,
  0x58, 0x1b, 0x5b, 0x65, 0xcb, 0x09, 0xf0, 0x20, 0x99, 0x09, 0x98, 0x58, 0xec, 0xa3, 0x9c, 0x6f,
  0x3c, 0x1a, 0xc1, 0xe6, 0x72, 0xad, 0xa2, 0xa7, 0x84, 0x76, 0x8a, 0xc2, 0xb6, 0xcf, 0x2d, 0x48,
  0x7b, 0x7d, 0x15, 0x06, 0x66, 0x2a, 0xc5, 0x77, 0x39, 0x3b, 0x4a, 0x61, 0x83, 0x0b, 0x3c, 0x03,
  0xff, 0xcf, 0x4b, 0x44, 0xae, 0x28, 0x1f, 0x30, 0x71, 0x12, 0x54, 0xc8, 0xf7, 0xba, 0xe3, 0x68,
  0xc8, 0x9f, 0x7d, 0xc0, 0x5f, 0x32, 0x63, 0xae, 0x0c, 0x3b, 0x53, 0x13, 0xe5, 0x49, 0xd3, 0xf9,
  0xf9, 0x59, 0x9e, 0xa0, 0x31, 0xdb, 0x7b, 0x8d, 0x55, 0xa4, 0x02, 0xaf, 0xd4, 0xc2, 0x78, 0xca,
  0xff, 0x0f, 0x7f, 0x0c, 0x9b, 0x17, 0x6e, 0x09, 0xa1, 0x86, 0xbe, 0x71, 0xde, 0x56, 0xae, 0xe5,
  0x98, 0x41, 0x67, 0x38, 0x38, 0x50, 0x96, 0x52, 0x32, 0x0c, 0xa9, 0xc7
};

const uint8_t ID2_KEY1_CERT1[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x01, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x01, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xa4, 0xec, 0xd8, 0xd5, 0xef, 0x86, 0xaf, 0x92, 0xb5, 0x95, 0xa1, 0xc0, 0x97, 0xb5, 0xed,
  0x8e, 0x1a, 0x8b, 0x98, 0x25, 0xb6, 0xe2, 0x94, 0x5a, 0x91, 0x78, 0xa5, 0xd2, 0x10, 0xa7, 0x70,
  0x87, 0x11, 0xc4, 0xdb, 0x1c, 0x87, 0xe9, 0x41, 0xd3, 0xd0, 0x7c, 0xc4, 0xc2, 0xe2, 0xd9, 0x35,
  0x33, 0xb0, 0xf1, 0xe5, 0x6a, 0x29, 0xd4, 0x15, 0x11, 0x5f, 0x8a, 0xff, 0xf9, 0x41, 0x8e, 0x8f,
  0xe2, 0xd8, 0x3f, 0x0c, 0x70, 0xe1, 0xb8, 0x74, 0x60, 0xff, 0x5f, 0x7c, 0xc3, 0x3a, 0x14, 0x83,
  0xf2, 0x27, 0x19, 0xa7, 0xa5, 0x45, 0x6d, 0x26, 0x22, 0xd6, 0x6b, 0x2f, 0xa0, 0xae, 0x39, 0xa7,
  0x9c, 0x1e, 0xaa, 0x05, 0xa6, 0x5e, 0xc3, 0x79, 0x5d, 0x87, 0xc5, 0x0e, 0x6e, 0x86, 0xbf, 0x81,
  0x11, 0xfa, 0x19, 0x34, 0x91, 0xb3, 0x1d, 0x8b, 0x8d, 0xbd, 0xd6, 0x1e, 0x98, 0x97, 0x21, 0x26,
  0xbb, 0x7a, 0x21, 0x69, 0x42, 0x30, 0x57, 0x63, 0x20, 0xb7, 0x9c, 0xe7, 0x9d, 0x7c, 0x77, 0x37,
  0x20, 0x0e, 0x00, 0x54, 0xf4, 0x39, 0xbd, 0xc7, 0x40, 0x2f, 0xef, 0xae, 0x3a, 0x3a, 0x68, 0xb5,
  0xc9, 0x4c, 0xe7, 0x7a, 0xba, 0xca, 0x91, 0x95, 0xbe, 0xc3, 0x49, 0x9b, 0xbc, 0xea, 0x73, 0x6e,
  0x54, 0x32, 0x24, 0xc3, 0x7e, 0x43, 0x19, 0x9b, 0xa5, 0xe0, 0x62, 0x05, 0x5b, 0x44, 0xb7, 0x66,
  0x0b, 0xd1, 0x05, 0xde, 0x12, 0x92, 0xa0, 0x63, 0xb9, 0xfd, 0x05, 0x2a, 0x86, 0xe4, 0x5e, 0x48,
  0xd9, 0xb0, 0x2d, 0x28, 0x63, 0x13, 0x7a, 0x47, 0x75, 0x71, 0xaa, 0xd7, 0x02, 0xa4, 0x2e, 0x5e,
  0x08, 0x8d, 0xff, 0x9c, 0xb3, 0x4d, 0x1f, 0x8e, 0x7b, 0xa3, 0x7d, 0x88, 0xc0, 0xd3, 0x45, 0xe6,
  0xd1, 0x2a, 0x8e, 0x63, 0x5c, 0x6b, 0x35, 0xde, 0x60, 0x3d, 0x06, 0x41, 0xbf, 0x6f, 0xf1, 0x7c,
  0xa1, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x01, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x84, 0x96, 0xe5, 0xf7,
  0x43, 0x40, 0x2f, 0xbe, 0x29, 0x97, 0x52, 0xeb, 0x03, 0x71, 0x1b, 0xba, 0xa7, 0x6a, 0x48, 0xb3,
  0x57, 0xcf, 0xbf, 0x86, 0x4b, 0xe5, 0x7a, 0x7c, 0x2e, 0x08, 0x1a, 0x43, 0xc2, 0xbd, 0xff, 0x1f,
  0x56, 0xfd, 0xf9, 0xf3, 0x2b, 0x28, 0xcc, 0x77, 0x8c, 0xee, 0x91, 0xe3, 0x58, 0x39, 0xf1, 0x35,
  0x0a, 0x8d, 0xbc, 0x4b, 0xf2, 0x51, 0x62, 0x6f, 0xc2, 0xb9, 0x3d, 0x20, 0x88, 0x35, 0x5f, 0x70,
  0xd5, 0xb1, 0x70, 0xac, 0x0e, 0x8f, 0x4b, 0x16, 0xa2, 0xab, 0xe2, 0xeb, 0x6c, 0xd2, 0xd5, 0x3f,
  0x3a, 0x18, 0xc0, 0xe1, 0x4b, 0xac, 0xbd, 0xca, 0x68, 0xa9, 0x7f, 0x94, 0xd0, 0x53, 0x01, 0x4d,
  0x09, 0x9e, 0x04, 0x08, 0x5e, 0xa2, 0x2d, 0xda, 0x95, 0x48, 0xe3, 0x4d, 0x4c, 0xfa, 0x3c, 0xdf,
  0xa3, 0xb2, 0x07, 0x38, 0x39, 0x07, 0x4d, 0x3a, 0xbe, 0x35, 0x99, 0xbd, 0x78, 0x5c, 0x76, 0x40,
  0x66, 0xbf, 0xb5, 0x87, 0x2b, 0x21, 0x77, 0xfa, 0xf2, 0x65, 0xa2, 0x2a, 0xe3, 0xcf, 0xf1, 0x8a,
  0x84, 0x5f, 0xe9, 0x9c, 0xee, 0x58, 0x05, 0xf2, 0x39, 0x40, 0xc2, 0x9a, 0xea, 0x78, 0xad, 0xde,
  0xfa, 0x28, 0x22, 0x7c, 0xd9, 0xf4, 0x53, 0x4e, 0x41, 0x22, 0x3e, 0x23, 0x5a, 0x78, 0x50, 0x47,
  0x71, 0x84, 0xb1, 0xb4, 0x95, 0xf8, 0x91, 0xe9, 0xdf, 0xb0, 0xcd, 0x56, 0x87, 0xe2, 0xa1, 0x20,
  0x8c, 0x7d, 0x01, 0x95, 0x6c, 0xb1, 0xbc, 0xe6, 0x57, 0x8c, 0x85, 0x86, 0x91, 0x14, 0xb3, 0x90,
  0x62, 0xbd, 0x39, 0x7f, 0xf0, 0xa3, 0x5c, 0x1b, 0xdc, 0x50, 0x3c, 0xf0, 0xe2, 0x8d, 0x67, 0x9c,
  0xee, 0x8c, 0x2a, 0x09, 0xfb, 0x48, 0xfc, 0x71, 0x31, 0xac, 0x78, 0xab, 0x5c, 0xc3, 0x90, 0xdf,
  0x2a, 0x9c, 0x86, 0x0e, 0x58, 0xf3, 0xbc, 0x8a, 0xe2, 0xe6, 0xf2, 0x63
};

const uint8_t ID2_KEY1_CERT2[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x01, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x02, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xa4, 0xec, 0xd8, 0xd5, 0xef, 0x86, 0xaf, 0x92, 0xb5, 0x95, 0xa1, 0xc0, 0x97, 0xb5, 0xed,
  0x8e, 0x1a, 0x8b, 0x98, 0x25, 0xb6, 0xe2, 0x94, 0x5a, 0x91, 0x78, 0xa5, 0xd2, 0x10, 0xa7, 0x70,
  0x87, 0x11, 0xc4, 0xdb, 0x1c, 0x87, 0xe9, 0x41, 0xd3, 0xd0, 0x7c, 0xc4, 0xc2, 0xe2, 0xd9, 0x35,
  0x33, 0xb0, 0xf1, 0xe5, 0x6a, 0x29, 0xd4, 0x15, 0x11, 0x5f, 0x8a, 0xff, 0xf9, 0x41, 0x8e, 0x8f,
  0xe2, 0xd8, 0x3f, 0x0c, 0x70, 0xe1, 0xb8, 0x74, 0x60, 0xff, 0x5f, 0x7c, 0xc3, 0x3a, 0x14, 0x83,
  0xf2, 0x27, 0x19, 0xa7, 0xa5, 0x45, 0x6d, 0x26, 0x22, 0xd6, 0x6b, 0x2f, 0xa0, 0xae, 0x39, 0xa7,
  0x9c, 0x1e, 0xaa, 0x05, 0xa6, 0x5e, 0xc3, 0x79, 0x5d, 0x87, 0xc5, 0x0e, 0x6e, 0x86, 0xbf, 0x81,
  0x11, 0xfa, 0x19, 0x34, 0x91, 0xb3, 0x1d, 0x8b, 0x8d, 0xbd, 0xd6, 0x1e, 0x98, 0x97, 0x21, 0x26,
  0xbb, 0x7a, 0x21, 0x69, 0x42, 0x30, 0x57, 0x63, 0x20, 0xb7, 0x9c, 0xe7, 0x9d, 0x7c, 0x77, 0x37,
  0x20, 0x0e, 0x00, 0x54, 0xf4, 0x39, 0xbd, 0xc7, 0x40, 0x2f, 0xef, 0xae, 0x3a, 0x3a, 0x68, 0xb5,
  0xc9, 0x4c, 0xe7, 0x7a, 0xba, 0xca, 0x91, 0x95, 0xbe, 0xc3, 0x49, 0x9b, 0xbc, 0xea, 0x73, 0x6e,
  0x54, 0x32, 0x24, 0xc3, 0x7e, 0x43, 0x19, 0x9b, 0xa5, 0xe0, 0x62, 0x05, 0x5b, 0x44, 0xb7, 0x66,
  0x0b, 0xd1, 0x05, 0xde, 0x12, 0x92, 0xa0, 0x63, 0xb9, 0xfd, 0x05, 0x2a, 0x86, 0xe4, 0x5e, 0x48,
  0xd9, 0xb0, 0x2d, 0x28, 0x63, 0x13, 0x7a, 0x47, 0x75, 0x71, 0xaa, 0xd7, 0x02, 0xa4, 0x2e, 0x5e,
  0x08, 0x8d, 0xff, 0x9c, 0xb3, 0x4d, 0x1f, 0x8e, 0x7b, 0xa3, 0x7d, 0x88, 0xc0, 0xd3, 0x45, 0xe6,
  0xd1, 0x2a, 0x8e, 0x63, 0x5c, 0x6b, 0x35, 0xde, 0x60, 0x3d, 0x06, 0x41, 0xbf, 0x6f, 0xf1, 0x7c,
  0xa1, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x01, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x37, 0x1a, 0x68, 0x00,
  0x94, 0xdf, 0x4c, 0xdb, 0x9c, 0xa7, 0x09, 0xe8, 0xb3, 0x95, 0x14, 0xd2, 0x77, 0x75, 0xd1, 0x67,
  0x91, 0x0e, 0x83, 0x69, 0x6d, 0x39, 0xaa, 0x11, 0xc6, 0x5e, 0x8f, 0xfb, 0x2b, 0x9c, 0x22, 0x17,
  0xe5, 0x5b, 0xfb, 0x05, 0x28, 0xef, 0x3b, 0x18, 0x0c, 0xcc, 0xd0, 0xe6, 0xa3, 0xee, 0x13, 0x12,
  0xba, 0x72, 0x74, 0x5e, 0xb5, 0x23, 0x09, 0x9d, 0xd1, 0x5d, 0x8e, 0x5b, 0x51, 0x91, 0xe9, 0x77,
  0xf5, 0xa7, 0x00, 0xb8, 0xce, 0x76, 0xeb, 0x2b, 0x9d, 0x45, 0x35, 0x27, 0xdd, 0x5a, 0x37, 0x27,
  0x23, 0xe2, 0x6e, 0xb8, 0xba, 0x8e, 0x2e, 0xc5, 0x04, 0x4a, 0xad, 0xeb, 0x86, 0xe8, 0x32, 0x2e,
  0x63, 0x91, 0x53, 0x8f, 0xc4, 0xb3, 0x0e, 0x0e, 0x7d, 0x21, 0xf7, 0xcc, 0xe4, 0x8c, 0x77, 0x4a,
  0x08, 0x4f, 0x51, 0x65, 0xf2, 0x67, 0xb1, 0x0c, 0xf1, 0x41, 0x17, 0x2e, 0x65, 0x84, 0xa9, 0x15,
  0x9e, 0x8b, 0xbe, 0x16, 0x35, 0x2c, 0x73, 0x14, 0xae, 0x0d, 0x68, 0x89, 0xda, 0xf2, 0x5e, 0x01,
  0xaa, 0x3c, 0x9e, 0x9b, 0x27, 0xe1, 0x7e, 0xf4, 0xad, 0xa8, 0x93, 0x82, 0xa5, 0x77, 0xd8, 0x9a,
  0x20, 0x5b, 0x61, 0xc2, 0xed, 0x66, 0x6f, 0x50, 0xcf, 0x7d, 0x86, 0x7a, 0x07, 0xe7, 0x85, 0x59,
  0xb4, 0x25, 0xfb, 0xfa, 0x36, 0xf5, 0x23, 0x0f, 0x2d, 0xf1, 0x72, 0x0c, 0xb8, 0xcc, 0x34, 0x06,
  0x80, 0x2b, 0x2b, 0x8d, 0x83, 0x7a, 0xb7, 0x96, 0xb3, 0x5b, 0xcd, 0x26, 0x98, 0x08, 0xad, 0xb1,
  0xf9, 0xdd, 0x6a, 0xae, 0x7e, 0xc3, 0xd5, 0x14, 0xc5, 0xa3, 0x0a, 0xa3, 0x48, 0xbc, 0xf7, 0x9e,
  0x2a, 0x0d, 0xff, 0xb4, 0x9b, 0xb0, 0xfe, 0xbe, 0x3f, 0xba, 0x5e, 0xd9, 0x4c, 0x93, 0x82, 0x9e,
  0x94, 0x43, 0x23, 0x4e, 0x26, 0x7e, 0x65, 0xc1, 0xb3, 0x3c, 0x06, 0x23
};

const uint8_t ID2_KEY2_CERT1[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x02, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x01, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xe8, 0xfc, 0xf6, 0xbc, 0xdb, 0xcb, 0x07, 0xae, 0xcd, 0xe4, 0xd0, 0xc9, 0xeb, 0xbf, 0xad,
  0xc1, 0xf7, 0xb7, 0x67, 0x11, 0x33, 0x80, 0x05, 0x10, 0xbb, 0x30, 0xf3, 0x02, 0xf5, 0xd3, 0xfa,
  0x29, 0xdc, 0x88, 0xc1, 0x42, 0xc8, 0x23, 0xc7, 0x8d, 0x25, 0x51, 0xf0, 0x31, 0x62, 0x83, 0xb7,
  0xd5, 0xe1, 0xc9, 0x90, 0xaa, 0x62, 0x7e, 0xcd, 0x48, 0x0d, 0x22, 0xbe, 0x9a, 0x83, 0xe7, 0x8c,
  0x47, 0x86, 0x68, 0x37, 0x8a, 0xba, 0xf5, 0xdc, 0xa0, 0xd1, 0x29, 0x22, 0xe3, 0x60, 0x4e, 0x1f,
  0x94, 0x9e, 0x87, 0x0a, 0x31, 0x68, 0x4a, 0x85, 0x1a, 0x48, 0x54, 0x5d, 0x37, 0xe8, 0xfc, 0x60,
  0xcc, 0x1a, 0x2e, 0xc9, 0xc6, 0xb3, 0x57, 0xf6, 0x04, 0x97, 0x9c, 0x54, 0x95, 0x71, 0x6e, 0x27,
  0x4b, 0xb3, 0xab, 0xbc, 0x67, 0xe1, 0xf4, 0x79, 0x26, 0x7e, 0x6a, 0x51, 0xf8, 0x45, 0xa0, 0xac,
  0xeb, 0x8a, 0x5b, 0xda, 0x3b, 0x13, 0x33, 0x0d, 0x18, 0xd3, 0x18, 0xcd, 0xcd, 0x63, 0xb0, 0xba,
  0xd6, 0xfa, 0x19, 0x2d, 0xd9, 0x0c, 0xdf, 0x99, 0x03, 0x9c, 0xfb, 0x60, 0x9e, 0x54, 0x0d, 0x9d,
  0x2b, 0x9f, 0xc1, 0x70, 0xf5, 0xae, 0x89, 0xd4, 0x8d, 0x5a, 0x44, 0x95, 0xd8, 0xf3, 0x7f, 0xe9,
  0x58, 0xb3, 0x03, 0xc2, 0xeb, 0xfa, 0x2e, 0x25, 0x38, 0xa8, 0xc8, 0x52, 0x79, 0x8c, 0x41, 0xec,
  0x1a, 0xb1, 0x2a, 0x4b, 0x07, 0x22, 0x73, 0xac, 0x94, 0x06, 0x3a, 0xed, 0x63, 0xc3, 0x11, 0xf1,
  0xeb, 0x3b, 0x83, 0xd3, 0xf9, 0xf7, 0xc2, 0xd8, 0x8b, 0xbf, 0xfc, 0x79, 0xee, 0xf6, 0xb7, 0xf5,
  0xff, 0x5e, 0x44, 0x38, 0xbd, 0xda, 0x33, 0x52, 0xf5, 0x10, 0xe6, 0x8e, 0x4f, 0x64, 0x6a, 0x7d,
  0x70, 0xd0, 0x52, 0x67, 0x4d, 0x71, 0x6b, 0x1f, 0x8b, 0xec, 0xfb, 0x57, 0xf5, 0x96, 0xa4, 0x24,
  0x5b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x02, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x60, 0x9d, 0x96, 0x3d,
  0x33, 0xb6, 0x6c, 0x2a, 0x39, 0x70, 0x33, 0x94, 0x13, 0x7f, 0x55, 0x60, 0xf4, 0xd6, 0xf1, 0x63,
  0x82, 0xd4, 0xb9, 0xce, 0x68, 0x27, 0x80, 0xc8, 0x00, 0x1f, 0x5f, 0xe3, 0x3d, 0x17, 0x8d, 0x16,
  0x41, 0xd7, 0x55, 0xad, 0x10, 0xe1, 0x00, 0xb1, 0x41, 0x35, 0x6f, 0x3b, 0xcf, 0x0c, 0x7b, 0x5b,
  0x94, 0x43, 0x7c, 0x8d, 0x05, 0x63, 0xe6, 0x82, 0x4f, 0x55, 0x63, 0x83, 0x5d, 0x1a, 0x77, 0xa7,
  0xf3, 0xee, 0x21, 0xd2, 0xf0, 0x03, 0x5f, 0x86, 0x4c, 0x85, 0x19, 0x17, 0x96, 0xf9, 0xaa, 0x35,
  0x41, 0x06, 0x45, 0xc3, 0x17, 0xe7, 0xa1, 0xcd, 0x4f, 0xe3, 0x87, 0x14, 0xd6, 0x9f, 0xde, 0xf4,
  0x07, 0x3a, 0x2f, 0x08, 0xe3, 0x70, 0xe6, 0xae, 0xe5, 0xe1, 0x0e, 0x82, 0x89, 0xe3, 0xe2, 0xb4,
  0x00, 0x45, 0x32, 0xaa, 0x6a, 0xc2, 0x96, 0x61, 0xee, 0x95, 0x02, 0xac, 0x37, 0x7f, 0xe2, 0x41,
  0xf4, 0x88, 0x14, 0x86, 0x2a, 0xc6, 0xfe, 0x46, 0x43, 0x70, 0x81, 0x08, 0x91, 0x1f, 0x9b, 0xd3,
  0xdf, 0xbc, 0xa4, 0xef, 0xdf, 0x9b, 0x3b, 0x62, 0x27, 0x89, 0x8b, 0x64, 0x38, 0x19, 0x63, 0x6a,
  0x3e, 0x92, 0xf9, 0x73, 0xc0, 0xfe, 0x9c, 0xfb, 0xff, 0xff, 0xc8, 0x66, 0xc1, 0x1a, 0x8b, 0x86,
  0x12, 0x36, 0x08, 0x1f, 0xb9, 0x68, 0x2f, 0xe9, 0xea, 0x15, 0xb7, 0xcc, 0xc7, 0xf2, 0x7f, 0x88,
  0x36, 0xa4, 0x86, 0xd2, 0xf4, 0xe4, 0x65, 0xbd, 0x79, 0xf0, 0x9c, 0x3b, 0xdd, 0x93, 0x9f, 0x87,
  0x79, 0x14, 0xdd, 0x71, 0xb3, 0x3b, 0xc0, 0x94, 0x2f, 0x91, 0x06, 0xc5, 0x23, 0x59, 0xf2, 0x57,
  0xa1, 0x0f, 0x81, 0x6d, 0x0f, 0x53, 0xef, 0x45, 0x7f, 0xe5, 0x5b, 0x53, 0x84, 0xb5, 0xcc, 0x29,
  0xe9, 0xcd, 0x74, 0xcd, 0x54, 0xd4, 0xdf, 0xae, 0x9f, 0x60, 0x61, 0x69
};

const uint8_t ID2_KEY2_CERT2[] = {
  0x06, 0xfd, 0x02, 0xb8, 0x07, 0x2b, 0x08, 0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74,
  0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08, 0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b,
  0x45, 0x59, 0x08, 0x01, 0x02, 0x08, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x08, 0x02, 0xfd,
  0x02, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36, 0xee, 0x80, 0x15, 0xfd, 0x01, 0x26,
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
  0x00, 0xe8, 0xfc, 0xf6, 0xbc, 0xdb, 0xcb, 0x07, 0xae, 0xcd, 0xe4, 0xd0, 0xc9, 0xeb, 0xbf, 0xad,
  0xc1, 0xf7, 0xb7, 0x67, 0x11, 0x33, 0x80, 0x05, 0x10, 0xbb, 0x30, 0xf3, 0x02, 0xf5, 0xd3, 0xfa,
  0x29, 0xdc, 0x88, 0xc1, 0x42, 0xc8, 0x23, 0xc7, 0x8d, 0x25, 0x51, 0xf0, 0x31, 0x62, 0x83, 0xb7,
  0xd5, 0xe1, 0xc9, 0x90, 0xaa, 0x62, 0x7e, 0xcd, 0x48, 0x0d, 0x22, 0xbe, 0x9a, 0x83, 0xe7, 0x8c,
  0x47, 0x86, 0x68, 0x37, 0x8a, 0xba, 0xf5, 0xdc, 0xa0, 0xd1, 0x29, 0x22, 0xe3, 0x60, 0x4e, 0x1f,
  0x94, 0x9e, 0x87, 0x0a, 0x31, 0x68, 0x4a, 0x85, 0x1a, 0x48, 0x54, 0x5d, 0x37, 0xe8, 0xfc, 0x60,
  0xcc, 0x1a, 0x2e, 0xc9, 0xc6, 0xb3, 0x57, 0xf6, 0x04, 0x97, 0x9c, 0x54, 0x95, 0x71, 0x6e, 0x27,
  0x4b, 0xb3, 0xab, 0xbc, 0x67, 0xe1, 0xf4, 0x79, 0x26, 0x7e, 0x6a, 0x51, 0xf8, 0x45, 0xa0, 0xac,
  0xeb, 0x8a, 0x5b, 0xda, 0x3b, 0x13, 0x33, 0x0d, 0x18, 0xd3, 0x18, 0xcd, 0xcd, 0x63, 0xb0, 0xba,
  0xd6, 0xfa, 0x19, 0x2d, 0xd9, 0x0c, 0xdf, 0x99, 0x03, 0x9c, 0xfb, 0x60, 0x9e, 0x54, 0x0d, 0x9d,
  0x2b, 0x9f, 0xc1, 0x70, 0xf5, 0xae, 0x89, 0xd4, 0x8d, 0x5a, 0x44, 0x95, 0xd8, 0xf3, 0x7f, 0xe9,
  0x58, 0xb3, 0x03, 0xc2, 0xeb, 0xfa, 0x2e, 0x25, 0x38, 0xa8, 0xc8, 0x52, 0x79, 0x8c, 0x41, 0xec,
  0x1a, 0xb1, 0x2a, 0x4b, 0x07, 0x22, 0x73, 0xac, 0x94, 0x06, 0x3a, 0xed, 0x63, 0xc3, 0x11, 0xf1,
  0xeb, 0x3b, 0x83, 0xd3, 0xf9, 0xf7, 0xc2, 0xd8, 0x8b, 0xbf, 0xfc, 0x79, 0xee, 0xf6, 0xb7, 0xf5,
  0xff, 0x5e, 0x44, 0x38, 0xbd, 0xda, 0x33, 0x52, 0xf5, 0x10, 0xe6, 0x8e, 0x4f, 0x64, 0x6a, 0x7d,
  0x70, 0xd0, 0x52, 0x67, 0x4d, 0x71, 0x6b, 0x1f, 0x8b, 0xec, 0xfb, 0x57, 0xf5, 0x96, 0xa4, 0x24,
  0x5b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x50, 0x1b, 0x01, 0x01, 0x1c, 0x21, 0x07, 0x1f, 0x08,
  0x03, 0x70, 0x69, 0x62, 0x08, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x08,
  0x02, 0x69, 0x64, 0x08, 0x01, 0x32, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x01, 0x02, 0xfd, 0x00,
  0xfd, 0x26, 0xfd, 0x00, 0xfe, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x30, 0x31, 0x30, 0x32, 0x54, 0x30,
  0x30, 0x30, 0x30, 0x30, 0x30, 0xfd, 0x00, 0xff, 0x0f, 0x32, 0x30, 0x31, 0x38, 0x30, 0x31, 0x30,
  0x32, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x17, 0xfd, 0x01, 0x00, 0x5c, 0xe2, 0x50, 0x7a,
  0x26, 0xdf, 0x04, 0xaa, 0xda, 0xa7, 0x20, 0x81, 0x56, 0x33, 0xb5, 0x21, 0xfc, 0xd9, 0x9b, 0xe6,
  0x59, 0xa9, 0x9d, 0x10, 0x13, 0x25, 0xf3, 0x57, 0x83, 0xae, 0xc5, 0x7b, 0xa9, 0x58, 0xa2, 0x0f,
  0x8f, 0x0e, 0x08, 0xf3, 0xab, 0xc3, 0xda, 0xaf, 0xa5, 0xb1, 0xab, 0xa3, 0xe2, 0x12, 0x26, 0xfc,
  0x5f, 0x4a, 0xe8, 0x86, 0x9a, 0xe7, 0x7e, 0xb0, 0x7f, 0xf9, 0x32, 0xf3, 0x55, 0x89, 0x10, 0xe0,
  0xca, 0xfd, 0xcf, 0x90, 0x3d, 0xe3, 0xaf, 0x8a, 0x40, 0xbb, 0x7e, 0x80, 0xd1, 0x45, 0x5f, 0x19,
  0x28, 0x26, 0x33, 0x69, 0xed, 0xc5, 0x25, 0xa2, 0xe3, 0xec, 0xc8, 0x76, 0x10, 0x46, 0xf5, 0x1d,
  0xba, 0x49, 0x43, 0xdf, 0x6e, 0x70, 0xa4, 0xdf, 0x9b, 0x55, 0xca, 0xc2, 0xaa, 0xe0, 0x92, 0x92,
  0xff, 0x80, 0x0e, 0x89, 0x01, 0xd6, 0xd7, 0x10, 0x14, 0x46, 0x22, 0x99, 0x37, 0x59, 0x00, 0x7a,
  0x9c, 0x04, 0xb1, 0x8d, 0x62, 0x03, 0xfe, 0xb2, 0x30, 0x1d, 0xff, 0x5d, 0xe0, 0x54, 0xe5, 0x31,
  0xef, 0x6f, 0x04, 0x17, 0x4e, 0x62, 0x51, 0x64, 0xca, 0x94, 0xec, 0xd4, 0xe1, 0x61, 0x2b, 0x84,
  0x67, 0x38, 0xbe, 0x27, 0x2d, 0x42, 0xad, 0x37, 0x80, 0x65, 0x77, 0xde, 0x5e, 0x64, 0xd2, 0x95,
  0x43, 0x7a, 0x1d, 0xd4, 0x41, 0xdb, 0x53, 0xd6, 0x2c, 0x5c, 0x20, 0xfd, 0x7e, 0x7e, 0x39, 0x7c,
  0x9d, 0x8b, 0x63, 0x11, 0x3d, 0x3f, 0x7b, 0x2d, 0x59, 0xff, 0x32, 0xc9, 0x98, 0x35, 0x7d, 0x48,
  0xb4, 0x21, 0xfa, 0x1b, 0x74, 0x79, 0xf3, 0x99, 0xa8, 0xec, 0x07, 0x3e, 0x84, 0x93, 0x43, 0xe3,
  0x6a, 0xcd, 0x20, 0x00, 0x44, 0x65, 0x48, 0xb1, 0x19, 0xe8, 0x64, 0x5f, 0xd4, 0xd6, 0x77, 0x51,
  0xda, 0x69, 0x48, 0x66, 0xe6, 0x94, 0xd2, 0x96, 0xd9, 0x45, 0xce, 0xf1
};

static ptr_lib::shared_ptr<CertificateV2>
encodeCertificate(const uint8_t* array, size_t arrayLength)
{
  ptr_lib::shared_ptr<CertificateV2> result(new CertificateV2());
  result->wireDecode(array, arrayLength);
  return result;
}

PibDataFixture::PibDataFixture()
{
  id1Key1Cert1 = encodeCertificate(ID1_KEY1_CERT1, sizeof(ID1_KEY1_CERT1));
  id1Key1Cert2 = encodeCertificate(ID1_KEY1_CERT2, sizeof(ID1_KEY1_CERT2));
  id1Key2Cert1 = encodeCertificate(ID1_KEY2_CERT1, sizeof(ID1_KEY2_CERT1));
  id1Key2Cert2 = encodeCertificate(ID1_KEY2_CERT2, sizeof(ID1_KEY2_CERT2));

  id2Key1Cert1 = encodeCertificate(ID2_KEY1_CERT1, sizeof(ID2_KEY1_CERT1));
  id2Key1Cert2 = encodeCertificate(ID2_KEY1_CERT2, sizeof(ID2_KEY1_CERT2));
  id2Key2Cert1 = encodeCertificate(ID2_KEY2_CERT1, sizeof(ID2_KEY2_CERT1));
  id2Key2Cert2 = encodeCertificate(ID2_KEY2_CERT2, sizeof(ID2_KEY2_CERT2));

  id1 = id1Key1Cert1->getIdentity();
  id2 = id2Key1Cert1->getIdentity();

  id1Key1Name = id1Key1Cert1->getKeyName();
  id1Key2Name = id1Key2Cert1->getKeyName();

  id2Key1Name = id2Key1Cert1->getKeyName();
  id2Key2Name = id2Key2Cert1->getKeyName();

  id1Key1 = id1Key1Cert1->getPublicKey();
  id1Key2 = id1Key2Cert1->getPublicKey();
  id2Key1 = id2Key1Cert1->getPublicKey();
  id2Key2 = id2Key2Cert1->getPublicKey();
}

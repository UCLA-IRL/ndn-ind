/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
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

/**
 * This example creates a secured interest with Name-based Access Control using
 * a group content key (GCK). It gets the GCK from the access manager and uses
 * it to encrypt a message which is sent in the Interest's ApplicationParameters
 * field. The interest is sent to the responder which decrypts the message,
 * creates a response message, encrypts it and sends a response Data packet.
 * This receives the response, decrypts and prints the response message. This
 * example works with test-access-manager and test-secured-interest-responder.
 */

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <ndn-ind/face.hpp>
#include <ndn-ind/security/validator-null.hpp>
#include <ndn-ind/security/command-interest-preparer.hpp>
#include <ndn-ind/encrypt/encryptor-v2.hpp>
#include <ndn-ind/encrypt/decryptor-v2.hpp>
#include <ndn-ind/transport/tcp-transport.hpp>

using namespace std;
using namespace std::chrono;
using namespace ndn;
using namespace ndn::func_lib;

/**
 * Add a hard-coded identity to the KeyChain for the sender and return its
 * identity name. In a production application, this would simply access the
 * identity in the KeyChain on disk.
 * @param keyChain The KeyChain for the identity.
 * @return The identity name.
 */
static Name
getSenderName(KeyChain& keyChain)
{
  const uint8_t firstMemberSafeBagEncoding[] = {
0x80, 0xFD, 0x07, 0xD1, 0x06, 0xFD, 0x02, 0xB7, 0x07, 0x2D, 0x08, 0x05, 0x66, 0x69, 0x72, 0x73,
0x74, 0x08, 0x04, 0x75, 0x73, 0x65, 0x72, 0x08, 0x03, 0x4B, 0x45, 0x59, 0x08, 0x08, 0x0C, 0x87,
0xEB, 0xE6, 0x55, 0x27, 0x42, 0xD6, 0x08, 0x04, 0x73, 0x65, 0x6C, 0x66, 0x08, 0x09, 0xFD, 0x00,
0x00, 0x01, 0x49, 0x9D, 0x59, 0x8C, 0xA0, 0x14, 0x09, 0x18, 0x01, 0x02, 0x19, 0x04, 0x00, 0x36,
0xEE, 0x80, 0x15, 0xFD, 0x01, 0x26, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82,
0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xB9, 0xFB, 0xEA, 0x51, 0x88, 0x7B, 0xE5, 0x9A, 0x2B,
0x94, 0xCA, 0xF8, 0x3E, 0x70, 0x4D, 0x94, 0x3F, 0x16, 0x2A, 0xDC, 0x81, 0x0E, 0x51, 0xF9, 0xAF,
0x4F, 0xB2, 0x73, 0xFF, 0xDB, 0x1E, 0x78, 0x26, 0xFC, 0x8A, 0xA2, 0x89, 0xAD, 0x11, 0x14, 0xC1,
0x36, 0xA1, 0x82, 0x75, 0xDA, 0x0D, 0x42, 0x8D, 0xA6, 0x9B, 0x2C, 0xF4, 0xE5, 0xC5, 0xDC, 0xEA,
0xB0, 0xC3, 0x15, 0x4F, 0x67, 0x0A, 0x05, 0x36, 0x55, 0x63, 0xF0, 0x2F, 0xF9, 0xC1, 0x24, 0x65,
0x3F, 0xBF, 0x36, 0x08, 0x25, 0xB1, 0x60, 0x24, 0x0D, 0x0F, 0xFC, 0x1F, 0x93, 0xB7, 0x49, 0x15,
0x60, 0x6E, 0x50, 0x0C, 0x7B, 0x48, 0xD4, 0xD1, 0xF4, 0x19, 0x50, 0xBD, 0x61, 0x25, 0xB6, 0xA1,
0x2E, 0xB1, 0x01, 0x96, 0x8E, 0xFD, 0x1E, 0xFD, 0xD7, 0xCA, 0xE5, 0xAB, 0x6A, 0xE5, 0xDE, 0x8C,
0x33, 0xE2, 0xF9, 0x1F, 0xAA, 0x5D, 0x6A, 0x35, 0x13, 0x1B, 0x2F, 0x77, 0x83, 0x33, 0xFC, 0x6F,
0x35, 0x9D, 0x73, 0x9F, 0x07, 0x78, 0x7B, 0xDD, 0x74, 0xEF, 0x37, 0x26, 0x86, 0x72, 0xE4, 0xCF,
0xB4, 0xFE, 0xFB, 0x48, 0x36, 0xFE, 0x91, 0xF3, 0xC3, 0xDC, 0x3F, 0x7F, 0xC6, 0x75, 0x32, 0x55,
0x5E, 0xBE, 0x29, 0x39, 0x95, 0xD6, 0xD0, 0x83, 0x54, 0x2F, 0x99, 0x0D, 0xE8, 0x6F, 0x56, 0x4A,
0x05, 0xCD, 0xC9, 0xFE, 0x57, 0x6E, 0x1F, 0xBF, 0x1F, 0xCA, 0x61, 0x6D, 0x21, 0x49, 0x46, 0x7D,
0x1D, 0xD8, 0x3A, 0x17, 0x67, 0x7F, 0x5F, 0xA6, 0xAD, 0x12, 0x68, 0x6A, 0xBE, 0xDD, 0x58, 0x44,
0x78, 0x50, 0xD2, 0xA1, 0x50, 0xA3, 0xCD, 0x9E, 0x2E, 0x2D, 0x62, 0x34, 0x02, 0xE7, 0xEC, 0xFC,
0xDD, 0x6B, 0x29, 0x41, 0x66, 0x6D, 0x01, 0xB6, 0x5A, 0xB8, 0xC7, 0x7B, 0xEF, 0x6F, 0x70, 0x26,
0x47, 0x6B, 0x1F, 0xB1, 0xA2, 0xA8, 0x25, 0x02, 0x03, 0x01, 0x00, 0x01, 0x16, 0x4D, 0x1B, 0x01,
0x01, 0x1C, 0x1E, 0x07, 0x1C, 0x08, 0x05, 0x66, 0x69, 0x72, 0x73, 0x74, 0x08, 0x04, 0x75, 0x73,
0x65, 0x72, 0x08, 0x03, 0x4B, 0x45, 0x59, 0x08, 0x08, 0x0C, 0x87, 0xEB, 0xE6, 0x55, 0x27, 0x42,
0xD6, 0xFD, 0x00, 0xFD, 0x26, 0xFD, 0x00, 0xFE, 0x0F, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30,
0x31, 0x54, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0xFD, 0x00, 0xFF, 0x0F, 0x32, 0x30, 0x33, 0x34,
0x31, 0x31, 0x30, 0x36, 0x54, 0x30, 0x35, 0x33, 0x35, 0x33, 0x32, 0x17, 0xFD, 0x01, 0x00, 0x6C,
0xC0, 0x96, 0x33, 0x99, 0xB7, 0xB3, 0xC0, 0x75, 0xAB, 0x29, 0x8B, 0xA6, 0xE1, 0x9B, 0xCC, 0xD4,
0x59, 0x03, 0x94, 0x65, 0xBB, 0xDE, 0x26, 0x18, 0x2C, 0x8B, 0x27, 0xEC, 0x64, 0xBD, 0x85, 0xF7,
0x76, 0x15, 0x9F, 0x86, 0xF7, 0xB2, 0x09, 0x86, 0xA4, 0x2A, 0x85, 0xB0, 0xCC, 0x59, 0x06, 0x74,
0x94, 0x2E, 0xD2, 0xD9, 0x98, 0xDE, 0x9A, 0xEA, 0xC7, 0x72, 0x8E, 0x5A, 0x05, 0xA4, 0x8A, 0x1E,
0x3C, 0x74, 0x90, 0x71, 0xCD, 0xEF, 0xC6, 0xD0, 0x46, 0xB6, 0x7C, 0x2F, 0xA0, 0xCA, 0xD1, 0xCD,
0x38, 0x4D, 0xB2, 0x67, 0x3A, 0xB3, 0xE6, 0x08, 0x2D, 0xA3, 0x1F, 0xFA, 0x59, 0x02, 0xC8, 0x20,
0xC0, 0xAB, 0x67, 0xD3, 0x3C, 0x4F, 0x11, 0xA3, 0x3C, 0xF2, 0xE5, 0xC3, 0xD8, 0x91, 0xCB, 0xD0,
0x03, 0x96, 0x62, 0x33, 0xF7, 0x11, 0x35, 0x00, 0x9D, 0x48, 0xFE, 0x70, 0x85, 0xA4, 0x5B, 0xE6,
0x35, 0x24, 0xF8, 0x81, 0x4C, 0x3E, 0x89, 0xF9, 0x03, 0x96, 0x89, 0xC9, 0xFD, 0xF0, 0xCC, 0xAB,
0x45, 0x94, 0x79, 0x5B, 0xEE, 0xBA, 0xEF, 0x01, 0x0B, 0xA5, 0xAB, 0x79, 0xC0, 0xEF, 0x8E, 0xB8,
0x6A, 0x7C, 0x6F, 0xCF, 0xD7, 0x58, 0xFE, 0x36, 0x89, 0xB1, 0x17, 0x79, 0xEB, 0x7E, 0xED, 0xD2,
0x67, 0x53, 0x44, 0x7F, 0x17, 0x13, 0x52, 0xC7, 0xA5, 0xEB, 0xD8, 0x42, 0x72, 0x7A, 0xEA, 0x24,
0x47, 0x1F, 0x63, 0xE1, 0x0D, 0x88, 0xE4, 0xD6, 0x05, 0x39, 0x28, 0xDF, 0x80, 0xFA, 0xEF, 0xB4,
0x60, 0xF2, 0x28, 0xBD, 0x6E, 0x08, 0x22, 0x25, 0x35, 0xC1, 0x80, 0x40, 0x54, 0x5B, 0xA4, 0xCA,
0x2C, 0xD9, 0xF8, 0xDD, 0x95, 0x1D, 0xF5, 0x56, 0x28, 0x32, 0xD3, 0xB0, 0x8E, 0xE3, 0x80, 0xFB,
0xFB, 0xC0, 0xDC, 0x32, 0x24, 0x00, 0x69, 0x71, 0xC4, 0x51, 0xDF, 0x1A, 0x7B, 0xA5, 0xF5, 0x81,
0xFD, 0x05, 0x12, 0x30, 0x82, 0x05, 0x0E, 0x30, 0x40, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
0x0D, 0x01, 0x05, 0x0D, 0x30, 0x33, 0x30, 0x1B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
0x01, 0x05, 0x0C, 0x30, 0x0E, 0x04, 0x08, 0x51, 0x3C, 0x41, 0x91, 0x4C, 0x11, 0xDC, 0x22, 0x02,
0x02, 0x08, 0x00, 0x30, 0x14, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07, 0x04,
0x08, 0x6E, 0x9D, 0xF6, 0xEF, 0x4D, 0x3A, 0x71, 0x53, 0x04, 0x82, 0x04, 0xC8, 0xFC, 0x55, 0x0D,
0x6A, 0xC9, 0x2D, 0xF0, 0x67, 0x41, 0x4B, 0x5F, 0xA6, 0x98, 0x21, 0x52, 0x20, 0x0C, 0x9D, 0x81,
0xE1, 0xC5, 0x37, 0xCE, 0x7E, 0xA1, 0x0A, 0xAC, 0x76, 0x75, 0x29, 0x2F, 0x55, 0xFC, 0xDF, 0xC9,
0x42, 0xEA, 0x72, 0x17, 0xD5, 0x84, 0x5C, 0xCB, 0x91, 0x67, 0x74, 0x70, 0xA6, 0xAF, 0x9A, 0x03,
0x3B, 0xBB, 0x20, 0x05, 0x81, 0x21, 0xBE, 0xC0, 0x21, 0xB9, 0x12, 0x8C, 0x48, 0x56, 0x29, 0x03,
0xDF, 0x29, 0xB9, 0x66, 0x92, 0x98, 0x5C, 0xA0, 0x7B, 0xE7, 0x65, 0x84, 0x4D, 0x54, 0xA6, 0x37,
0xD2, 0xF5, 0x59, 0x5E, 0xBD, 0xAC, 0x83, 0x96, 0x72, 0x04, 0x87, 0x9D, 0x9B, 0x35, 0x43, 0x6D,
0x98, 0xC6, 0x79, 0xCD, 0x93, 0xA9, 0x9C, 0x17, 0xEB, 0xDB, 0xB4, 0x2D, 0x4A, 0x30, 0x78, 0x5A,
0x68, 0xC5, 0xD4, 0x11, 0x7D, 0x52, 0x2D, 0x79, 0xE9, 0x2C, 0x0B, 0x51, 0x40, 0x82, 0xBB, 0x3B,
0x92, 0xFF, 0x1C, 0xC4, 0xEB, 0x88, 0x32, 0x18, 0x4B, 0xCB, 0xD3, 0xC9, 0x5A, 0x8F, 0x79, 0x4E,
0xC8, 0x81, 0xFB, 0x68, 0xEA, 0x34, 0xC7, 0x5D, 0x4B, 0x31, 0xD4, 0x38, 0xAB, 0x8D, 0x5A, 0xA4,
0x9D, 0xD4, 0x72, 0x38, 0xBA, 0x88, 0x63, 0xC5, 0x46, 0xCF, 0x50, 0xE2, 0xBB, 0xF8, 0xED, 0x33,
0xC9, 0x08, 0x7E, 0x06, 0xFF, 0x38, 0x80, 0x4A, 0x50, 0xC6, 0xD4, 0x56, 0xBA, 0x9C, 0x96, 0xA5,
0x7E, 0x0F, 0x3A, 0xA3, 0x59, 0xD3, 0x2B, 0x93, 0xF8, 0xFA, 0x00, 0x51, 0x68, 0x0F, 0xB2, 0x4A,
0x09, 0xAD, 0x1B, 0x0A, 0xA9, 0xAD, 0x35, 0x88, 0x33, 0x51, 0x60, 0x77, 0x56, 0xC5, 0x1F, 0x6B,
0xF6, 0xDA, 0x43, 0x83, 0x7C, 0x13, 0x5F, 0x64, 0xD3, 0x70, 0x33, 0x7D, 0x59, 0x02, 0xA2, 0x2B,
0x64, 0x51, 0x34, 0xB9, 0x16, 0xCA, 0xEC, 0x35, 0x1D, 0x19, 0x42, 0x64, 0xED, 0x58, 0x80, 0x6C,
0xA4, 0xC9, 0x41, 0xD0, 0x1E, 0x34, 0xC5, 0xE5, 0x92, 0x5F, 0x05, 0xBC, 0x42, 0xCB, 0x06, 0xEA,
0xA6, 0x26, 0x07, 0x49, 0x6F, 0x72, 0x82, 0x77, 0x3A, 0xC2, 0xFF, 0x7B, 0x03, 0x64, 0x61, 0xCF,
0xC3, 0x62, 0xCA, 0x0C, 0x67, 0x2A, 0x95, 0x90, 0x7D, 0x98, 0x31, 0x6A, 0x15, 0xAF, 0xE1, 0x06,
0xAC, 0x0F, 0x96, 0x2C, 0x1B, 0x3F, 0xEF, 0xDF, 0xFE, 0x89, 0x37, 0xA4, 0xA4, 0x90, 0x44, 0x54,
0x63, 0xBD, 0xF5, 0x62, 0xB0, 0x9F, 0x49, 0x82, 0x5C, 0x96, 0xC8, 0xC7, 0x45, 0xF3, 0x97, 0xF3,
0x46, 0xFA, 0xAE, 0xDF, 0xCF, 0xD0, 0xD9, 0xBB, 0xA3, 0x8A, 0x77, 0x39, 0x1C, 0x0B, 0xE2, 0xED,
0x34, 0xEE, 0x20, 0x73, 0x94, 0x16, 0x46, 0xCB, 0xAE, 0xFA, 0x32, 0x7C, 0xD3, 0x86, 0x67, 0xB8,
0x27, 0x41, 0xB0, 0xD7, 0x99, 0x86, 0xE5, 0xEF, 0x68, 0xD1, 0x4A, 0x7E, 0x04, 0xD8, 0xE9, 0x67,
0x5C, 0xF6, 0x57, 0xF8, 0x88, 0x65, 0x77, 0x48, 0x74, 0xF2, 0x21, 0xC4, 0xDE, 0xE2, 0x11, 0x52,
0xF7, 0xBF, 0x2B, 0x0A, 0xBE, 0xF4, 0x16, 0xDE, 0x93, 0xE6, 0xD7, 0xAB, 0xBB, 0x49, 0x38, 0x3B,
0x3C, 0x69, 0x8B, 0x4B, 0xB5, 0xF1, 0xBF, 0x77, 0x93, 0x74, 0xC9, 0x7F, 0x45, 0xFA, 0x4D, 0xAA,
0x59, 0xAE, 0xDE, 0x90, 0xCD, 0xDF, 0x86, 0x07, 0xD5, 0xE2, 0x7A, 0xD2, 0x85, 0xDE, 0x0E, 0xC0,
0xFA, 0x5F, 0xB3, 0x9C, 0xC4, 0x76, 0x07, 0x6C, 0xFE, 0x88, 0x25, 0xDF, 0x30, 0x1C, 0x77, 0xE3,
0x0A, 0x0C, 0xA9, 0xA8, 0x56, 0x24, 0xE7, 0x8E, 0x65, 0x40, 0x97, 0x9E, 0x7F, 0x45, 0x06, 0x59,
0xD1, 0x58, 0xEE, 0xD6, 0xB1, 0x32, 0xFB, 0xC4, 0xEF, 0x49, 0x37, 0x7C, 0xB4, 0xE7, 0x43, 0x22,
0x7B, 0x60, 0xFF, 0x88, 0x9D, 0x7A, 0x47, 0x03, 0x1B, 0x61, 0x76, 0xAB, 0xA9, 0xE9, 0x4E, 0x8C,
0x15, 0x21, 0xBE, 0x54, 0x54, 0x41, 0xAD, 0x2B, 0xA2, 0x95, 0x40, 0x5A, 0xB1, 0x18, 0x77, 0x42,
0x14, 0x80, 0x8A, 0x47, 0xD7, 0x63, 0x6E, 0xC9, 0x2C, 0x15, 0x35, 0x79, 0xA0, 0xFC, 0xB7, 0xC3,
0x87, 0x4B, 0x5E, 0x16, 0xE1, 0x10, 0x09, 0xD8, 0x40, 0x69, 0x37, 0xFE, 0x85, 0xE5, 0xEC, 0x99,
0x1A, 0x2D, 0xD6, 0x4D, 0x32, 0x69, 0x33, 0xB4, 0x4B, 0xDF, 0x72, 0xEE, 0x50, 0xA3, 0x55, 0x32,
0x1D, 0x63, 0xAD, 0xD1, 0xB5, 0x96, 0x76, 0xC9, 0x52, 0xD6, 0x2F, 0x65, 0xEC, 0x9E, 0x4E, 0x9C,
0xB5, 0x3A, 0x37, 0xA6, 0xB2, 0xED, 0xCA, 0x9D, 0x93, 0x12, 0x9F, 0x0D, 0x98, 0x4A, 0x16, 0x1C,
0x16, 0x1A, 0xD9, 0x73, 0xF9, 0x77, 0x74, 0x42, 0xFB, 0x75, 0x5F, 0x83, 0x7A, 0x5D, 0x92, 0x0B,
0x6D, 0x13, 0xF7, 0x3F, 0x2B, 0xB1, 0x18, 0x8B, 0x11, 0xFE, 0x3D, 0x8A, 0xDA, 0x61, 0xE8, 0x8B,
0xC7, 0xA8, 0xE1, 0xA9, 0xA0, 0x77, 0x5D, 0x38, 0xCA, 0x2C, 0xFF, 0xC1, 0xFF, 0x7C, 0x0A, 0x66,
0x0D, 0xC9, 0xB9, 0x82, 0xF5, 0x44, 0x63, 0x14, 0x72, 0xA8, 0xBB, 0xE9, 0x4C, 0x7E, 0x0E, 0xE6,
0x0F, 0xBC, 0xD3, 0x3F, 0x3A, 0xF0, 0x39, 0x54, 0x38, 0xA7, 0x84, 0xC2, 0xCB, 0x09, 0xAA, 0x2D,
0x91, 0x74, 0xDF, 0x3D, 0x18, 0xD9, 0x06, 0xBD, 0x71, 0x9C, 0x5D, 0x4A, 0x00, 0x13, 0x18, 0x36,
0xAF, 0xF2, 0x28, 0x1E, 0x88, 0xB3, 0x93, 0x1E, 0x25, 0xB4, 0x3C, 0x72, 0xAB, 0xB6, 0xE4, 0x5B,
0xB4, 0x28, 0xEB, 0x28, 0x24, 0xF1, 0xB9, 0x57, 0x2E, 0x62, 0x32, 0xF0, 0x78, 0xB2, 0x62, 0xCA,
0x91, 0x01, 0x70, 0x68, 0xDB, 0xA1, 0x4E, 0x38, 0xCE, 0xE2, 0x3F, 0x3C, 0x7E, 0xC2, 0x3B, 0x5B,
0x30, 0x00, 0x5A, 0xA7, 0xD6, 0xAB, 0x6F, 0xEA, 0x6B, 0x4A, 0x3B, 0xD8, 0x4C, 0x18, 0x4B, 0x7D,
0x7F, 0xC0, 0x89, 0x46, 0x55, 0x43, 0xED, 0x80, 0xC3, 0xE8, 0x32, 0x5C, 0x6F, 0x4F, 0xC1, 0x04,
0xB4, 0x51, 0x29, 0xCD, 0x4E, 0x40, 0x48, 0xD4, 0xBD, 0xB2, 0xCC, 0xC7, 0x2F, 0x47, 0x69, 0x5E,
0x8D, 0x8E, 0x04, 0xAB, 0xD9, 0xF8, 0xB9, 0x01, 0x9B, 0xC3, 0xAA, 0x57, 0x65, 0xB5, 0xE8, 0x31,
0x23, 0x1B, 0xB1, 0xFD, 0xB6, 0xB6, 0x10, 0x83, 0x9B, 0xF9, 0x4A, 0x31, 0xBA, 0x9A, 0xA4, 0x9F,
0xDD, 0x2D, 0xDF, 0xF9, 0xF7, 0x95, 0x4E, 0xC3, 0x30, 0xA4, 0x59, 0xB7, 0xD9, 0x87, 0x26, 0xAE,
0xCF, 0x64, 0x96, 0x94, 0x44, 0x6E, 0xE5, 0x63, 0x74, 0xCD, 0x3A, 0x0F, 0x8B, 0x76, 0x55, 0xDE,
0x2F, 0x24, 0x64, 0x65, 0xCB, 0xC2, 0xC5, 0xB9, 0xC3, 0x2A, 0x0C, 0x0B, 0x33, 0x17, 0xBF, 0xA8,
0x76, 0x76, 0xC9, 0x14, 0x0B, 0x34, 0x6E, 0x67, 0x33, 0xBD, 0xEB, 0x8D, 0x65, 0x54, 0x66, 0x95,
0xE8, 0xB6, 0x3B, 0xD7, 0x13, 0xC1, 0x30, 0x00, 0xA5, 0x25, 0x05, 0x25, 0x34, 0x98, 0xBE, 0xDC,
0x04, 0xC2, 0x2D, 0xF2, 0x35, 0x14, 0xEF, 0xFB, 0xDC, 0xEA, 0x5A, 0xCD, 0xFC, 0xCB, 0xAC, 0x60,
0x0E, 0x6B, 0x60, 0xF8, 0x4C, 0x79, 0x4E, 0x39, 0x1D, 0x59, 0xC2, 0xB4, 0x60, 0xF1, 0x4D, 0x9C,
0x9D, 0x1B, 0x66, 0x34, 0x1C, 0x1C, 0x7D, 0xEA, 0xEB, 0xF3, 0xF5, 0x76, 0xB4, 0xB8, 0x0A, 0xBB,
0x30, 0xA5, 0x11, 0x9E, 0xF4, 0x04, 0x03, 0x69, 0xD2, 0x38, 0x26, 0x20, 0x13, 0xB7, 0x8B, 0x2E,
0x09, 0xA7, 0x2E, 0xA5, 0x60, 0x0A, 0x8E, 0x02, 0x75, 0x75, 0xAA, 0x6E, 0xBE, 0x51, 0xF2, 0x50,
0x34, 0x81, 0x68, 0xDE, 0xFC, 0x56, 0x29, 0xE3, 0x09, 0x10, 0xDB, 0xDD, 0x3F, 0x7C, 0x5C, 0x00,
0x4F, 0x97, 0x6A, 0xBB, 0x0A, 0xF4, 0x52, 0x3B, 0x0F, 0x57, 0x61, 0xF5, 0x75, 0x2D, 0xE3, 0xA5,
0x9A, 0xDA, 0x39, 0x49, 0xEC, 0x2C, 0x0D, 0x45, 0x48, 0x6E, 0xC1, 0xE7, 0xE6, 0x36, 0xC0, 0x6A,
0xA6, 0x16, 0xAE, 0x2E, 0x7D, 0x11, 0x2A, 0x45, 0x02, 0xDA, 0x0D, 0x44, 0xA6, 0x99, 0x6E, 0x66,
0x46, 0xA3, 0xD7, 0x0E, 0xE7, 0xC2, 0x14, 0x98, 0x17, 0x24, 0xA9, 0x50, 0x52, 0x8C, 0x71, 0xE7,
0xFB, 0xA1, 0x78, 0x3A, 0x4F, 0xAE, 0xE6, 0x0F, 0xF0, 0xA5, 0x5C, 0x00, 0x8C, 0xB9, 0xA7, 0xCE,
0xA2, 0xA3, 0xFE, 0xEB, 0x47, 0xEC, 0x34, 0x9E, 0xF3, 0x4A, 0x7F, 0x9F, 0xF8, 0xD9, 0xF4, 0xA3,
0xE7, 0x6E, 0x72, 0x6F, 0xEE, 0x04, 0x3D, 0xAA, 0x20, 0x37, 0x48, 0x36, 0x11, 0x5F, 0xA8, 0xD9,
0x8A, 0xBC, 0xF9, 0x6E, 0xD6, 0xD5, 0x47, 0xED, 0xDE, 0x14, 0x1F, 0xB4, 0x99, 0x98, 0xD2, 0x33,
0x19, 0x6B, 0x2A, 0x37, 0x76, 0xBA, 0x71, 0x8F, 0x0D, 0x2F, 0x99, 0x6E, 0x04, 0xB4, 0x00, 0xC4,
0x93, 0xD0, 0x07, 0xA2, 0x99, 0x20, 0x21, 0x40, 0x50, 0x99, 0x7A, 0x1A, 0x6B, 0xD1, 0xED, 0x19,
0x73, 0x4B, 0xB7, 0xF6, 0x74, 0x28, 0xD4, 0xDF, 0x15, 0xED, 0xF3, 0xF4, 0x89, 0x29, 0x00, 0xAA,
0xAC, 0xA8, 0x7D, 0x40, 0xC8, 0x93, 0xBC, 0xFB, 0x1B, 0xE5, 0xF7, 0x78, 0xD8, 0x5E, 0x8E, 0x95,
0xB5, 0x80, 0x23, 0x3F, 0xB1, 0x24, 0x18, 0x01, 0xD5, 0xF6, 0x78, 0xAC, 0xB7, 0x0E, 0x4D, 0x40,
0xA8, 0xBD, 0x31, 0xA1, 0x19
  };

  SafeBag firstMemberSafeBag
    (ndn::Blob(firstMemberSafeBagEncoding, sizeof(firstMemberSafeBagEncoding)));
  string safeBagPassword = "password";
  keyChain.importSafeBag
    (firstMemberSafeBag, (const uint8_t*)safeBagPassword.c_str(),
     safeBagPassword.size());
  return keyChain.getDefaultIdentity();
}

// Set this false to exit the application.
static bool isRunning = true;

static void
onData
  (const ptr_lib::shared_ptr<Data>& data,
   const ptr_lib::shared_ptr<Validator>& validator,
   const ptr_lib::shared_ptr<DecryptorV2>& decryptor)
{
  // Validate the Data signature.
  validator->validate
    (*data,
     [=](auto&) {
       // The Data signature is valid. Now decrypt.
       decryptor->decrypt
         (*data,
          [](auto& plainData) {
            cout << "Received response: " << plainData.toRawStr() << endl;
            isRunning = false;
          },
          [](auto errorCode, const std::string& message) {
            cout << "DecryptorV2 error: " << message << endl;
            isRunning = false;
          });
     },
     [](auto&, auto& error) {
       cout << "Validate Data failure: " << error.toString() << endl;
       isRunning = false;
     });
}

static void
usage()
{
  cerr << "Usage: test-secured-interest-sender [options]\n"
       << "  -a access-group-name The access group name as printed by test-access-manager. If omitted, use\n"
       << "                       <default-identity>/NAC/test-group where <default-identity> is the system default identity.\n"
       << "  -n name-prefix       The name prefix for the message. If omitted, use /test-secured-interest\n"
       << "                       This must match the prefix for test-secured-interest-responder.\n"
       << "  -h host              If omitted or \"\", the default Face connects to the local forwarder\n"
       << "                       Both test-access-manager and test-secured-interest-responder must be reachable.\n"
       << "  -p port              If omitted, use 6363\n"
       << "  -?                   Print this help" << endl;
}

int
main(int argc, char** argv)
{
  Name accessGroupName;
  Name messagePrefix("/test-secured-interest");
  string host = "";
  int port = 6363;

  for (int i = 1; i < argc; ++i) {
    string arg = argv[i];
    string value = (i + 1 < argc ? argv[i + 1] : "");

    if (arg == "-?") {
      usage();
      return 0;
    }
    else if (arg == "-a") {
      accessGroupName = Name(value);
      ++i;
    }
    else if (arg == "-n") {
      messagePrefix = Name(value);
      ++i;
    }
    else if (arg == "-h") {
      host = value;
      ++i;
    }
    else if (arg == "-p") {
      port = atoi(value.c_str());
      if (port == 0) {
        usage();
        return 1;
      }
      ++i;
    }
    else {
      cerr << "Unrecognized option: " << arg << endl;
      usage();
      return 1;
    }
  }

  try {
    // Silence the warning from Interest wire encode.
    Interest::setDefaultCanBePrefix(true);

    CommandInterestPreparer commandInterestPreparer;

    KeyChain systemKeyChain;
    ptr_lib::shared_ptr<Face> face;
    if (host == "")
      // The default Face will connect using a Unix socket, or to "localhost".
      face.reset(new Face());
    else
      face.reset(new Face
        (ptr_lib::make_shared<TcpTransport>(),
         ptr_lib::make_shared<TcpTransport::ConnectionInfo>(host.c_str(), port)));

    // Create an in-memory key chain and get the encryptor identity.
    auto nacKeyChain = ptr_lib::make_shared<KeyChain>("pib-memory:", "tpm-memory:");
    Name senderName = getSenderName(*nacKeyChain);

    // In a production application, use a validator which has access to the
    // certificates of the access manager and the responder.
    auto validator = ptr_lib::make_shared<ValidatorNull>();
    if (accessGroupName.size() == 0) {
      // Assume the access manager is the default identity on this computer.
      auto accessManagerName =
        systemKeyChain.getPib().getIdentity(systemKeyChain.getDefaultIdentity())->getName();
      accessGroupName = Name(accessManagerName).append(Name("NAC/test-group"));
    }
    // Create the EncryptorV2 to encrypt the secured interest.
    auto encryptor = ptr_lib::make_shared<EncryptorV2>
      (accessGroupName,
       [](auto errorCode, const std::string& message) {
         cout << "EncryptorV2 error: " << message << endl;
         isRunning = false;
       },
       nacKeyChain->getPib().getIdentity(senderName)->getDefaultKey().get(),
       validator.get(), nacKeyChain.get(), face.get(), ndn_EncryptAlgorithmType_AesCbc);
    // Create the DecryptorV2 to decrypt the reply Data packet.
    auto decryptor = ptr_lib::make_shared<ndn::DecryptorV2>
      (nacKeyChain->getPib().getIdentity(senderName)->getDefaultKey().get(),
       validator.get(), nacKeyChain.get(), face.get());

    auto interest = ptr_lib::make_shared<Interest>(messagePrefix);
    commandInterestPreparer.prepareCommandInterestName(*interest);

    string message = "encrypted message";
    interest->setApplicationParameters(Blob::fromRawStr(message));
    encryptor->encrypt
      (interest,
       [=](auto&, auto&) {
         nacKeyChain->sign(*interest);         
         face->expressInterest(
           *interest,
           [=](auto&, auto& data) { onData(data, validator, decryptor); },
           [](auto& i) { 
             cout << "Timeout for interest " << i->getName().toUri() << endl;
             isRunning = false;
           });
       });
    cout << "Sending message:   " << message << endl;

    // The main event loop. Run until something sets isRunning false.
    while (isRunning) {
      face->processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
  return 0;
}

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: ndn-cxx/detail/cancel-handle.cpp
 * Original repository: https://github.com/named-data/ndn-cxx
 *
 * Summary of Changes: Use ndn-ind includes. Move ScopedCancelHandle in here.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (c) 2013-2020 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_BOOST.
#include <ndn-ind/ndn-ind-config.h>
#ifdef NDN_IND_HAVE_BOOST

#include <ndn-ind/util/impl/cancel-handle.hpp>

namespace ndn_ind {
namespace scheduler {

CancelHandle::CancelHandle(std::function<void()> cancel)
  : m_cancel(std::move(cancel))
{
}

void
CancelHandle::cancel() const
{
  if (m_cancel != nullptr) {
    m_cancel();
    m_cancel = nullptr;
  }
}

ScopedCancelHandle::ScopedCancelHandle(CancelHandle hdl)
  : m_hdl(std::move(hdl))
{
}

ScopedCancelHandle::ScopedCancelHandle(ScopedCancelHandle&& other)
  : m_hdl(other.release())
{
}

ScopedCancelHandle&
ScopedCancelHandle::operator=(ScopedCancelHandle&& other)
{
  cancel();
  m_hdl = other.release();
  return *this;
}

ScopedCancelHandle::~ScopedCancelHandle()
{
  m_hdl.cancel();
}

void
ScopedCancelHandle::cancel()
{
  release().cancel();
}

CancelHandle
ScopedCancelHandle::release()
{
  CancelHandle hdl;
  std::swap(hdl, m_hdl);
  return hdl;
}

} // namespace scheduler
} // namespace ndn_ind

#endif // NDN_IND_HAVE_BOOST

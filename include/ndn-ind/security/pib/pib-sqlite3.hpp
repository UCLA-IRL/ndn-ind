/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: include/ndn-cpp/security/pib/pib-sqlite3.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use NDN_IND macros. Support ndn_ind_dll.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2017-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/pib/pib-sqlite3.hpp
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

#ifndef NDN_PIB_SQLITE3_HPP
#define NDN_PIB_SQLITE3_HPP

// Define this even if we don't have NDN_IND_HAVE_SQLITE3 .
#define NDN_PIB_SQLITE3_SCHEME "pib-sqlite3"

// Only compile if ndn-ind-config.h defines NDN_IND_HAVE_SQLITE3.
#include "../../ndn-ind-config.h"
#ifdef NDN_IND_HAVE_SQLITE3

#include "pib-impl.hpp"

struct sqlite3;

namespace ndn_ind {

/**
 * PibSqlite3 extends PibImpl and is used by the Pib class as an implementation
 * of a PIB based on an SQLite3 database. All the contents in the PIB are stored
 * in an SQLite3 database file. This provides more persistent storage than
 * PibMemory.
 */
class ndn_ind_dll PibSqlite3 : public PibImpl {
public:
  /**
   * Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
   * database directory does not contain a PIB database of an older version.
   * @param databaseDirectoryPath (optional) The directory where the
   * database file is located. If omitted, use $HOME/.ndn . If the directory
   * does not exist, create it.
   * @param databaseFilename (optional) The name if the database file in the
   * databaseDirectoryPath. If omitted, use "pib.db".
   * @throws PibImpl::Error if initialization fails.
   */
  PibSqlite3
    (const std::string& databaseDirectoryPath = "",
     const std::string& databaseFilename = "pib.db");

  /**
   * Destroy and clean up the internal state.
   */
  virtual
  ~PibSqlite3();

  static std::string
  getScheme();

  // TpmLocator management.

  /**
   * Set the corresponding TPM information to tpmLocator. This method does not
   * reset the contents of the PIB.
   * @param tpmLocator The TPM locator string.
   */
  virtual void
  setTpmLocator(const std::string& tpmLocator);

  /**
   * Get the TPM Locator.
   * @return The TPM locator string.
   */
  virtual std::string
  getTpmLocator() const;

  // Identity management.

  /**
   * Check for the existence of an identity.
   * @param identityName The name of the identity.
   * @return True if the identity exists, otherwise false.
   */
  virtual bool
  hasIdentity(const Name& identityName) const;

  /**
   * Add the identity. If the identity already exists, do nothing. If no default
   * identity has been set, set the added identity as the default.
   * @param identityName The name of the identity to add. This copies the name.
   */
  virtual void
  addIdentity(const Name& identityName);

  /**
   * Remove the identity and its related keys and certificates. If the default
   * identity is being removed, no default identity will be selected.  If the
   * identity does not exist, do nothing.
   * @param identityName The name of the identity to remove.
   */
  virtual void
  removeIdentity(const Name& identityName);

  /**
   * Erase all certificates, keys, and identities.
   */
  virtual void
  clearIdentities();

  /**
   * Get the names of all the identities.
   * @return The set of identity names. The Name objects are fresh copies.
   */
  virtual std::set<Name>
  getIdentities() const;

  /**
   * Set the identity with the identityName as the default identity. If the
   * identity with identityName does not exist, then it will be created.
   * @param identityName The name for the default identity. This copies the name.
   */
  virtual void
  setDefaultIdentity(const Name& identityName);

  /**
   * Get the default identity.
   * @return The name of the default identity, as a fresh copy.
   * @throws Pib::Error for no default identity.
   */
  virtual Name
  getDefaultIdentity() const;

  // Key management.

  /**
   * Check for the existence of a key with keyName.
   * @param keyName The name of the key.
   * @return True if the key exists, otherwise false. Return false if the
   * identity does not exist.
   */
  virtual bool
  hasKey(const Name& keyName) const;

  /**
   * Add the key. If a key with the same name already exists, overwrite the key.
   * If the identity does not exist, it will be created. If no default key for
   * the identity has been set, then set the added key as the default for the
   * identity.  If no default identity has been set, identity becomes the
   * default.
   * @param identityName The name of the identity that the key belongs to. This
   * copies the name.
   * @param keyName The name of the key. This copies the name.
   * @param key The public key bits. This copies the array.
   * @param keyLength The length of the public key bits array.
   */
  virtual void
  addKey
    (const Name& identityName, const Name& keyName, const uint8_t* key,
     size_t keyLength);

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing.
   * @param keyName The name of the key.
   */
  virtual void
  removeKey(const Name& keyName);

  /**
   * Get the key bits of a key with name keyName.
   * @param keyName The name of the key.
   * @return The key bits.
   * @throws Pib::Error if the key does not exist.
   */
  virtual Blob
  getKeyBits(const Name& keyName) const;

  /**
   * Get all the key names of the identity with the name identityName. The
   * returned key names can be used to create a KeyContainer. With a key name
   * and a backend implementation, one can create a Key front end instance.
   * @param identityName The name of the identity.
   * @return The set of key names. The Name objects are fresh copies. If the
   * identity does not exist, return an empty set.
   */
  virtual std::set<Name>
  getKeysOfIdentity(const Name& identityName) const;

  /**
   * Set the key with keyName as the default key for the identity with name
   * identityName.
   * @param identityName The name of the identity.
   * @param keyName The name of the key. This copies the name.
   * @throws Pib::Error if the key does not exist.
   */
  virtual void
  setDefaultKeyOfIdentity(const Name& identityName, const Name& keyName);

  /**
   * Get the name of the default key for the identity with name identityName.
   * @param identityName The name of the identity.
   * @return The name of the default key, as a fresh copy.
   * @throws Pib::Error if there is no default key or if the identity does not
   * exist.
   */
  virtual Name
  getDefaultKeyOfIdentity(const Name& identityName) const;

  // Certificate management.

  /**
   * Check for the existence of a certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  virtual bool
  hasCertificate(const Name& certificateName) const;

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If the key or
   * identity does not exist, they will be created. If no default certificate
   * for the key has been set, then set the added certificate as the default for
   * the key. If no default key was set for the identity, it will be set as the
   * default key for the identity. If no default identity was selected, the
   * certificate's identity becomes the default.
   * @param certificate The certificate to add. This copies the object.
   */
  virtual void
  addCertificate(const CertificateV2& certificate);

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * @param certificateName The name of the certificate.
   */
  virtual void
  removeCertificate(const Name& certificateName);

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the certificate.
   * @throws Pib::Error if the certificate does not exist.
   */
  virtual ptr_lib::shared_ptr<CertificateV2>
  getCertificate(const Name& certificateName) const;

  /**
   * Get a list of certificate names of the key with id keyName. The returned
   * certificate names can be used to create a PibCertificateContainer. With a
   * certificate name and a backend implementation, one can obtain the
   * certificate.
   * @param keyName The name of the key.
   * @return The set of certificate names. The Name objects are fresh copies. If
   * the key does not exist, return an empty set.
   */
  virtual std::set<Name>
  getCertificatesOfKey(const Name& keyName) const;

  /**
   * Set the cert with name certificateName as the default for the key with
   * keyName.
   * @param keyName The name of the key.
   * @param certificateName The name of the certificate. This copies the name.
   * @throws Pib::Error if the certificate with name certificateName does not
   * exist.
   */
  virtual void
  setDefaultCertificateOfKey(const Name& keyName, const Name& certificateName);

  /**
   * Get the default certificate for the key with eyName.
   * @param keyName The name of the key.
   * @return A copy of the default certificate.
   * @throws Pib::Error if the default certificate does not exist.
   */
  virtual ptr_lib::shared_ptr<CertificateV2>
  getDefaultCertificateOfKey(const Name& keyName) const;

  /**
   * Get the default that the constructor uses if databaseDirectoryPath is
   * omitted. This does not try to create the directory.
   * @return The default database directory path.
   */
  static std::string
  getDefaultDatabaseDirectoryPath();

  /**
   * Get the default database file path that the constructor uses if
   * databaseDirectoryPath and databaseFilename are omitted.
   * @return The default database file path.
   */
  static std::string
  getDefaultDatabaseFilePath()
  {
    return getDefaultDatabaseDirectoryPath() + '/' + "pib.db";
  }

private:
  bool
  hasDefaultIdentity() const;

  bool
  hasDefaultKeyOfIdentity(const Name& identityName) const;

  bool
  hasDefaultCertificateOfKey(const Name& keyName) const;

  // Disable the copy constructor and assignment operator.
  PibSqlite3(const PibSqlite3& other);
  PibSqlite3& operator=(const PibSqlite3& other);

  struct sqlite3 *database_;
};

}

#endif // NDN_IND_HAVE_SQLITE3

#endif

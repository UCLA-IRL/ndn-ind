/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2020 Operant Networks, Incorporated.
 * @author: Jeff Thompson <jefft0@gmail.com>
 *
 * This works is based substantially on previous work as listed below:
 *
 * Original file: src/util/boost-info-parser.hpp
 * Original repository: https://github.com/named-data/ndn-cpp
 *
 * Summary of Changes: Use ndn-ind includes.
 *
 * which was originally released under the LGPL license with the following rights:
 *
 * Copyright (C) 2014-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN boost_info_parser by Adeola Bannis.
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

#ifndef NDN_BOOST_INFO_PARSER_HPP
#define NDN_BOOST_INFO_PARSER_HPP

#include <istream>
#include <string>
#include <vector>
#include <utility>
#include <ndn-ind/common.hpp>

namespace ndn_ind {

/**
 * BoostInfoTree is provided for compatibility with the Boost INFO property list
 * format used in ndn-cxx.
 *
 * Each node in the tree may have a name and a value as well as associated
 * sub-trees. The sub-tree names are not unique, and so sub-trees are stored as
 * dictionaries where the key is a sub-tree name and the values are the
 * sub-trees sharing the same name.
 *
 * Nodes can be accessed with a path syntax, as long as nodes in the path do not
 * contain the path separator '/' in their names.
 */
class BoostInfoTree
{
public:
  BoostInfoTree(const std::string& value = "", BoostInfoTree* parent = 0)
  : value_(value), parent_(parent), lastChild_(0)
  {
  }

  /**
   * Insert a BoostInfoTree as a sub-tree with the given name.
   * @param treeName The name of the new sub-tree.
   * @param newTree The sub-tree to add.
   */
  void
  addSubtree
    (const std::string& treeName,
     const ptr_lib::shared_ptr<BoostInfoTree>& newTree);

  /**
   * Create a new BoostInfo and insert it as a sub-tree with the given name.
   * @param treeName The name of the new sub-tree.
   * @param value The value associated with the new sub-tree.
   * @return The created sub-tree.
   */
  const BoostInfoTree&
  createSubtree(const std::string& treeName, const std::string& value = "");

  /**
   * Look up using the key and return a list of the subtrees.
   * @param key The key which may be a path separated with '/'.
   * @return A new vector with pointers to the subtrees.
   */
  std::vector<const BoostInfoTree*>
  operator [] (const std::string& key) const;

  /**
   * Look up using the key and return string value of the first subtree.
   * @param key The key which may be a path separated with '/'.
   * @return A shared_ptr for the string value or null if not found.
   */
  ptr_lib::shared_ptr<std::string>
  getFirstValue(const std::string& key) const
  {
    std::vector<const BoostInfoTree*> list = (*this)[key];
    if (list.size() >= 1)
      return ptr_lib::make_shared<std::string>(list[0]->value_);
    else
      return ptr_lib::shared_ptr<std::string>();
  }

  const std::string&
  getValue() const { return value_; }

  BoostInfoTree*
  getParent() { return parent_; }

  BoostInfoTree*
  getLastChild() { return lastChild_; }

  std::string
  prettyPrint(int indentLevel = 1) const;

private:
  /**
   * Use treeName to find the vector of BoostInfoTree in subtrees_.
   * @param value The key in subtrees_ to search for.  This does a flat search
   * in subtrees_.  It does not split by '/' into a path.
   * @return A pointer to the vector of BoostInfoTree, or 0 if not found.
   */
  std::vector<ptr_lib::shared_ptr<BoostInfoTree> >*
  find(const std::string& treeName);

  static std::vector<std::string>
  split(const std::string &input, char separator);

  // We can't use a map for subtrees_ because we want the keys to be in order.
  std::vector<std::pair<std::string, std::vector<ptr_lib::shared_ptr<BoostInfoTree> > > > subtrees_;
  std::string value_;
  BoostInfoTree* parent_;
  BoostInfoTree* lastChild_;
};

inline std::ostream&
operator << (std::ostream& os, const BoostInfoTree& tree)
{
  os << tree.prettyPrint();
  return os;
}

/**
 * A BoostInfoParser reads files in Boost's INFO format and constructs a
 * BoostInfoTree.
 */
class BoostInfoParser
{
public:
  BoostInfoParser()
  : root_(new BoostInfoTree())
  {
  }

  /**
   * Add the contents of the file to the root BoostInfoTree.
   * @param fileName The path to the INFO file.
   * @return The new root BoostInfoTree.
   */
  const BoostInfoTree&
  read(const std::string& fileName);

  /**
   * Add the contents of the input string to the root BoostInfoTree.
   * @param input The contents of the INFO file, with lines separated by "\n" or
   * "\r\n".
   * @param inputName Used for log messages, etc.
   * @return The new root BoostInfoTree.
   */
  const BoostInfoTree&
  read(const std::string& input, const std::string& inputName);

  // TODO: Implement readPropertyList.

  /**
   * Write the root tree of this BoostInfoParser as file in Boost's INFO format.
   * @param fileName The output path.
   */
  void
  write(const std::string& fileName) const;

  /**
   * Get the root tree of this parser.
   * @return The root BoostInfoTree.
   */
  const BoostInfoTree&
  getRoot() const { return *root_; }

private:
  /**
   * Similar to Python's shlex.split, split s into an array of strings which are
   * separated by whitespace, treating a string within quotes as a single entity
   * regardless of whitespace between the quotes. Also allow a backslash to
   * escape the next character.
   * @param s The input string to split.
   * @param result This appends the split strings to result. This does not first
   * clear the vector.
   */
  static void
  shlex_split(const std::string& s, std::vector<std::string>& result);

  /**
   * Internal import method with an explicit context node.
   * @param stream The stream for reading the INFO content.
   * @param ctx The node currently being populated.
   * @return The ctx.
   */
  BoostInfoTree*
  read(std::istream& stream, BoostInfoTree* ctx);

  /**
   * Internal helper method for parsing INFO files line by line.
   */
  BoostInfoTree*
  parseLine(const std::string& line, BoostInfoTree* context);

  ptr_lib::shared_ptr<BoostInfoTree> root_;
};

}

#endif

// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces of a SymbolAddressDeriver class.
//
#pragma once

// C/C++ standard headers
#include <cstdint>
#include <string>

// Other external headers
// Windows headers
#include <tchar.h>

// Original headers

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// forward declaration
class SymbolResolver;

class SymbolAddressDeriver {
 public:
  SymbolAddressDeriver(_In_ SymbolResolver *SymbolResolver,
                       _In_ const std::basic_string<TCHAR> &FilePath,
                       _In_ std::uintptr_t BaseAddress);

  ~SymbolAddressDeriver();

  std::uint64_t getAddress(
      _In_ const std::basic_string<TCHAR> &SymbolName) const;

 private:
  SymbolAddressDeriver &operator=(const SymbolAddressDeriver &) = delete;

  SymbolResolver *m_SymbolResolver;  // does not control its life span
  const std::uintptr_t m_BaseAddress;
  const std::uint64_t m_Module;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

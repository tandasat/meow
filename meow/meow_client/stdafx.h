// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

// C/C++ standard headers
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <algorithm>

// Other external headers
// Windows headers
#include <tchar.h>
#include <Windows.h>
#include <strsafe.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

// Original headers
#include "../Common/ScopedResource/unique_resource.h"
#include "../Common/ScopedResource/scope_exit.h"

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

// Returns true when it is running on the x64 system.
inline bool IsX64() {
#ifdef _AMD64_
  return true;
#else
  return false;
#endif
}

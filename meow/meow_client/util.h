// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to utility functions.
//
#pragma once

// C/C++ standard headers
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

std::basic_string<TCHAR> GetWin32ErrorMessage(_In_ std::uint32_t ErrorCode);

void PrintErrorMessage(_In_ const std::basic_string<TCHAR> &Message);

void ThrowRuntimeError(_In_ const std::basic_string<TCHAR> &Message);

bool RegWritePointerSize(_In_ const std::basic_string<TCHAR> &Path,
                         _In_ const std::basic_string<TCHAR> &Name,
                         _In_ std::uintptr_t Value);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

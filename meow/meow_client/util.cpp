// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements utility functions.
//
#include "stdafx.h"
#include "util.h"

// C/C++ standard headers
// Other external headers
// Windows headers
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

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Return an error message of corresponding Win32 error code.
std::basic_string<TCHAR> GetWin32ErrorMessage(_In_ std::uint32_t ErrorCode) {
  TCHAR *messageNaked = nullptr;
  if (!::FormatMessage(
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
          ErrorCode, LANG_USER_DEFAULT, reinterpret_cast<LPTSTR>(&messageNaked),
          0, nullptr)) {
    return TEXT("");
  }
  if (!messageNaked) {
    return TEXT("");
  }
  auto message = std::experimental::make_unique_resource(
      std::move(messageNaked), &LocalFree);

  const auto length = ::_tcslen(message.get());
  if (!length) {
    return TEXT("");
  }

  if (message.get()[length - 2] == TEXT('\r')) {
    message.get()[length - 2] = TEXT('\0');
  }
  return message.get();
}

// Display an error message with an error message of the current error code.
void PrintErrorMessage(_In_ const std::basic_string<TCHAR> &Message) {
  const auto errorCode = ::GetLastError();
  const auto errorMessage = GetWin32ErrorMessage(errorCode);
  ::_ftprintf_s(stderr, _T("%s : %lu(0x%08x) : %s\n"), Message.c_str(),
                errorCode, errorCode, errorMessage.c_str());
}

// Throw std::runtime_error with an error message.
void ThrowRuntimeError(_In_ const std::basic_string<TCHAR> &Message) {
  const auto errorCode = ::GetLastError();
  const auto errorMessage = GetWin32ErrorMessage(errorCode);
  char msg[1024];
#if UNICODE
  static const char FORMAT_STR[] = "%S : %lu(0x%08x) : %S";
#else
  static const char FORMAT_STR[] = "%s : %lu(0x%08x) : %s";
#endif
  StringCchPrintfA(msg, _countof(msg), FORMAT_STR, Message.c_str(), errorCode,
                   errorCode, errorMessage.c_str());
  throw std::runtime_error(msg);
}

// Save a pointer size value to the registry
bool RegWritePointerSize(_In_ const std::basic_string<TCHAR> &Path,
                         _In_ const std::basic_string<TCHAR> &Name,
                         _In_ std::uintptr_t Value) {
  static_assert(sizeof(Value) == sizeof(void *),
                "Size has to be a pointer size");

  HKEY keyNaked = nullptr;
  auto status = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, Path.c_str(), 0, nullptr,
                                 0, KEY_SET_VALUE, nullptr, &keyNaked, nullptr);
  if (!SUCCEEDED(status)) {
    return false;
  }
  auto key = std::experimental::make_unique_resource(std::move(keyNaked),
                                                     &::RegCloseKey);

  auto regType = (IsX64()) ? REG_QWORD : REG_DWORD;
  status =
      ::RegSetValueEx(key.get(), Name.c_str(), 0, regType,
                      reinterpret_cast<const BYTE *>(&Value), sizeof(Value));
  return SUCCEEDED(status);
}

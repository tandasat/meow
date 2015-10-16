// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements symbol management function(s).
//
#include "stdafx.h"
#include "symbolManagement.h"

// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers
#include "util.h"
#include "SymbolResolver.h"
#include "SymbolAddressDeriver.h"

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

namespace {

using DriverInfo = std::pair<std::uintptr_t, std::basic_string<TCHAR>>;
using DriverInfoList = std::vector<DriverInfo>;

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

namespace {

DriverInfoList GetDriverList();

std::vector<std::basic_string<TCHAR>> GetRequestedSymbolNames();

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Resolve all necessary symbols and register the addresses to the registry.
// This function gets the list of kernel modules and checks if the module is
// needed to be used for symbols one by one.
bool RegisterSymbolInformation(
    _In_ const std::basic_string<TCHAR> &RegistryPath) {
  // Get a full path of system32
  std::array<TCHAR, MAX_PATH> sysDir_;
  ::GetSystemDirectory(sysDir_.data(), static_cast<UINT>(sysDir_.size()));
  std::basic_string<TCHAR> sysDir(sysDir_.data());
  sysDir += TEXT("\\");

  // Get a name list of requested symbols
  const auto requestedSymbols = GetRequestedSymbolNames();

  _tprintf(_T("Preparing symbols...\n"));
  SymbolResolver resolver;

  // Do follow for each driver files loaded in the kernel.
  for (const auto &driverInfo : GetDriverList()) {
    // Get a base name of the driver
    const auto driverBaseName =
        driverInfo.second.substr(0, driverInfo.second.find(TEXT('.')));

    // Check if this driver is in the required list
    for (const auto &requestedSymbol : requestedSymbols) {
      // Get a base name of the required symbol name
      const auto requestedBaseName =
          requestedSymbol.substr(0, requestedSymbol.find(TEXT('!')));

      // ignore if it is a different module
      if (requestedBaseName != driverBaseName) {
        continue;
      }

      // Get an address of the symbol
      SymbolAddressDeriver deriver(&resolver, sysDir + driverInfo.second,
                                   driverInfo.first);
      const auto address =
          static_cast<std::uintptr_t>(deriver.getAddress(requestedSymbol));
      if (!address) {
        std::basic_stringstream<TCHAR> ss;
        ss << requestedSymbol << TEXT(" could not be solved.");
        const auto str = ss.str();
        PrintErrorMessage(str.c_str());
        return false;
      }

      // Save the address to the registry
      if (!RegWritePointerSize(RegistryPath, requestedSymbol, address)) {
        PrintErrorMessage(TEXT("RegSetPtr failed."));
        return false;
      }
      _tprintf(_T("0x%p : %s\n"), reinterpret_cast<void *>(address),
               requestedSymbol.c_str());
    }
  }
  return true;
}

namespace {

// Get a list of file names of drivers that are currently loaded in the kernel.
DriverInfoList GetDriverList() {
  // Determine the current number of drivers
  DWORD needed = 0;
  std::array<void *, 1000> baseAddresses;
  if (!::EnumDeviceDrivers(
          baseAddresses.data(),
          static_cast<DWORD>(baseAddresses.size() * sizeof(void *)), &needed)) {
    ThrowRuntimeError(TEXT("EnumDeviceDrivers failed."));
  }

  // Collect their base names
  DriverInfoList list;
  const auto numberOfDrivers = needed / sizeof(baseAddresses.at(0));
  for (std::uint32_t i = 0; i < numberOfDrivers; ++i) {
    std::array<TCHAR, MAX_PATH> name;
    if (!::GetDeviceDriverBaseName(baseAddresses.at(i), name.data(),
                                   static_cast<DWORD>(name.size()))) {
      ThrowRuntimeError(TEXT("GetDeviceDriverBaseName failed."));
    }
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
    list.emplace_back(reinterpret_cast<std::uintptr_t>(baseAddresses.at(i)),
                      name.data());
  }
  return list;
}

// Returns a list of requested symbols
std::vector<std::basic_string<TCHAR>> GetRequestedSymbolNames() {
  // clang-format off
  std::vector<std::basic_string<TCHAR>> forAll = {
      TEXT("ntoskrnl!ExAcquireResourceSharedLite"),
      TEXT("ntoskrnl!VerifierExAcquireResourceSharedLite"),
      TEXT("ntoskrnl!KeWaitForSingleObject"),
      TEXT("ntoskrnl!KeDelayExecutionThread"),
  };
  std::vector<std::basic_string<TCHAR>> forX64 = {
      TEXT("ntoskrnl!KiCommitThreadWait"),
      TEXT("ntoskrnl!ApiSetpSearchForApiSetHost"),
      TEXT("ntoskrnl!KiScbQueueScanWorker"), 
      TEXT("ntoskrnl!CcBcbProfiler"),
  };
  std::vector<std::basic_string<TCHAR>> forARM = {
      TEXT("ntoskrnl!KeRemovePriQueue"), 
      TEXT("ntoskrnl!CmpDelayFreeTMWorker"),
      TEXT("ntoskrnl!PopPdcSampleIdleTimeouts"),
      TEXT("ntoskrnl!CcDelayedFlushTimer"),
  };
  // clang-format on
  const auto &arch = (IsX64() ? forX64 : forARM);

  forAll.insert(forAll.end(), arch.begin(), arch.end());
  return forAll;
}

}  // namespace

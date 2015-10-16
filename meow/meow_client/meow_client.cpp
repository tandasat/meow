// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the program.
//
#include "stdafx.h"

// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers
#include "../Common/meow_ioctl.h"
#include "symbolManagement.h"
#include "util.h"

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

bool AppMain(_In_ const std::vector<std::string> &Args);

bool ProcessCommand(_In_ const std::string &Command);

bool InvalidCommand(_In_ const std::string &Command);

bool LoadDll(_In_ const std::string &DllPath);

bool DisarmPatchGuard();

bool SendIoctlCommand(_In_ DWORD IoControlCode);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

int main(int argc, char *argv[]) {
  auto exitCode = EXIT_FAILURE;
  try {
    std::vector<std::string> args;
    for (auto i = 0; i < argc; ++i) {
      args.push_back(argv[i]);
    }
    if (AppMain(args)) {
      exitCode = EXIT_SUCCESS;
    }
  } catch (std::exception &e) {
    std::cout << e.what() << std::endl;
  } catch (...) {
    std::cout << "Unhandled exception occurred." << std::endl;
  }
  return exitCode;
}

// A main application loop
bool AppMain(_In_ const std::vector<std::string> &Args) {
  // Process given commands as parameters
  for (auto i = 1ul; i < Args.size(); ++i) {
    const auto cmd = Args.at(i);
    std::cout << "> " << cmd << std::endl;
    if (ProcessCommand(cmd)) {
      SetLastError(NO_ERROR);
      PrintErrorMessage(Args.at(i));
    }
  }

  std::cout << "\n"
            << "Type one of following these commands:\n"
            << "  disarm           # Disarm PatchGuard\n"
            << "  load:<dll_path>  # Load the DLL\n"
            << "  exit             # Exit this program\n" << std::endl;

  // Enter a command shell
  for (;;) {
    std::cout << "> ";
    std::string command;
    std::cin >> command;
    if (ProcessCommand(command)) {
      PrintErrorMessage(command);
    }
  }
}

// Interpret and execute commands
bool ProcessCommand(_In_ const std::string &Command) {
  if (Command == "exit") {
    std::exit(EXIT_SUCCESS);
  } else if (Command == "disarm") {
    return DisarmPatchGuard();
  } else if (std::strncmp(Command.c_str(), "load:", 5) == 0) {
    return LoadDll(Command.c_str() + 5);
  } else {
    return InvalidCommand(Command);
  }
}

// An invalid command handler.
bool InvalidCommand(_In_ const std::string &Command) {
  std::cout << "Unknown Command: " << Command << std::endl;
  return false;
}

// Load a specified dll file (which does not require the dll to be signed).
bool LoadDll(_In_ const std::string &DllPath) {
  const auto dll = std::experimental::make_unique_resource(
      LoadLibraryA(DllPath.c_str()), &FreeLibrary);
  std::cout << std::hex << dll.get() << " : " << DllPath << std::endl;
  if (!dll.get()) {
    PrintErrorMessage(TEXT("LoadLibrary failed."));
    return false;
  }
  return true;
}

// Disarm PatchGuard.
bool DisarmPatchGuard() {
  if (!RegisterSymbolInformation(
          TEXT("SYSTEM\\CurrentControlSet\\Services\\meow"))) {
    return false;
  }
  return SendIoctlCommand(MEOW_IOCTL_DISARM);
}

// Send an IOCTL command to the meow driver.
bool SendIoctlCommand(_In_ DWORD IoControlCode) {
  const auto handle = std::experimental::make_unique_resource(
      CreateFile(TEXT("\\\\.\\meow"), GENERIC_READ | GENERIC_WRITE,
                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
      &CloseHandle);
  if (handle.get() == INVALID_HANDLE_VALUE) {
    PrintErrorMessage(TEXT("CreateFile failed."));
    return false;
  }
  DWORD returned = 0;
  if (!DeviceIoControl(handle.get(), IoControlCode, nullptr, 0, nullptr, 0,
                       &returned, nullptr)) {
    PrintErrorMessage(TEXT("DeviceIoControl failed."));
    return false;
  }
  return true;
}

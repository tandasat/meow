// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to function parse functions.
//
#pragma once

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// A supported number of function epilogues for each function. 31 because most
// of functions are less than that
static const auto FNPARSEP_MAX_SUPPORTED_EPILOGUE_NUMBER = 31ul;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A set of information retrieved from unwind information.
struct EpilogueInfo {
  SIZE_T EpilogueLength;
  SIZE_T UnwindStackSize;
  UCHAR *EpilogueAddresses[FNPARSEP_MAX_SUPPORTED_EPILOGUE_NUMBER];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C IMAGE_RUNTIME_FUNCTION_ENTRY *FnparseLookupFunctionEntry(
    _In_ FARPROC FunctionAddress, _Out_ PVOID *ImageBase);

EXTERN_C SIZE_T FnparseGetFunctionLength(_In_ UCHAR *FunctionAddress);

EXTERN_C EpilogueInfo FnparseGetEpilogueInfo(_In_ UCHAR *FunctionAddress);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

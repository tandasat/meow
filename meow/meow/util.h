// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to utility functions.
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

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C void *UtilMemMem(_In_ const void *SearchBase, _In_ SIZE_T SearchSize,
                          _In_ const void *Pattern, _In_ SIZE_T PatternSize);

EXTERN_C bool UtilIsAccessibleAddress(_In_ const void *Address);

EXTERN_C bool UtilIsExecutableAddress(_In_ const void *Address);

EXTERN_C NTSTATUS UtilSleep(_In_ LONG Millisecond);

EXTERN_C NTSTATUS UtilLoadPointerVaule(_In_ const wchar_t *Key,
                                       _In_ const wchar_t *Value,
                                       _Out_ void **Data);

EXTERN_C void UtilInvalidateInstructionCache(_In_ void *BaseAddress,
                                             _In_ SIZE_T Length);

EXTERN_C NTSTATUS UtilForceMemCpy(_In_ void *Destination,
                                  _In_ const void *Source, _In_ SIZE_T Length);

EXTERN_C UCHAR *UtilFpToData(_In_opt_ FARPROC FunctionPointer);

EXTERN_C FARPROC UtilDataToFp(_In_opt_ UCHAR *FunctionAddress);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
